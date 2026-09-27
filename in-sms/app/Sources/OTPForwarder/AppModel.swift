import Foundation

/// One labeled "Older" submenu chunk (ARCHITECTURE.md §5: "grouped in chunks
/// of 20, like Clipy's 1-20, 21-40").
struct OlderChunk: Identifiable {
    let id: Int // offset, unique per chunk
    let offset: Int
    let limit: Int
    let label: String
}

@MainActor
final class AppModel: ObservableObject {
    let client: IPCClient

    @Published var recentMessages: [SMSMessage] = []
    @Published var totalMessages: Int = 0
    @Published var deviceStatus = DeviceStatusResult(paired: false, deviceName: nil, lastSeen: nil)
    @Published var pairingStatus = PairStatusResult(state: .idle, attemptsLeft: 5, expiresAt: nil)
    @Published var settings = AppSettings.defaults
    @Published var lastErrorMessage: String?
    /// False whenever the last IPC call failed because otpd isn't reachable
    /// (as opposed to a call that reached the daemon but was itself
    /// rejected). Drives the "Daemon not running" status line.
    @Published var isConnected = true

    @Published var isPairWindowPresented = false
    @Published var isSettingsWindowPresented = false

    private static let recentCount = 5
    private static let chunkSize = 20

    private var eventTask: Task<Void, Never>?

    init(client: IPCClient) {
        self.client = client
        NotificationManager.shared.onTapped = { [weak self] _, code, _ in
            guard let self, !code.isEmpty else { return }
            ClipboardManager.shared.copy(code, clearAfterSeconds: self.settings.clipboardClearSeconds)
        }
        eventTask = Task { [weak self] in await self?.consumeEvents() }
        Task { [weak self] in await self?.refreshAll() }
    }

    deinit {
        eventTask?.cancel()
    }

    // MARK: - Derived state for the menu

    /// "Older" submenu descriptors covering everything past the first
    /// `recentCount` messages, chunked by `chunkSize`.
    var olderChunks: [OlderChunk] {
        let remaining = totalMessages - Self.recentCount
        guard remaining > 0 else { return [] }
        var chunks: [OlderChunk] = []
        var offset = Self.recentCount
        var displayStart = Self.recentCount + 1 // 1-based, for the "6-25" style label
        while offset < totalMessages {
            let limit = min(Self.chunkSize, totalMessages - offset)
            let displayEnd = displayStart + limit - 1
            chunks.append(OlderChunk(id: offset, offset: offset, limit: limit, label: "\(displayStart)\u{2013}\(displayEnd)"))
            offset += limit
            displayStart += limit
        }
        return chunks
    }

    var statusLine: String {
        guard isConnected else { return "Daemon not running" }
        guard deviceStatus.paired else { return "No phone paired" }
        let name = deviceStatus.deviceName ?? "Unknown device"
        guard let lastSeen = deviceStatus.lastSeen else { return "\(name) · never seen" }
        let date = Date(timeIntervalSince1970: TimeInterval(lastSeen))
        let formatter = RelativeDateTimeFormatter()
        return "\(name) · \(formatter.localizedString(for: date, relativeTo: Date()))"
    }

    // MARK: - Refreshing

    /// Records a successful IPC round trip — clears the "daemon not
    /// running" state, since we clearly just reached it.
    private func markConnected() {
        isConnected = true
    }

    /// Records an IPC failure. Distinguishes "otpd isn't reachable at all"
    /// (IPCError.notConnected) from any other failure, since only the
    /// former should flip the status line to "Daemon not running".
    private func handle(_ error: Error) {
        lastErrorMessage = error.localizedDescription
        if case IPCError.notConnected = error {
            isConnected = false
        }
    }

    func refreshAll() async {
        await refreshMessages()
        await refreshDeviceStatus()
        await refreshSettings()
        await refreshPairingStatus()
    }

    func refreshMessages() async {
        do {
            let result = try await client.messagesList(offset: 0, limit: Self.recentCount)
            recentMessages = result.messages
            totalMessages = result.total
            markConnected()
        } catch {
            handle(error)
        }
    }

    func fetchOlderChunk(offset: Int, limit: Int) async -> [SMSMessage] {
        do {
            let messages = try await client.messagesList(offset: offset, limit: limit).messages
            markConnected()
            return messages
        } catch {
            handle(error)
            return []
        }
    }

    func refreshDeviceStatus() async {
        do {
            deviceStatus = try await client.deviceStatus()
            markConnected()
        } catch { handle(error) }
    }

    func refreshSettings() async {
        do {
            settings = try await client.settingsGet()
            markConnected()
        } catch { handle(error) }
    }

    func refreshPairingStatus() async {
        do {
            pairingStatus = try await client.pairStatus()
            markConnected()
        } catch { handle(error) }
    }

    // MARK: - Events

    private func consumeEvents() async {
        for await event in client.events {
            switch event {
            case .messageNew(let msg):
                recentMessages.insert(msg, at: 0)
                if recentMessages.count > Self.recentCount { recentMessages.removeLast() }
                totalMessages += 1

                if settings.autoCopyNewest {
                    let text = msg.code.isEmpty ? msg.body : msg.code
                    ClipboardManager.shared.copy(text, clearAfterSeconds: settings.clipboardClearSeconds)
                }
                if settings.notificationsEnabled {
                    NotificationManager.shared.notify(sender: msg.sender, code: msg.code, body: msg.body, messageId: msg.id)
                }

            case .pairingStatus(let status):
                pairingStatus = status
                if status.state == .paired {
                    isPairWindowPresented = false
                    Task { await self.refreshDeviceStatus() }
                }

            case .deviceLastSeen(let seen):
                deviceStatus = DeviceStatusResult(paired: true, deviceName: seen.deviceName, lastSeen: seen.lastSeen)

            case .connectionLost:
                isConnected = false
                lastErrorMessage = "Lost connection to the daemon."
            }
        }
    }

    // MARK: - Actions

    func copyCode(_ message: SMSMessage) {
        let text = message.code.isEmpty ? message.body : message.code
        ClipboardManager.shared.copy(text, clearAfterSeconds: settings.clipboardClearSeconds)
    }

    func copyFullBody(_ message: SMSMessage) {
        ClipboardManager.shared.copy(message.body, clearAfterSeconds: settings.clipboardClearSeconds)
    }

    func startPairing() async -> PairStartResult? {
        do {
            let result = try await client.pairStart()
            markConnected()
            pairingStatus = PairStatusResult(state: .waiting, attemptsLeft: 5, expiresAt: result.expiresAt)
            return result
        } catch {
            handle(error)
            return nil
        }
    }

    func cancelPairing() async {
        do { try await client.pairCancel(); markConnected() }
        catch { handle(error) }
        await refreshPairingStatus()
    }

    func unpair() async {
        do { try await client.deviceUnpair(); markConnected() }
        catch { handle(error) }
        await refreshDeviceStatus()
    }

    func clearHistory() async {
        do {
            try await client.historyClear()
            markConnected()
            recentMessages = []
            totalMessages = 0
        } catch {
            handle(error)
        }
    }

    func saveSettings(_ newSettings: AppSettings) async {
        do { settings = try await client.settingsSet(newSettings); markConnected() }
        catch { handle(error) }
    }
}
