import Foundation

/// Stand-in backend so the menu bar UI is fully browsable before (or
/// without) a real otpd daemon — e.g. in SwiftUI previews, or when
/// developing the UI ahead of the daemon's pairing/message-path
/// implementation (docs/CRYPTO_IMPLEMENTATION.md). Populated with enough
/// sample history to exercise the "recent 5 + chunked Older" menu layout.
final class MockIPCClient: IPCClient {
    let events: AsyncStream<IPCEvent>
    private let eventsContinuation: AsyncStream<IPCEvent>.Continuation

    private var messages: [SMSMessage]
    private var settings = AppSettings.defaults
    private var pairing = PairStatusResult(state: .idle, attemptsLeft: 5, expiresAt: nil)
    private var device: DeviceStatusResult

    init(sampleCount: Int = 47) {
        var continuation: AsyncStream<IPCEvent>.Continuation!
        self.events = AsyncStream { continuation = $0 }
        self.eventsContinuation = continuation

        let senders = ["Bank", "GitHub", "Google", "AWS", "PayPal", "38221"]
        let keywords = ["OTP", "verification code", "code"]
        let formatter = ISO8601DateFormatter()
        self.messages = (0..<sampleCount).map { i in
            let code = String(format: "%06d", Int.random(in: 0...999_999))
            let sender = senders[i % senders.count]
            let keyword = keywords[i % keywords.count]
            let date = Date(timeIntervalSinceNow: -Double(i) * 900) // every 15 min back
            return SMSMessage(
                id: "mock-\(i)",
                receivedAt: formatter.string(from: date),
                sender: sender,
                body: "Your \(keyword) is \(code). Valid for 10 minutes. Do not share this with anyone.",
                code: code,
                sim: i % 2 == 0 ? 1 : 2
            )
        }
        self.device = DeviceStatusResult(
            paired: true,
            deviceName: "Sam's Pixel",
            lastSeen: Int64(Date().timeIntervalSince1970) - 120
        )
    }

    func pairStart() async throws -> PairStartResult {
        pairing = PairStatusResult(state: .waiting, attemptsLeft: 5, expiresAt: Int64(Date().timeIntervalSince1970) + 120)
        eventsContinuation.yield(.pairingStatus(pairing))
        // A syntactically-plausible demo URI so the QR view has something to render.
        let fakeMacPub = Data((0..<65).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let fakeToken = Data((0..<32).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let uri = "otpfwd://pair?v=1&mac_pub=\(fakeMacPub)&token=\(fakeToken)&hosts=192.168.1.23&port=47820&name=Mock%20Mac&exp=\(pairing.expiresAt ?? 0)"
        return PairStartResult(uri: uri, expiresAt: pairing.expiresAt ?? 0)
    }

    func pairStatus() async throws -> PairStatusResult { pairing }

    func pairCancel() async throws {
        pairing = PairStatusResult(state: .idle, attemptsLeft: 5, expiresAt: nil)
        eventsContinuation.yield(.pairingStatus(pairing))
    }

    func deviceStatus() async throws -> DeviceStatusResult { device }

    func deviceUnpair() async throws {
        device = DeviceStatusResult(paired: false, deviceName: nil, lastSeen: nil)
    }

    func messagesList(offset: Int, limit: Int) async throws -> MessagesListResult {
        let total = messages.count
        guard offset < total else { return MessagesListResult(messages: [], total: total) }
        let end = min(offset + limit, total)
        return MessagesListResult(messages: Array(messages[offset..<end]), total: total)
    }

    func messagesGet(id: String) async throws -> SMSMessage {
        guard let m = messages.first(where: { $0.id == id }) else {
            throw IPCError.daemon("message not found")
        }
        return m
    }

    func historyClear() async throws {
        messages.removeAll()
    }

    func settingsGet() async throws -> AppSettings { settings }

    func settingsSet(_ newSettings: AppSettings) async throws -> AppSettings {
        var clamped = newSettings
        clamped.maxMessages = min(max(clamped.maxMessages, 10), 1000)
        settings = clamped
        return clamped
    }

    /// Test-only helper to simulate a new SMS arriving, for exercising the
    /// menu's live-update behavior without a real daemon.
    func simulateIncomingMessage(sender: String = "Demo", code: String = "123456") {
        let formatter = ISO8601DateFormatter()
        let msg = SMSMessage(
            id: "mock-live-\(UUID().uuidString.prefix(8))",
            receivedAt: formatter.string(from: Date()),
            sender: sender,
            body: "Your OTP is \(code).",
            code: code,
            sim: 1
        )
        messages.insert(msg, at: 0)
        eventsContinuation.yield(.messageNew(msg))
    }
}
