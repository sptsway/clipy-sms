import Foundation

// Mirrors daemon/internal/ipc/schema.go exactly — keep the two in sync by
// hand, since this app talks to the daemon only through that wire schema
// (ARCHITECTURE.md §3.6), not by linking against the Go code.

enum IPCMethod {
    static let pairStart = "pair.start"
    static let pairStatus = "pair.status"
    static let pairCancel = "pair.cancel"
    static let deviceStatus = "device.status"
    static let deviceUnpair = "device.unpair"
    static let messagesList = "messages.list"
    static let messagesGet = "messages.get"
    static let historyClear = "history.clear"
    static let settingsGet = "settings.get"
    static let settingsSet = "settings.set"
}

enum IPCEventName {
    static let messageNew = "message.new"
    static let pairingStatus = "pairing.status"
    static let deviceLastSeen = "device.lastSeen"
}

enum PairingState: String, Codable {
    case idle
    case waiting
    case paired
    case failed
}

struct PairStartResult: Codable {
    let uri: String
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case uri
        case expiresAt = "expires_at"
    }
}

struct PairStatusResult: Codable {
    let state: PairingState
    let attemptsLeft: Int
    let expiresAt: Int64?

    enum CodingKeys: String, CodingKey {
        case state
        case attemptsLeft = "attempts_left"
        case expiresAt = "expires_at"
    }
}

struct DeviceStatusResult: Codable {
    let paired: Bool
    let deviceName: String?
    let lastSeen: Int64?

    enum CodingKeys: String, CodingKey {
        case paired
        case deviceName = "device_name"
        case lastSeen = "last_seen"
    }
}

struct DeviceLastSeenEvent: Codable {
    let deviceName: String
    let lastSeen: Int64

    enum CodingKeys: String, CodingKey {
        case deviceName = "device_name"
        case lastSeen = "last_seen"
    }
}

struct SMSMessage: Codable, Identifiable, Equatable {
    let id: String
    let receivedAt: String // RFC3339, from the daemon
    let sender: String
    let body: String
    let sim: Int?

    enum CodingKeys: String, CodingKey {
        case id
        case receivedAt = "received_at"
        case sender, body, sim
    }

    /// Parsed once for display; falls back to .distantPast if the daemon
    /// ever sent something unparsable rather than crashing the UI.
    var receivedDate: Date {
        ISO8601DateFormatter().date(from: receivedAt) ?? .distantPast
    }
}

struct MessagesListParams: Encodable {
    let offset: Int
    let limit: Int
}

struct MessagesListResult: Codable {
    let messages: [SMSMessage]
    let total: Int
}

struct MessagesGetParams: Encodable {
    let id: String
}

struct AppSettings: Codable, Equatable {
    var maxMessages: Int
    var autoCopyNewest: Bool
    var clipboardClearSeconds: Int
    var port: Int
    var launchAtLogin: Bool
    var notificationsEnabled: Bool

    enum CodingKeys: String, CodingKey {
        case maxMessages = "max_messages"
        case autoCopyNewest = "auto_copy_newest"
        case clipboardClearSeconds = "clipboard_clear_seconds"
        case port
        case launchAtLogin = "launch_at_login"
        case notificationsEnabled = "notifications_enabled"
    }

    static let defaults = AppSettings(
        maxMessages: 100,
        autoCopyNewest: false,
        clipboardClearSeconds: 30,
        port: 47820,
        launchAtLogin: false,
        notificationsEnabled: true
    )
}
