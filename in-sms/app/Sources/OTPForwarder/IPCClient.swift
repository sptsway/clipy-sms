import Foundation

/// An event pushed unsolicited from the daemon (ARCHITECTURE.md §3.6).
enum IPCEvent {
    case messageNew(SMSMessage)
    case pairingStatus(PairStatusResult)
    case deviceLastSeen(DeviceLastSeenEvent)
    case connectionLost
}

enum IPCError: Error, LocalizedError {
    case notConnected
    case daemon(String)
    case decoding(Error)
    case timedOut

    var errorDescription: String? {
        switch self {
        case .notConnected: return "Not connected to the daemon."
        case .daemon(let message): return message
        case .decoding(let err): return "Malformed response from daemon: \(err.localizedDescription)"
        case .timedOut: return "The daemon did not respond in time."
        }
    }
}

/// Everything the UI needs from whatever is on the other end of the socket —
/// implemented by UnixSocketIPCClient (talks to the real otpd) and by
/// MockIPCClient (canned data, for running the UI before/without a daemon).
protocol IPCClient: AnyObject {
    var events: AsyncStream<IPCEvent> { get }

    func pairStart() async throws -> PairStartResult
    func pairStatus() async throws -> PairStatusResult
    func pairCancel() async throws

    func deviceStatus() async throws -> DeviceStatusResult
    func deviceUnpair() async throws

    func messagesList(offset: Int, limit: Int) async throws -> MessagesListResult
    func messagesGet(id: String) async throws -> SMSMessage
    func historyClear() async throws

    func settingsGet() async throws -> AppSettings
    func settingsSet(_ settings: AppSettings) async throws -> AppSettings
}
