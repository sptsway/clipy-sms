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

/// Everything the UI needs from whatever is on the other end of the socket.
/// The only production implementation is UnixSocketIPCClient, which talks to
/// the real otpd; DisconnectedIPCClient below is the fallback when it can't
/// connect — it reports the honest "not connected" state rather than
/// fabricating any data.
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

/// Used when otpd wasn't reachable at launch (e.g. the daemon hasn't started
/// yet, or isn't installed as a login item). Every call fails with
/// `.notConnected` — no sample/fake data — so the UI shows an honest "Daemon
/// not running" status instead of anything invented.
///
/// Known limitation: this doesn't retry — if otpd starts after the UI does,
/// the app keeps using this client until relaunched. Worth revisiting if
/// startup ordering turns out to matter in practice (see ARCHITECTURE.md §6
/// on SMAppService registration).
final class DisconnectedIPCClient: IPCClient {
    let events: AsyncStream<IPCEvent> = AsyncStream { _ in }

    func pairStart() async throws -> PairStartResult { throw IPCError.notConnected }
    func pairStatus() async throws -> PairStatusResult { throw IPCError.notConnected }
    func pairCancel() async throws { throw IPCError.notConnected }
    func deviceStatus() async throws -> DeviceStatusResult { throw IPCError.notConnected }
    func deviceUnpair() async throws { throw IPCError.notConnected }
    func messagesList(offset: Int, limit: Int) async throws -> MessagesListResult { throw IPCError.notConnected }
    func messagesGet(id: String) async throws -> SMSMessage { throw IPCError.notConnected }
    func historyClear() async throws { throw IPCError.notConnected }
    func settingsGet() async throws -> AppSettings { throw IPCError.notConnected }
    func settingsSet(_ settings: AppSettings) async throws -> AppSettings { throw IPCError.notConnected }
}
