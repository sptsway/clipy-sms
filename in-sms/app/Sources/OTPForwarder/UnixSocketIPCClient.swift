import Darwin
import Foundation

/// Type-erasing wrapper so a single Encodable field can hold any concrete
/// params type (MessagesListParams, AppSettings, ...) without a generic
/// OutgoingRequest per method.
private struct AnyEncodable: Encodable {
    let wrapped: Encodable
    func encode(to encoder: Encoder) throws { try wrapped.encode(to: encoder) }
}

private struct OutgoingRequest: Encodable {
    let id: String
    let method: String
    let params: AnyEncodable?
}

/// Real IPC client: connects to the daemon's Unix domain socket and speaks
/// the newline-delimited JSON protocol from ARCHITECTURE.md §3.6/§4 —
/// request/response correlated by id, plus unsolicited `{"type":"event",...}`
/// lines dispatched through `events`.
final class UnixSocketIPCClient: IPCClient {
    let events: AsyncStream<IPCEvent>
    private let eventsContinuation: AsyncStream<IPCEvent>.Continuation

    private let fileHandle: FileHandle
    private var readBuffer = Data()
    private let stateLock = NSLock()
    private var pending: [String: CheckedContinuation<Data, Error>] = [:]

    static var defaultSocketPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/OTPForwarder/otpd.sock")
            .path
    }

    init(socketPath: String = UnixSocketIPCClient.defaultSocketPath) throws {
        let fd = try Self.connectSocket(path: socketPath)
        self.fileHandle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)

        var continuation: AsyncStream<IPCEvent>.Continuation!
        self.events = AsyncStream { continuation = $0 }
        self.eventsContinuation = continuation

        fileHandle.readabilityHandler = { [weak self] handle in
            self?.handleReadable(handle)
        }
    }

    deinit {
        fileHandle.readabilityHandler = nil
        try? fileHandle.close()
    }

    // MARK: - Connecting

    private static func connectSocket(path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw IPCError.daemon("socket() failed: \(String(cString: strerror(errno)))")
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < capacity else {
            close(fd)
            throw IPCError.daemon("socket path too long (\(pathBytes.count) >= \(capacity))")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            let buf = raw.bindMemory(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() {
                buf[i] = CChar(bitPattern: byte)
            }
            buf[pathBytes.count] = 0
        }

        let len = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count + 1)
        let result = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, len)
            }
        }
        guard result == 0 else {
            let err = errno
            close(fd)
            throw IPCError.daemon("connect(\(path)) failed: \(String(cString: strerror(err)))")
        }
        return fd
    }

    // MARK: - Reading

    private func handleReadable(_ handle: FileHandle) {
        let data = handle.availableData
        if data.isEmpty {
            handle.readabilityHandler = nil
            failAllPending(IPCError.notConnected)
            eventsContinuation.yield(.connectionLost)
            eventsContinuation.finish()
            return
        }
        readBuffer.append(data)
        while let newlineRange = readBuffer.range(of: Data([0x0A])) {
            let lineData = readBuffer.subdata(in: readBuffer.startIndex..<newlineRange.lowerBound)
            readBuffer.removeSubrange(readBuffer.startIndex..<newlineRange.upperBound)
            if !lineData.isEmpty {
                handleLine(lineData)
            }
        }
    }

    private func handleLine(_ lineData: Data) {
        guard let obj = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any] else {
            return
        }

        if (obj["type"] as? String) == "event" {
            handleEvent(obj)
            return
        }

        guard let id = obj["id"] as? String else { return }
        stateLock.lock()
        let continuation = pending.removeValue(forKey: id)
        stateLock.unlock()
        guard let continuation else { return } // stray/late response; nobody is waiting

        if let errMessage = obj["error"] as? String, !errMessage.isEmpty {
            continuation.resume(throwing: IPCError.daemon(errMessage))
            return
        }

        // Re-serialize just the "result" payload so the caller can decode it
        // into its own concrete type. Void-returning calls (pair.cancel,
        // device.unpair, history.clear) have no "result" key at all — hand
        // back "{}" so callVoid's discard-the-decode-target path is happy.
        guard let resultValue = obj["result"],
              JSONSerialization.isValidJSONObject(resultValue) || (resultValue is [Any]),
              let resultData = try? JSONSerialization.data(withJSONObject: resultValue)
        else {
            continuation.resume(returning: Data("{}".utf8))
            return
        }
        continuation.resume(returning: resultData)
    }

    private func handleEvent(_ obj: [String: Any]) {
        guard let eventName = obj["event"] as? String else { return }
        let dataValue = obj["data"] ?? [String: Any]()
        guard JSONSerialization.isValidJSONObject(dataValue),
              let dataBytes = try? JSONSerialization.data(withJSONObject: dataValue)
        else { return }

        switch eventName {
        case IPCEventName.messageNew:
            if let msg = try? JSONDecoder().decode(SMSMessage.self, from: dataBytes) {
                eventsContinuation.yield(.messageNew(msg))
            }
        case IPCEventName.pairingStatus:
            if let status = try? JSONDecoder().decode(PairStatusResult.self, from: dataBytes) {
                eventsContinuation.yield(.pairingStatus(status))
            }
        case IPCEventName.deviceLastSeen:
            if let seen = try? JSONDecoder().decode(DeviceLastSeenEvent.self, from: dataBytes) {
                eventsContinuation.yield(.deviceLastSeen(seen))
            }
        default:
            break
        }
    }

    private func failAllPending(_ error: Error) {
        stateLock.lock()
        let all = pending
        pending.removeAll()
        stateLock.unlock()
        for (_, continuation) in all {
            continuation.resume(throwing: error)
        }
    }

    // MARK: - Sending

    private func sendRequest(method: String, params: Encodable?) async throws -> Data {
        let id = UUID().uuidString
        let req = OutgoingRequest(id: id, method: method, params: params.map { AnyEncodable(wrapped: $0) })
        var line: Data
        do {
            line = try JSONEncoder().encode(req)
        } catch {
            throw IPCError.decoding(error)
        }
        line.append(0x0A)

        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            stateLock.lock()
            pending[id] = continuation
            stateLock.unlock()

            do {
                try fileHandle.write(contentsOf: line)
            } catch {
                stateLock.lock()
                pending.removeValue(forKey: id)
                stateLock.unlock()
                continuation.resume(throwing: IPCError.daemon("write failed: \(error.localizedDescription)"))
            }
        }
    }

    private func call<Result: Decodable>(_ method: String, params: Encodable? = nil) async throws -> Result {
        let data = try await sendRequest(method: method, params: params)
        do {
            return try JSONDecoder().decode(Result.self, from: data)
        } catch {
            throw IPCError.decoding(error)
        }
    }

    private func callVoid(_ method: String, params: Encodable? = nil) async throws {
        _ = try await sendRequest(method: method, params: params)
    }

    // MARK: - IPCClient

    func pairStart() async throws -> PairStartResult { try await call(IPCMethod.pairStart) }
    func pairStatus() async throws -> PairStatusResult { try await call(IPCMethod.pairStatus) }
    func pairCancel() async throws { try await callVoid(IPCMethod.pairCancel) }

    func deviceStatus() async throws -> DeviceStatusResult { try await call(IPCMethod.deviceStatus) }
    func deviceUnpair() async throws { try await callVoid(IPCMethod.deviceUnpair) }

    func messagesList(offset: Int, limit: Int) async throws -> MessagesListResult {
        try await call(IPCMethod.messagesList, params: MessagesListParams(offset: offset, limit: limit))
    }
    func messagesGet(id: String) async throws -> SMSMessage {
        try await call(IPCMethod.messagesGet, params: MessagesGetParams(id: id))
    }
    func historyClear() async throws { try await callVoid(IPCMethod.historyClear) }

    func settingsGet() async throws -> AppSettings { try await call(IPCMethod.settingsGet) }
    func settingsSet(_ settings: AppSettings) async throws -> AppSettings {
        try await call(IPCMethod.settingsSet, params: settings)
    }
}
