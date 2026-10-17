import Foundation
import Network

/// A blocking TCP client for integration tests. Callbacks run on a private queue;
/// the test thread waits on them with a deadline, so a hung proxy fails the test instead of the run.
final class TestClient {
    private let conn: NWConnection
    private let queue = DispatchQueue(label: "TestClient")
    private let lock = NSLock()
    private var buffer = Data()
    private var eof = false
    private let arrived = DispatchSemaphore(value: 0)

    init(port: UInt16, host: NWEndpoint.Host = "127.0.0.1", timeout: TimeInterval = 5) throws {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcp)
        params.preferNoProxies = true
        conn = NWConnection(host: host, port: NWEndpoint.Port(rawValue: port)!, using: params)

        let ready = DispatchSemaphore(value: 0)
        let failure = LockedBox<Error?>(nil)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.signal()
            case .failed(let error), .waiting(let error): failure.value = error; ready.signal()
            default: break
            }
        }
        conn.start(queue: queue)
        guard ready.wait(timeout: .now() + timeout) == .success else { throw HarnessError.timeout("client connect") }
        if let error = failure.value { throw error }
        conn.stateUpdateHandler = nil
        receiveLoop()
    }

    deinit { conn.cancel() }

    func send(_ data: Data, timeout: TimeInterval = 5) throws {
        let done = DispatchSemaphore(value: 0)
        let failure = LockedBox<Error?>(nil)
        conn.send(content: data, completion: .contentProcessed { error in
            failure.value = error
            done.signal()
        })
        guard done.wait(timeout: .now() + timeout) == .success else { throw HarnessError.timeout("send") }
        if let error = failure.value { throw error }
    }

    func send(_ text: String) throws { try send(Data(text.utf8)) }

    /// Returns exactly `count` bytes.
    func read(count: Int, timeout: TimeInterval = 5) throws -> Data {
        try take(what: "\(count) bytes", timeout: timeout) { buffer in
            buffer.count >= count ? count : nil
        }
    }

    /// Returns everything up to and including `delimiter`.
    func read(through delimiter: Data, timeout: TimeInterval = 5) throws -> Data {
        try take(what: "delimiter", timeout: timeout) { buffer in
            buffer.firstRange(of: delimiter).map { $0.upperBound - buffer.startIndex }
        }
    }

    /// True if the peer closed (or reset) the connection before the deadline.
    func waitForClose(timeout: TimeInterval = 5) -> Bool {
        let deadline = DispatchTime.now() + timeout
        while true {
            if lock.withLock({ eof }) { return true }
            if arrived.wait(timeout: deadline) == .timedOut { return lock.withLock { eof } }
        }
    }

    /// Non-blocking: has the peer closed the connection yet?
    var isClosedByPeer: Bool { lock.withLock { eof } }

    func close() { conn.cancel() }

    private func take(what: String, timeout: TimeInterval, length: (Data) -> Int?) throws -> Data {
        let deadline = DispatchTime.now() + timeout
        while true {
            let result: Data? = lock.withLock {
                guard let n = length(buffer) else { return nil }
                let chunk = buffer.prefix(n)
                buffer = Data(buffer.dropFirst(n))
                return Data(chunk)
            }
            if let result { return result }
            if lock.withLock({ eof }) { throw HarnessError.closed(what) }
            if arrived.wait(timeout: deadline) == .timedOut { throw HarnessError.timeout(what) }
        }
    }

    private func receiveLoop() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.lock.withLock {
                if let data { self.buffer.append(data) }
                if isComplete || error != nil { self.eof = true }
            }
            self.arrived.signal()
            if isComplete || error != nil { return }
            self.receiveLoop()
        }
    }
}
