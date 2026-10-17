import Foundation
import Network

/// A TCP server on the loopback interface (IPv4 and IPv6) with an ephemeral port.
/// Every behaviour records the bytes it receives, so a test can assert exact equality.
final class LoopbackOrigin {
    enum Behaviour {
        /// Writes every received chunk back.
        case echo
        /// Only records; never writes.
        case recordAll
        /// Sends a banner on accept, then records.
        case serverFirst(Data)
    }

    private(set) var port: UInt16 = 0
    private let listener: NWListener
    private let behaviour: Behaviour
    private let queue = DispatchQueue(label: "LoopbackOrigin")
    private let lock = NSLock()
    private var connections: [NWConnection] = []
    private var _received = Data()
    private var _acceptCount = 0

    /// Everything received, across all connections, in arrival order.
    var received: Data { lock.withLock { _received } }
    var acceptCount: Int { lock.withLock { _acceptCount } }

    init(_ behaviour: Behaviour) throws {
        self.behaviour = behaviour
        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        listener = try NWListener(using: params, on: .any)

        let ready = DispatchSemaphore(value: 0)
        let failure = LockedBox<Error?>(nil)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.signal()
            case .failed(let error): failure.value = error; ready.signal()
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success else { throw HarnessError.timeout("origin listener") }
        if let error = failure.value { throw error }
        port = listener.port!.rawValue
    }

    func stop() {
        listener.cancel()
        lock.withLock { connections }.forEach { $0.cancel() }
    }

    private func accept(_ conn: NWConnection) {
        lock.withLock {
            connections.append(conn)
            _acceptCount += 1
        }
        conn.start(queue: queue)
        if case .serverFirst(let banner) = behaviour {
            conn.send(content: banner, completion: .idempotent)
        }
        receive(on: conn)
    }

    private func receive(on conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.lock.withLock { self._received.append(data) }
                if case .echo = self.behaviour {
                    conn.send(content: data, completion: .idempotent)
                }
            }
            if isComplete || error != nil {
                conn.cancel()
                return
            }
            self.receive(on: conn)
        }
    }
}

enum HarnessError: Error, CustomStringConvertible {
    case timeout(String)
    case closed(String)

    var description: String {
        switch self {
        case .timeout(let what): return "timed out waiting for \(what)"
        case .closed(let what): return "connection closed while waiting for \(what)"
        }
    }
}

final class LockedBox<T> {
    private var _value: T
    private let lock = NSLock()
    init(_ value: T) { _value = value }
    var value: T {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}
