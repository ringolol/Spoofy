import Foundation

/// What one accepted client connection owns: a serial queue and every connection opened for it.
/// All methods must be called on `queue`; handlers start their connections on it too.
final class SessionScope {
    let id: UInt64
    let queue: DispatchQueue
    private(set) var isClosed = false
    private var connections: [any ConnectionProtocol] = []

    init(id: UInt64, target: DispatchQueue) {
        self.id = id
        self.queue = DispatchQueue(label: "com.rnglol.Spoofy.session.\(id)", target: target)
    }

    /// Ties `connection` to the session's lifetime. If the session is already closed
    /// (for example by `ProxyServer.stop()` during a dial), the connection is cancelled at once.
    func adopt(_ connection: any ConnectionProtocol) {
        assertOnQueue()
        if isClosed {
            connection.cancel()
            return
        }
        connections.append(connection)
    }

    /// Cancels every adopted connection. Idempotent.
    func close() {
        assertOnQueue()
        guard !isClosed else { return }
        isClosed = true
        let open = connections
        connections = []
        open.forEach { $0.cancel() }
    }

    private func assertOnQueue() {
        #if DEBUG
        dispatchPrecondition(condition: .onQueue(queue))
        #endif
    }
}
