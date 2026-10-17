import Foundation
import Network
@testable import SpoofyCore

/// Scripted `ConnectionProtocol` for relay and handshake tests.
///
/// Works at the `send` level, so tests can assert exact segmentation (loopback TCP would coalesce).
/// All callbacks are delivered asynchronously on `queue`, like NWConnection.
final class FakeConnection: ConnectionProtocol {
    enum Event {
        case data(Data)
        case eof
        case error(NWError)
    }

    let queue: DispatchQueue
    /// When set, every `send` completes with this error and records nothing.
    var sendError: NWError?

    private let lock = NSLock()
    private var script: [Event]
    private var parked: ((Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)?
    private var _sent: [Data] = []
    private var _cancelled = false

    init(queue: DispatchQueue, script: [Event] = []) {
        self.queue = queue
        self.script = script
    }

    /// One entry per `send` call.
    var sent: [Data] { lock.withLock { _sent } }
    var cancelled: Bool { lock.withLock { _cancelled } }

    func send(content: Data?, contentContext: NWConnection.ContentContext,
              isComplete: Bool, completion: NWConnection.SendCompletion) {
        let error: NWError? = lock.withLock {
            if _cancelled { return .posix(.ECANCELED) }
            if let sendError { return sendError }
            if let content, !content.isEmpty { _sent.append(content) }
            return nil
        }
        if case .contentProcessed(let handler) = completion {
            queue.async { handler(error) }
        }
    }

    func receive(minimumIncompleteLength: Int, maximumLength: Int,
                 completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void) {
        lock.lock()
        if _cancelled {
            lock.unlock()
            queue.async { completion(nil, nil, false, .posix(.ECANCELED)) }
        } else if script.isEmpty {
            parked = completion
            lock.unlock()
        } else {
            let event = script.removeFirst()
            lock.unlock()
            queue.async { Self.deliver(event, to: completion) }
        }
    }

    /// Feed more input; satisfies a parked `receive` if there is one.
    func push(_ event: Event) {
        lock.lock()
        if let waiting = parked {
            parked = nil
            lock.unlock()
            queue.async { Self.deliver(event, to: waiting) }
        } else {
            script.append(event)
            lock.unlock()
        }
    }

    /// Like NWConnection, a pending receive completes with ECANCELED.
    func cancel() {
        lock.lock()
        _cancelled = true
        let waiting = parked
        parked = nil
        lock.unlock()
        if let waiting {
            queue.async { waiting(nil, nil, false, .posix(.ECANCELED)) }
        }
    }

    private static func deliver(_ event: Event,
                                to completion: (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void) {
        switch event {
        case .data(let data): completion(data, nil, false, nil)
        case .eof: completion(nil, nil, true, nil)
        case .error(let error): completion(nil, nil, false, error)
        }
    }
}
