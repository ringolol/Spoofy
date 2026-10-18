import Foundation
@testable import SpoofyCore

/// `ConnectionObserver` that keeps every call. Thread-safe: sessions call it from their own
/// queues, `ProxyServer` from the server queue.
final class RecordingObserver: ConnectionObserver {
    private let lock = NSLock()
    private var _starts: [TraceStart] = []
    private var _summaries: [TraceSummary] = []
    private var _refusals: [RefusalRecord] = []

    var starts: [TraceStart] { lock.withLock { _starts } }
    var summaries: [TraceSummary] { lock.withLock { _summaries } }
    var refusals: [RefusalRecord] { lock.withLock { _refusals } }

    func begin(_ start: TraceStart, queue: DispatchQueue) -> ConnectionTrace? {
        lock.withLock { _starts.append(start) }
        return ConnectionTrace(start, queue: queue) { [weak self] summary in
            guard let self else { return }
            self.lock.withLock { self._summaries.append(summary) }
        }
    }

    func refused(_ record: RefusalRecord) {
        lock.withLock { _refusals.append(record) }
    }
}
