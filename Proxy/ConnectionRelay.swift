import Foundation
import Network
import os.log

/// Abstraction over NWConnection so that ConnectionRelay can pipe between
/// raw TCP connections and encrypted streams (e.g. ShadowsocksStream).
protocol ConnectionProtocol: AnyObject {
    func send(content: Data?, contentContext: NWConnection.ContentContext,
              isComplete: Bool, completion: NWConnection.SendCompletion)
    func receive(minimumIncompleteLength: Int, maximumLength: Int,
                 completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)
    func cancel()
}

extension NWConnection: ConnectionProtocol {}

/// Watches a relay for the scanner (network-scanner plan §3). All calls on the relay's queue.
protocol RelayObserver: AnyObject {
    /// After the write completed. `prefix` is the start of the chunk (up to `observedPrefix` bytes).
    func relayed(_ count: Int, fromLeft: Bool, prefix: Data)
    /// Every event that ends a direction; the observer keeps the first.
    func relayEnded(_ event: RelayEndEvent)
    /// Every `idleCheckInterval`.
    func relayTick(now: UInt64)
}

enum RelayEndEvent: Equatable {
    case readError(fromLeft: Bool, NWError)
    case eof(fromLeft: Bool)
    case writeError(toLeft: Bool, NWError)
    case idleTimeout
}

/// Bidirectional relay between two connections.
/// Reads from source and writes to destination in a loop until either side closes or errors.
/// It logs nothing per packet unless built with `DEBUG_TRACE` (M3); the session logs one line at
/// close with the `Stats`.
final class ConnectionRelay {
    private static let bufferSize = 32768 // 32KB (matches Go's io.CopyBuffer)
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Relay")
    private static let idleTimeoutSeconds: Double = 120
    static let defaultIdleCheckInterval: DispatchTimeInterval = .seconds(15)
    /// Enough for `PayloadSniffer` to find a `Host` header.
    static let observedPrefix = 4096

    struct Stats: Equatable {
        var bytesFromLeft: Int
        var bytesFromRight: Int
        var idleTimedOut: Bool
    }

    /// Start bidirectional relay between two connections.
    /// Calls completion when both directions finish or idle timeout is reached.
    /// `firstLeftReceive`, when set, replaces the first `left.receive` (a read already in flight,
    /// see `FirstFlightReader.inFlightRead`).
    static func relay(
        left: any ConnectionProtocol,
        right: any ConnectionProtocol,
        label: String = "",
        queue: DispatchQueue,
        idleTimeout: Double = idleTimeoutSeconds,
        idleCheckInterval: DispatchTimeInterval = defaultIdleCheckInterval,
        firstLeftReceive: ((@escaping ReceiveHandler) -> Void)? = nil,
        observer: RelayObserver? = nil,
        completion: @escaping (Stats) -> Void
    ) {
        trace("Relay started \(label)")

        let group = DispatchGroup()
        let completed = LockedFlag()
        let activity = RelayActivity()

        let finish: (_ idleTimedOut: Bool) -> Void = { idleTimedOut in
            guard completed.setIfFalse() else { return }
            left.cancel()
            right.cancel()
            let (fromLeft, fromRight) = activity.bytes()
            completion(Stats(bytesFromLeft: fromLeft, bytesFromRight: fromRight, idleTimedOut: idleTimedOut))
        }

        // Idle timeout: periodically check if connection has been inactive
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + idleCheckInterval,
            repeating: idleCheckInterval
        )
        timer.setEventHandler {
            observer?.relayTick(now: DispatchTime.now().uptimeNanoseconds)
            if activity.secondsSinceLast() > idleTimeout {
                observer?.relayEnded(.idleTimeout)
                timer.cancel()
                finish(true)
            }
        }
        timer.resume()

        group.enter()
        pipe(from: left, to: right, label: "\(label) client→server", activity: activity, fromLeft: true,
             observer: observer, firstReceive: firstLeftReceive) {
            group.leave()
        }

        group.enter()
        pipe(from: right, to: left, label: "\(label) server→client", activity: activity, fromLeft: false,
             observer: observer) {
            group.leave()
        }

        group.notify(queue: queue) {
            timer.cancel()
            finish(false)
        }
    }

    /// One-directional pipe: read from `source`, write to `dest`.
    private static func pipe(
        from source: any ConnectionProtocol,
        to dest: any ConnectionProtocol,
        label: String,
        activity: RelayActivity,
        fromLeft: Bool,
        observer: RelayObserver?,
        firstReceive: ((@escaping ReceiveHandler) -> Void)? = nil,
        completion: @escaping () -> Void
    ) {
        let receive: (@escaping ReceiveHandler) -> Void = firstReceive ?? { handler in
            source.receive(minimumIncompleteLength: 1, maximumLength: bufferSize, completion: handler)
        }
        receive { content, _, isComplete, error in
            if let error = error {
                trace("\(label) read error: \(error.localizedDescription)")
                observer?.relayEnded(.readError(fromLeft: fromLeft, error))
                dest.cancel()
                completion()
                return
            }

            if let data = content, !data.isEmpty {
                activity.record(data.count, fromLeft: fromLeft)
                trace("\(label) relaying \(data.count) bytes")
                dest.send(content: data, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { sendError in
                    if let sendError = sendError {
                        trace("\(label) write error: \(sendError.localizedDescription)")
                        observer?.relayEnded(.writeError(toLeft: !fromLeft, sendError))
                        // Cancel both: the opposite pipe is parked in receive on `dest` (N14).
                        source.cancel()
                        dest.cancel()
                        completion()
                        return
                    }
                    observer?.relayed(data.count, fromLeft: fromLeft, prefix: data.prefix(observedPrefix))
                    pipe(from: source, to: dest, label: label, activity: activity, fromLeft: fromLeft,
                         observer: observer, completion: completion)
                })
            } else if isComplete {
                trace("\(label) complete (isComplete=true, data=nil/empty)")
                observer?.relayEnded(.eof(fromLeft: fromLeft))
                dest.cancel()
                completion()
            } else {
                // No data, not complete - continue
                trace("\(label) empty read, retrying")
                pipe(from: source, to: dest, label: label, activity: activity, fromLeft: fromLeft,
                     observer: observer, completion: completion)
            }
        }
    }

    /// Per-packet logging, compiled out unless `DEBUG_TRACE` is set (M3): it costs CPU on every
    /// read and puts hostnames in the unified log.
    @inline(__always)
    private static func trace(_ message: @autoclosure () -> String) {
        #if DEBUG_TRACE
        let text = message()
        logger.debug("\(text)")
        #endif
    }
}

/// Thread-safe last-activity timestamp (for the idle timeout) and byte counts.
final class RelayActivity {
    private var timestamp = DispatchTime.now()
    private var fromLeft = 0
    private var fromRight = 0
    private let lock = NSLock()

    func record(_ count: Int, fromLeft isLeft: Bool) {
        lock.withLock {
            timestamp = DispatchTime.now()
            if isLeft { fromLeft += count } else { fromRight += count }
        }
    }

    func secondsSinceLast() -> Double {
        let elapsed = lock.withLock { DispatchTime.now().uptimeNanoseconds - timestamp.uptimeNanoseconds }
        return Double(elapsed) / 1_000_000_000
    }

    func bytes() -> (fromLeft: Int, fromRight: Int) {
        lock.withLock { (fromLeft, fromRight) }
    }
}

/// Thread-safe flag that can be set exactly once.
final class LockedFlag {
    private var flag = false
    private let lock = NSLock()

    /// Returns true if the flag was false and is now set to true. Returns false if already set.
    func setIfFalse() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if flag { return false }
        flag = true
        return true
    }
}
