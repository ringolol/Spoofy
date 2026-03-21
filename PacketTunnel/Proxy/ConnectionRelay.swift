import Foundation
import Network
import os.log

/// Bidirectional relay between two NWConnections.
/// Reads from source and writes to destination in a loop until either side closes or errors.
final class ConnectionRelay {
    private static let bufferSize = 32768 // 32KB (matches Go's io.CopyBuffer)
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Relay")
    private static let idleTimeoutSeconds: Double = 120
    private static let idleCheckIntervalSeconds: Int = 15

    /// Start bidirectional relay between two connections.
    /// Calls completion when both directions finish or idle timeout is reached.
    static func relay(
        left: NWConnection,
        right: NWConnection,
        label: String = "",
        queue: DispatchQueue,
        completion: @escaping () -> Void
    ) {
        logger.debug("Relay started \(label)")


        let group = DispatchGroup()
        let completed = LockedFlag()
        let activity = LastActivity()

        // Idle timeout: periodically check if connection has been inactive
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + .seconds(idleCheckIntervalSeconds),
            repeating: .seconds(idleCheckIntervalSeconds)
        )
        timer.setEventHandler {
            if activity.secondsSinceLast() > idleTimeoutSeconds {
                if completed.setIfFalse() {
                    logger.debug("Relay idle timeout \(label)")
            
                    left.cancel()
                    right.cancel()
                    completion()
                }
            }
        }
        timer.resume()

        let finish: () -> Void = {
            guard completed.setIfFalse() else { return }
            timer.cancel()
            left.cancel()
            right.cancel()
            completion()
        }

        group.enter()
        pipe(from: left, to: right, label: "\(label) client→server", activity: activity) {
            group.leave()
        }

        group.enter()
        pipe(from: right, to: left, label: "\(label) server→client", activity: activity) {
            group.leave()
        }

        group.notify(queue: queue) {
            finish()
        }
    }

    /// One-directional pipe: read from `source`, write to `dest`.
    private static func pipe(
        from source: NWConnection,
        to dest: NWConnection,
        label: String,
        activity: LastActivity,
        completion: @escaping () -> Void
    ) {
        source.receive(minimumIncompleteLength: 1, maximumLength: bufferSize) { content, _, isComplete, error in
            if let error = error {
                logger.debug("\(label) read error: \(error.localizedDescription) srcState=\(String(describing: source.state)) dstState=\(String(describing: dest.state))")
        
                dest.cancel()
                completion()
                return
            }

            if let data = content, !data.isEmpty {
                activity.touch()
                logger.debug("\(label) relaying \(data.count) bytes")
        
                dest.send(content: data, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { sendError in
                    if let sendError = sendError {
                        logger.debug("\(label) write error: \(sendError.localizedDescription)")
                
                        source.cancel()
                        completion()
                        return
                    }
                    // Continue reading
                    pipe(from: source, to: dest, label: label, activity: activity, completion: completion)
                })
            } else if isComplete {
                logger.debug("\(label) complete (isComplete=true, data=nil/empty) srcState=\(String(describing: source.state))")
        
                dest.cancel()
                completion()
            } else {
                // No data, not complete - continue
                logger.debug("\(label) empty read, retrying")
        
                pipe(from: source, to: dest, label: label, activity: activity, completion: completion)
            }
        }
    }
}

/// Thread-safe timestamp tracker for idle timeout detection.
final class LastActivity {
    private var timestamp = DispatchTime.now()
    private let lock = NSLock()

    func touch() {
        lock.lock()
        timestamp = DispatchTime.now()
        lock.unlock()
    }

    func secondsSinceLast() -> Double {
        lock.lock()
        let elapsed = DispatchTime.now().uptimeNanoseconds - timestamp.uptimeNanoseconds
        lock.unlock()
        return Double(elapsed) / 1_000_000_000
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
