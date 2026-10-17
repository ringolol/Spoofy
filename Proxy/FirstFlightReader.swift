import Foundation
import Network
import os.log

typealias ReceiveHandler = @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void

/// Drives a `ClientHelloReader` from a client connection, with the first-byte timer of plan §6.3.
/// Everything runs on `queue` (the session queue).
///
/// A receive can't be withdrawn, so when the timer fires one client read is still outstanding.
/// `inFlightRead` hands that read to the relay as its first client→server receive; nothing is lost
/// and order is kept.
final class FirstFlightReader {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "FirstFlight")
    static let readSize = 65_536

    private let client: any ConnectionProtocol
    private let queue: DispatchQueue
    private let firstByteTimeout: TimeInterval
    private let label: String
    private var reader = ClientHelloReader()
    private var completion: ((FirstFlight?) -> Void)?

    /// Set after a first-byte timeout: the outstanding read, delivered to whoever asks first.
    private var orphan: DeferredReceive?

    init(client: any ConnectionProtocol, queue: DispatchQueue, firstByteTimeout: TimeInterval, label: String) {
        self.client = client
        self.queue = queue
        self.firstByteTimeout = firstByteTimeout
        self.label = label
    }

    /// `completion` runs once on `queue`. nil means the client closed or failed before a decision.
    func read(completion: @escaping (FirstFlight?) -> Void) {
        self.completion = completion
        queue.asyncAfter(deadline: .now() + firstByteTimeout) { [self] in
            guard self.completion != nil, reader.state == .awaitingHeader, reader.bufferedCount == 0 else { return }
            Self.logger.info("[\(self.label)] no client bytes in \(self.firstByteTimeout)s, relaying without desync")
            orphan = DeferredReceive()
            finish(.empty)
        }
        receiveNext()
    }

    /// For `ConnectionRelay.relay(firstLeftReceive:)`: after an `.empty` result, the client read that
    /// is still pending; nil otherwise.
    var inFlightRead: ((@escaping ReceiveHandler) -> Void)? {
        guard let orphan else { return nil }
        return { handler in orphan.take(handler) }
    }

    private func receiveNext() {
        client.receive(minimumIncompleteLength: 1, maximumLength: Self.readSize) { [self] data, context, isComplete, error in
            if let orphan {
                orphan.fulfil(data, context, isComplete, error)
                return
            }
            guard completion != nil else { return }
            if let error {
                Self.logger.error("[\(self.label)] first flight read error: \(error.localizedDescription)")
                return finish(nil)
            }
            if let data, !data.isEmpty {
                switch reader.feed(data) {
                case .needMore:
                    break
                case .passthrough(let bytes):
                    return finish(.raw(bytes))
                case .clientHello(let record, let sniOffset):
                    return finish(.clientHello(record: record, sniOffset: sniOffset, leftover: reader.leftover))
                }
            }
            if isComplete {
                // Half-close before the record was complete: nothing sensible to desync.
                Self.logger.warning("[\(self.label)] client closed after \(self.reader.bufferedCount) bytes")
                return finish(nil)
            }
            receiveNext()
        }
    }

    private func finish(_ flight: FirstFlight?) {
        guard let completion else { return }
        self.completion = nil
        completion(flight)
    }
}

/// One receive result handed from whoever got it to whoever wants it, in either order.
private final class DeferredReceive {
    private var result: (Data?, NWConnection.ContentContext?, Bool, NWError?)?
    private var handler: ReceiveHandler?

    func fulfil(_ data: Data?, _ context: NWConnection.ContentContext?, _ isComplete: Bool, _ error: NWError?) {
        if let handler {
            self.handler = nil
            handler(data, context, isComplete, error)
        } else {
            result = (data, context, isComplete, error)
        }
    }

    func take(_ handler: @escaping ReceiveHandler) {
        if let result {
            self.result = nil
            handler(result.0, result.1, result.2, result.3)
        } else {
            self.handler = handler
        }
    }
}
