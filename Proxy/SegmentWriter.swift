import Foundation
import Network
import os.log

/// Writes desync segments and the rest of a first flight upstream (plan §6.5 `DesyncOutbound`).
enum SegmentWriter {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Segments")

    /// Sequential sends, each waiting for the previous one to be processed. With TCP_NODELAY each
    /// send leaves as its own TCP segment, which is what splits the SNI. Stops at the first error
    /// and reports it (N7); the caller must not relay after a failure.
    static func write(_ segments: [Data], to conn: any ConnectionProtocol,
                      completion: @escaping (NWError?) -> Void) {
        write(segments[...], to: conn, completion: completion)
    }

    private static func write(_ segments: ArraySlice<Data>, to conn: any ConnectionProtocol,
                              completion: @escaping (NWError?) -> Void) {
        guard let segment = segments.first else { return completion(nil) }
        conn.send(content: segment, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { error in
            if let error { return completion(error) }
            write(segments.dropFirst(), to: conn, completion: completion)
        })
    }

    /// Sends `flight` to `conn`: a ClientHello is desynced per `profile`, then its leftover follows;
    /// raw bytes go out unchanged.
    static func writeFirstFlight(_ flight: FirstFlight, profile: SpoofProfile, to conn: any ConnectionProtocol,
                                 label: String, completion: @escaping (NWError?) -> Void) {
        switch flight {
        case .empty:
            completion(nil)
        case .raw(let bytes):
            logger.info("[\(label)] not a ClientHello, forwarding \(bytes.count) bytes as-is")
            write(bytes.isEmpty ? [] : [bytes], to: conn, completion: completion)
        case .clientHello(let record, let sniOffset, let leftover):
            var segments = TLSDesyncer.split(
                raw: record,
                mode: profile.splitMode,
                chunkSize: profile.chunkSize,
                sniOffset: sniOffset,
                tlsRecordFragmentation: profile.tlsRecordFragmentation
            )
            logger.info("[\(label)] ClientHello \(record.count)B → \(segments.count) segments (mode=\(profile.splitMode.rawValue), sni=\(String(describing: sniOffset)))")
            if !leftover.isEmpty { segments.append(leftover) }
            write(segments, to: conn, completion: completion)
        }
    }
}
