import Foundation

/// What a desync tunnel sends upstream before the plain relay starts (plan §6.3, §6.5).
enum FirstFlight {
    /// The client sent nothing before the first-byte timeout (a server-first protocol).
    case empty
    /// Not a TLS ClientHello: forward as-is.
    case raw(Data)
    /// The complete first TLS record; `sniOffset` is relative to its start. `leftover` is whatever
    /// the client sent after the record, forwarded after the segments.
    case clientHello(record: Data, sniOffset: (start: Int, end: Int)?, leftover: Data)
}

/// Incremental parser for the first client flight of a CONNECT / SOCKS5 tunnel (plan §6.3).
/// Pure: the caller feeds it `receive` results. It decides on the first byte whether the
/// stream is TLS at all, so reads can ask for one byte at a time (U7, N15).
struct ClientHelloReader {
    enum State: Equatable {
        case awaitingHeader
        case awaitingBody(recordLength: Int)
        case done
    }

    enum Output {
        /// Call `receive` again.
        case needMore
        case clientHello(record: Data, sniOffset: (start: Int, end: Int)?)
        /// Not TLS, not a ClientHello or malformed: forward these bytes unmodified.
        case passthrough(Data)
    }

    /// TLSPlaintext.length limit (RFC 8446 §5.1); `TLSMessage.parse` uses the same bound.
    static let maxRecord = Int(TLSMessage.maxPayloadLen)

    private(set) var state: State = .awaitingHeader
    private var buffer = Data()
    /// Bytes after the ClientHello record. Valid once `feed` returned `.clientHello`.
    private(set) var leftover = Data()

    var bufferedCount: Int { buffer.count }

    mutating func feed(_ chunk: Data) -> Output {
        guard state != .done else {
            assertionFailure("ClientHelloReader.feed after done")
            return .passthrough(chunk)
        }
        buffer.append(chunk)

        if case .awaitingHeader = state {
            guard let first = buffer.first else { return .needMore }
            guard first == 0x16 else { return pass() }
            guard buffer.count >= 5 else { return .needMore }
            guard buffer[buffer.startIndex + 1] == 0x03 else { return pass() }
            let length = Int(buffer.readUInt16(at: buffer.startIndex + 3))
            guard length > 0, length <= Self.maxRecord else { return pass() }
            state = .awaitingBody(recordLength: length)
        }

        guard case .awaitingBody(let length) = state else { return .needMore }
        let total = 5 + length
        guard buffer.count >= total else { return .needMore }
        let record = Data(buffer.prefix(total))
        guard record[5] == 0x01 else { return pass() }

        state = .done
        leftover = Data(buffer.dropFirst(total))
        buffer = Data()
        let sniOffset = TLSMessage.parse(from: record)?.extractSNIOffset()
        return .clientHello(record: record, sniOffset: sniOffset)
    }

    /// EOF before a decision: whatever arrived is forwarded as-is.
    mutating func finishOnEOF() -> Output {
        guard state != .done else { return .passthrough(Data()) }
        return pass()
    }

    private mutating func pass() -> Output {
        state = .done
        let bytes = buffer
        buffer = Data()
        return .passthrough(bytes)
    }
}
