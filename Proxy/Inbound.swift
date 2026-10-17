import Foundation

/// A finished inbound handshake (plan §6.4). Parsers produce it; they never touch the network.
struct InboundRequest: Equatable {
    enum Kind: Equatable {
        /// CONNECT or SOCKS5 CONNECT: the session replies success, then relays bytes.
        case tunnel
        /// Plain HTTP: `head` is the rewritten request head to send upstream first.
        case http(head: Data)
    }

    let target: DialTarget
    let kind: Kind
    /// Bytes the client sent after the handshake. They must be forwarded, in order.
    let leftover: Data
}

indirect enum InboundStep {
    /// Call `feed` again with more client bytes.
    case needMore
    /// Write these bytes to the client, then continue with `then`.
    case reply(Data, then: InboundStep)
    case request(InboundRequest)
    /// Write `reply` (if any), then close.
    case fail(reply: Data?, reason: String)
}

/// Incremental: "need N bytes" checks return `.needMore` without consuming, so input split at
/// any byte boundary gives the same result as one chunk.
protocol InboundParser {
    mutating func feed(_ chunk: Data) -> InboundStep
}

enum InboundProtocol: String {
    case http
    case socks5

    /// The session picks the parser from the first byte: SOCKS5 starts with its version 0x05,
    /// HTTP with a method token.
    init(firstByte: UInt8) {
        self = firstByte == 0x05 ? .socks5 : .http
    }

    func makeParser() -> InboundParser {
        switch self {
        case .http: return HTTPHeadParser()
        case .socks5: return SOCKS5Parser()
        }
    }
}
