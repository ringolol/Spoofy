import Foundation
import Network

/// SOCKS5 greeting and CONNECT request, no authentication (RFC 1928; plan §6.4.2).
///
/// Bytes are buffered across reads and the parser re-runs on what is left after each message,
/// so a pipelined greeting + request + ClientHello in one read works, and so does a request
/// split byte by byte (N6).
struct SOCKS5Parser: InboundParser {
    enum State: Equatable {
        case greeting
        case request
        case done
    }

    private(set) var state: State = .greeting
    private var buffer: [UInt8] = []

    mutating func feed(_ chunk: Data) -> InboundStep {
        buffer.append(contentsOf: chunk)
        switch state {
        case .greeting: return parseGreeting()
        case .request: return parseRequest()
        case .done:
            assertionFailure("SOCKS5Parser.feed after done")
            return .needMore
        }
    }

    // MARK: - Replies

    /// RFC 1928 §6 reply. BND.ADDR/BND.PORT are always 0.0.0.0:0 (M7): legal, since a CONNECT
    /// client has no use for them, and the real local address isn't known to the session.
    static func reply(_ code: UInt8) -> Data {
        Data([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    }

    static let succeeded: UInt8 = 0x00
    static let generalFailure: UInt8 = 0x01
    static let notAllowedByRuleset: UInt8 = 0x02
    static let networkUnreachable: UInt8 = 0x03
    static let hostUnreachable: UInt8 = 0x04
    static let connectionRefused: UInt8 = 0x05
    static let ttlExpired: UInt8 = 0x06
    static let commandNotSupported: UInt8 = 0x07
    static let addressTypeNotSupported: UInt8 = 0x08

    /// Reply code for a failed outbound connect.
    static func replyCode(for error: OutboundError) -> UInt8 {
        switch error {
        case .dial(.timeout):
            return ttlExpired
        case .dial(.allFailed(let errors)):
            switch errors.last {
            case .posix(.ECONNREFUSED): return connectionRefused
            case .posix(.EHOSTUNREACH), .dns: return hostUnreachable
            case .posix(.ENETUNREACH): return networkUnreachable
            default: return generalFailure
            }
        case .dial(.cancelled), .shadowsocks:
            return generalFailure
        }
    }

    // MARK: - Parsing

    private mutating func parseGreeting() -> InboundStep {
        // VER NMETHODS METHODS...
        guard buffer.count >= 2 else { return .needMore }
        guard buffer[0] == 0x05 else {
            state = .done
            return .fail(reply: nil, reason: .malformed("SOCKS version \(buffer[0]) in greeting"))
        }
        let methodsEnd = 2 + Int(buffer[1])
        guard buffer.count >= methodsEnd else { return .needMore }
        guard buffer[2..<methodsEnd].contains(0x00) else {
            state = .done
            return .fail(reply: Data([0x05, 0xFF]), reason: .socks5AuthRequired(offered: Array(buffer[2..<methodsEnd])))
        }
        buffer.removeFirst(methodsEnd)
        state = .request
        // Whatever followed the greeting in the same read may already be the request.
        return .reply(Data([0x05, 0x00]), then: parseRequest())
    }

    private mutating func parseRequest() -> InboundStep {
        // VER CMD RSV ATYP DST.ADDR DST.PORT
        guard buffer.count >= 4 else { return .needMore }
        guard buffer[0] == 0x05 else { return fail(Self.generalFailure, .malformed("SOCKS version \(buffer[0]) in request")) }
        guard buffer[1] == 0x01 else { return fail(Self.commandNotSupported, .socks5Command(buffer[1])) }

        let host: String
        let portOffset: Int
        switch buffer[3] {
        case 0x01:
            guard buffer.count >= 10 else { return .needMore }
            host = buffer[4..<8].map(String.init).joined(separator: ".")
            portOffset = 8
        case 0x04:
            guard buffer.count >= 22 else { return .needMore }
            guard let address = IPv6Address(Data(buffer[4..<20])) else {
                return fail(Self.generalFailure, .malformed("bad IPv6 address"))
            }
            host = "\(address)"
            portOffset = 20
        case 0x03:
            guard buffer.count >= 5 else { return .needMore }
            let length = Int(buffer[4])
            guard length > 0 else { return fail(Self.generalFailure, .malformed("empty domain")) }
            guard buffer.count >= 5 + length + 2 else { return .needMore }
            let name = buffer[5..<(5 + length)]
            guard name.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else {
                return fail(Self.generalFailure, .malformed("non-ASCII domain"))
            }
            host = String(decoding: name, as: UTF8.self)
            portOffset = 5 + length
        default:
            return fail(Self.addressTypeNotSupported, .socks5AddressType(buffer[3]))
        }

        let port = UInt16(buffer[portOffset]) << 8 | UInt16(buffer[portOffset + 1])
        guard port != 0 else { return fail(Self.generalFailure, .malformed("port 0")) }

        let leftover = Data(buffer[(portOffset + 2)...])
        buffer = []
        state = .done
        return .request(InboundRequest(target: DialTarget(host: host, port: port), kind: .tunnel, leftover: leftover))
    }

    private mutating func fail(_ code: UInt8, _ reason: InboundFailure) -> InboundStep {
        state = .done
        return .fail(reply: Self.reply(code), reason: reason)
    }
}
