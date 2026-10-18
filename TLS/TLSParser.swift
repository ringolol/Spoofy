import Foundation

enum TLSMessageType: UInt8 {
    case invalid          = 0x00
    case changeCipherSpec = 0x14
    case alert            = 0x15
    case handshake        = 0x16
    case applicationData  = 0x17
    case heartbeat        = 0x18
}

struct TLSHeader {
    let type_: TLSMessageType
    let protoVersion: UInt16
    let payloadLen: UInt16

    func bytes() -> Data {
        var buf = Data(count: 5)
        buf[0] = type_.rawValue
        buf[1] = UInt8(protoVersion >> 8)
        buf[2] = UInt8(protoVersion & 0xFF)
        buf[3] = UInt8(payloadLen >> 8)
        buf[4] = UInt8(payloadLen & 0xFF)
        return buf
    }
}

struct TLSMessage {
    static let headerLen = 5
    static let maxPayloadLen: UInt16 = 16384

    let header: TLSHeader
    let raw: Data

    var isClientHello: Bool {
        raw.count > TLSMessage.headerLen
            && header.type_ == .handshake
            && raw[5] == 0x01
    }

    /// Returns (start, end) offsets of the SNI hostname within `raw`.
    func extractSNIOffset() -> (start: Int, end: Int)? {
        guard raw.count >= 43, let layout = ClientHelloLayout(raw) else { return nil }
        guard let ext = layout.extensions.first(where: { $0.type == 0x0000 }) else { return nil }
        // server_name_list length (2), name type (1), name length (2)
        guard ext.body.count >= 5 else { return nil }
        let nameLen = Int(raw.readUInt16(at: ext.body.lowerBound + 3))
        let realStart = ext.body.lowerBound + 5
        let realEnd = realStart + nameLen
        guard realEnd <= ext.body.upperBound else { return nil }
        return (realStart, realEnd)
    }

    /// Parse a TLS message from the given Data buffer.
    /// Returns the TLSMessage and how many bytes were consumed, or nil if insufficient data.
    static func parse(from data: Data) -> TLSMessage? {
        guard data.count >= headerLen else { return nil }

        let type_ = TLSMessageType(rawValue: data[0]) ?? .invalid
        let protoVersion = data.readUInt16(at: 1)
        let payloadLen = data.readUInt16(at: 3)

        guard payloadLen <= maxPayloadLen else { return nil }

        let totalLen = headerLen + Int(payloadLen)
        guard data.count >= totalLen else { return nil }

        let header = TLSHeader(type_: type_, protoVersion: protoVersion, payloadLen: payloadLen)
        let raw = Data(data.prefix(totalLen))

        return TLSMessage(header: header, raw: raw)
    }
}

/// Where the session ID and the extensions sit in a ClientHello record (offsets into `raw`).
/// A malformed extension ends the walk; the ones before it are kept.
struct ClientHelloLayout {
    let sessionID: Range<Int>
    let extensions: [(type: UInt16, body: Range<Int>)]

    /// `raw` must start at index 0.
    init?(_ raw: Data) {
        guard raw.count > 9, raw[0] == 0x16, raw[5] == 0x01 else { return nil }
        // Record header (5), handshake header (4), version (2), random (32).
        var curr = 43
        guard curr < raw.count else { return nil }
        let sessionIDLen = Int(raw[curr])
        sessionID = (curr + 1)..<(curr + 1 + sessionIDLen)
        curr += 1 + sessionIDLen
        guard curr + 2 <= raw.count else { return nil }
        curr += 2 + Int(raw.readUInt16(at: curr))           // cipher suites
        guard curr + 1 <= raw.count else { return nil }
        curr += 1 + Int(raw[curr])                           // compression methods
        guard curr + 2 <= raw.count else { return nil }
        let extensionsEnd = curr + 2 + Int(raw.readUInt16(at: curr))
        curr += 2
        guard extensionsEnd <= raw.count else { return nil }

        var extensions: [(type: UInt16, body: Range<Int>)] = []
        while curr + 4 <= extensionsEnd {
            let type = raw.readUInt16(at: curr)
            let length = Int(raw.readUInt16(at: curr + 2))
            curr += 4
            guard curr + length <= extensionsEnd else { break }
            extensions.append((type, curr..<(curr + length)))
            curr += length
        }
        self.extensions = extensions
    }
}

/// What the scanner keeps of a ClientHello (network-scanner plan §5); never the payload itself.
struct ClientHelloInfo: Equatable, Sendable {
    let sni: String?
    let sessionID: Data
    /// encrypted_client_hello (0xfe0d) present.
    let hasECH: Bool
    let alpn: [String]

    static func parse(record: Data) -> ClientHelloInfo? {
        let raw = Data(record)
        guard let layout = ClientHelloLayout(raw), layout.sessionID.upperBound <= raw.count else { return nil }
        let sni = TLSMessage.parse(from: raw)?.extractSNIOffset().map {
            String(decoding: raw[$0.start..<$0.end], as: UTF8.self)
        }
        var alpn: [String] = []
        if let ext = layout.extensions.first(where: { $0.type == 0x0010 }), ext.body.count >= 2 {
            var curr = ext.body.lowerBound + 2
            while curr < ext.body.upperBound {
                let length = Int(raw[curr])
                guard curr + 1 + length <= ext.body.upperBound else { break }
                alpn.append(String(decoding: raw[(curr + 1)..<(curr + 1 + length)], as: UTF8.self))
                curr += 1 + length
            }
        }
        return ClientHelloInfo(sni: sni, sessionID: raw[layout.sessionID],
                               hasECH: layout.extensions.contains { $0.type == 0xfe0d }, alpn: alpn)
    }
}

/// The start of a server's first flight. Tolerant of truncation: the session ID must be complete,
/// `negotiatedVersion` is nil when `supported_versions` isn't visible.
struct ServerHelloInfo: Equatable, Sendable {
    let sessionID: Data
    /// 0x0304 when the ServerHello carries supported_versions (TLS 1.3).
    let negotiatedVersion: UInt16?

    static func parse(prefix: Data) -> ServerHelloInfo? {
        let raw = Data(prefix)
        guard raw.count > 43, raw[0] == 0x16, raw[5] == 0x02 else { return nil }
        let idLength = Int(raw[43])
        let idEnd = 44 + idLength
        guard idLength <= 32, idEnd <= raw.count else { return nil }
        let sessionID = raw[44..<idEnd]

        // cipher suite (2), compression (1), extensions length (2)
        var version: UInt16?
        var curr = idEnd + 3
        if curr + 2 <= raw.count {
            let extensionsEnd = min(raw.count, curr + 2 + Int(raw.readUInt16(at: curr)))
            curr += 2
            while curr + 4 <= extensionsEnd {
                let type = raw.readUInt16(at: curr)
                let length = Int(raw.readUInt16(at: curr + 2))
                curr += 4
                guard curr + length <= extensionsEnd else { break }
                if type == 0x002b, length == 2 { version = raw.readUInt16(at: curr) }
                curr += length
            }
        }
        return ServerHelloInfo(sessionID: Data(sessionID), negotiatedVersion: version)
    }
}

extension Data {
    func readUInt16(at offset: Int) -> UInt16 {
        return UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }
}
