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
        guard raw.count >= 43 else { return nil }

        var curr = 0

        // Check content type is Handshake (0x16)
        guard raw[curr] == 0x16 else { return nil }
        curr += 5 // Skip record header

        // Check handshake type is ClientHello (0x01)
        guard raw[curr] == 0x01 else { return nil }
        curr += 4 // Skip handshake header

        // Skip protocol version (2) + random (32)
        curr += 34
        guard curr < raw.count else { return nil }

        // Skip session ID
        let sessionIDLen = Int(raw[curr])
        curr += 1 + sessionIDLen
        guard curr < raw.count else { return nil }

        // Skip cipher suites
        guard curr + 2 <= raw.count else { return nil }
        let cipherSuitesLen = Int(raw.readUInt16(at: curr))
        curr += 2 + cipherSuitesLen
        guard curr < raw.count else { return nil }

        // Skip compression methods
        guard curr + 1 <= raw.count else { return nil }
        let compressionLen = Int(raw[curr])
        curr += 1 + compressionLen
        guard curr < raw.count else { return nil }

        // Parse extensions
        guard curr + 2 <= raw.count else { return nil }
        let extensionsLen = Int(raw.readUInt16(at: curr))
        curr += 2

        let extensionsEnd = curr + extensionsLen
        guard extensionsEnd <= raw.count else { return nil }

        while curr < extensionsEnd {
            guard curr + 4 <= extensionsEnd else { break }

            let extType = raw.readUInt16(at: curr)
            let extLen = Int(raw.readUInt16(at: curr + 2))
            curr += 4

            guard curr + extLen <= extensionsEnd else { break }

            // SNI extension type == 0x0000
            if extType == 0x0000 {
                guard extLen >= 5 else { return nil }

                let sniDataStart = curr
                let nameLen = Int(raw.readUInt16(at: sniDataStart + 3))
                let realStart = sniDataStart + 5
                let realEnd = realStart + nameLen

                guard realEnd <= curr + extLen else { return nil }

                return (realStart, realEnd)
            }

            curr += extLen
        }

        return nil
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

extension Data {
    func readUInt16(at offset: Int) -> UInt16 {
        return UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }
}
