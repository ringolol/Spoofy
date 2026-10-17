import Foundation

/// Builds a minimal, well-formed TLS ClientHello record for parser edge cases
/// that the captured fixtures don't cover.
enum ClientHelloBuilder {
    static func make(sni: String?, extensionsBefore: [(type: UInt16, body: Data)] = []) -> Data {
        var body = Data([0x03, 0x03])                    // legacy_version
        body += Data(repeating: 0xAA, count: 32)         // random
        body += [32] + Data(repeating: 0xBB, count: 32)  // session id
        body += [0x00, 0x02, 0x13, 0x01]                 // cipher suites
        body += [0x01, 0x00]                             // compression methods

        var extensions = Data()
        for ext in extensionsBefore {
            extensions += u16(ext.type) + u16(ext.body.count) + ext.body
        }
        if let sni {
            let name = Data(sni.utf8)
            let serverNameList = Data([0x00]) + u16(name.count) + name
            let extBody = u16(serverNameList.count) + serverNameList
            extensions += u16(0x0000) + u16(extBody.count) + extBody
        }
        body += u16(extensions.count) + extensions

        let handshake = Data([0x01]) + u24(body.count) + body
        return Data([0x16, 0x03, 0x01]) + u16(handshake.count) + handshake
    }

    static func u16(_ value: Int) -> Data { Data([UInt8(value >> 8), UInt8(value & 0xFF)]) }
    static func u16(_ value: UInt16) -> Data { u16(Int(value)) }
    static func u24(_ value: Int) -> Data { Data([UInt8(value >> 16), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]) }
}
