import XCTest
@testable import SpoofyCore

final class OutlineAccessKeyTests: XCTestCase {
    /// base64url without padding, as Outline emits it.
    private func b64url(_ text: String) -> String {
        Data(text.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func testOutlineSIP002Key() throws {
        let config = try XCTUnwrap(OutlineAccessKey.parse(
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpQYTU1dzByZA@198.51.100.4:443/?outline=1#My%20Server"
        ))
        XCTAssertEqual(config, OutlineServerConfig(host: "198.51.100.4", port: 443, password: "Pa55w0rd",
                                                   cipher: .chacha20IetfPoly1305, prefix: nil))
    }

    func testPaddedBase64AndSurroundingWhitespace() throws {
        let config = try XCTUnwrap(OutlineAccessKey.parse(
            "  ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpQYTU1dzByZA==@example.net:8388\n"
        ))
        XCTAssertEqual(config.host, "example.net")
        XCTAssertEqual(config.port, 8388)
    }

    func testSchemeIsCaseInsensitive() {
        XCTAssertNotNil(OutlineAccessKey.parse("SS://\(b64url("aes-256-gcm:pw"))@example.net:1"))
    }

    func testPasswordKeepsColons() throws {
        let config = try XCTUnwrap(OutlineAccessKey.parse("ss://\(b64url("aes-256-gcm:a:b:c"))@example.net:443"))
        XCTAssertEqual(config.cipher, .aes256Gcm)
        XCTAssertEqual(config.password, "a:b:c")
    }

    func testIPv6HostInBrackets() throws {
        let config = try XCTUnwrap(OutlineAccessKey.parse("ss://\(b64url("aes-256-gcm:pw"))@[2001:db8::1]:443/?outline=1"))
        XCTAssertEqual(config.host, "2001:db8::1")
        XCTAssertEqual(config.port, 443)
    }

    func testLegacyFormat() throws {
        // base64("aes-256-gcm:p@ss:word@203.0.113.7:8388")
        let config = try XCTUnwrap(OutlineAccessKey.parse("ss://YWVzLTI1Ni1nY206cEBzczp3b3JkQDIwMy4wLjExMy43OjgzODg=#legacy"))
        XCTAssertEqual(config, OutlineServerConfig(host: "203.0.113.7", port: 8388, password: "p@ss:word",
                                                   cipher: .aes256Gcm, prefix: nil))
    }

    func testASCIIPrefix() throws {
        let config = try XCTUnwrap(OutlineAccessKey.parse("ss://\(b64url("aes-256-gcm:pw"))@example.net:443/?outline=1&prefix=POST%20"))
        XCTAssertEqual(config.prefix, Data("POST ".utf8))
    }

    func testControlBytePrefix() throws {
        let config = try XCTUnwrap(OutlineAccessKey.parse("ss://\(b64url("aes-256-gcm:pw"))@example.net:443/?prefix=%16%03%01"))
        XCTAssertEqual(config.prefix, Data([0x16, 0x03, 0x01]))
    }

    // N13: outline-sdk (configurl.parseStringPrefix) URL-decodes the prefix to a string and maps
    // each code point <= 0xFF to one byte, so %C2%A8 (U+00A8) is the single byte 0xA8.
    // This is the TLS-ClientHello prefix from Outline's prefixing guide.
    func testPrefixCodePointsBecomeBytes() throws {
        XCTExpectFailure("N13: prefix keeps raw UTF-8 bytes instead of code points")
        let config = try XCTUnwrap(OutlineAccessKey.parse(
            "ss://\(b64url("aes-256-gcm:pw"))@example.net:443/?outline=1&prefix=%16%03%01%00%C2%A8%01%01"
        ))
        XCTAssertEqual(config.prefix?.hex, "16030100a80101")
    }

    // N2: outline-sdk rejects a prefix longer than the salt ("prefix is too long").
    func testPrefixLongerThanSaltIsRejected() {
        XCTExpectFailure("N2: over-long prefix is accepted")
        let prefix = String(repeating: "A", count: 33)
        XCTAssertNil(OutlineAccessKey.parse("ss://\(b64url("aes-256-gcm:pw"))@example.net:443/?prefix=\(prefix)"))
    }

    func testRejectsMalformedKeys() {
        let rejected = [
            "",
            "https://example.net",
            "ss://",
            "ss://\(b64url("rc4-md5:pw"))@example.net:443",          // unsupported cipher
            "ss://\(b64url("aes-256-gcm"))@example.net:443",         // no password separator
            "ss://\(b64url("aes-256-gcm:pw"))@example.net",          // no port
            "ss://\(b64url("aes-256-gcm:pw"))@example.net:70000",    // port out of range
            "ss://\(b64url("aes-256-gcm:pw"))@:443",                 // empty host
            "ss://\(b64url("aes-256-gcm:pw"))@[2001:db8::1]443",     // IPv6 without ':'
            "ss://!!!notbase64!!!@example.net:443",
        ]
        for uri in rejected {
            XCTAssertNil(OutlineAccessKey.parse(uri), uri)
        }
    }
}
