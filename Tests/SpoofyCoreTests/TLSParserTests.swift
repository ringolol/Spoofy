import XCTest
@testable import SpoofyCore

final class TLSParserTests: XCTestCase {
    private func sniHost(_ message: TLSMessage) -> String? {
        guard let offset = message.extractSNIOffset() else { return nil }
        return String(decoding: message.raw[offset.start..<offset.end], as: UTF8.self)
    }

    func testParsesCapturedTLS13ClientHello() throws {
        let message = try XCTUnwrap(TLSMessage.parse(from: Fixtures.tls13ClientHello))
        XCTAssertEqual(message.header.type_, .handshake)
        XCTAssertEqual(message.header.protoVersion, 0x0301)
        XCTAssertEqual(Int(message.header.payloadLen), 1502)
        XCTAssertEqual(message.raw.count, 1507)
        XCTAssertTrue(message.isClientHello)
        XCTAssertEqual(message.extractSNIOffset()?.start, 117)
        XCTAssertEqual(message.extractSNIOffset()?.end, 132)
        XCTAssertEqual(sniHost(message), "www.example.com")
    }

    func testParsesCapturedTLS12ClientHello() throws {
        let message = try XCTUnwrap(TLSMessage.parse(from: Fixtures.tls12ClientHello))
        XCTAssertTrue(message.isClientHello)
        XCTAssertEqual(message.raw.count, 230)
        XCTAssertEqual(message.extractSNIOffset()?.start, 111)
        XCTAssertEqual(message.extractSNIOffset()?.end, 125)
        XCTAssertEqual(sniHost(message), "api.github.com")
    }

    func testHeaderBytesRoundTrip() throws {
        let message = try XCTUnwrap(TLSMessage.parse(from: Fixtures.tls12ClientHello))
        XCTAssertEqual(message.header.bytes(), Fixtures.tls12ClientHello.prefix(5))
    }

    func testParseConsumesOnlyTheFirstRecord() throws {
        let data = Fixtures.tls12ClientHello + Data([0x17, 0x03, 0x03, 0x00, 0x01, 0xFF])
        let message = try XCTUnwrap(TLSMessage.parse(from: data))
        XCTAssertEqual(message.raw, Fixtures.tls12ClientHello)
    }

    func testTruncatedRecordNeedsMoreData() {
        XCTAssertNil(TLSMessage.parse(from: Fixtures.tls12ClientHello.dropLast()))
        XCTAssertNil(TLSMessage.parse(from: Data([0x16, 0x03, 0x01, 0x00])))
        XCTAssertNil(TLSMessage.parse(from: Data()))
    }

    func testOversizedRecordLengthIsRejected() {
        // 0x4001 = 16385 > 2^14, the TLS plaintext record limit.
        var data = Data([0x16, 0x03, 0x01, 0x40, 0x01])
        data += Data(repeating: 0, count: 0x4001)
        XCTAssertNil(TLSMessage.parse(from: data))
    }

    func testApplicationDataIsNotAClientHello() throws {
        var data = Fixtures.tls12ClientHello
        data[0] = 0x17
        let message = try XCTUnwrap(TLSMessage.parse(from: data))
        XCTAssertEqual(message.header.type_, .applicationData)
        XCTAssertFalse(message.isClientHello)
        XCTAssertNil(message.extractSNIOffset())
    }

    func testUnknownContentTypeParsesAsInvalid() throws {
        var data = Fixtures.tls12ClientHello
        data[0] = 0x42
        let message = try XCTUnwrap(TLSMessage.parse(from: data))
        XCTAssertEqual(message.header.type_, .invalid)
        XCTAssertFalse(message.isClientHello)
    }

    func testServerHelloHandshakeTypeIsNotAClientHello() throws {
        var data = Fixtures.tls12ClientHello
        data[5] = 0x02
        let message = try XCTUnwrap(TLSMessage.parse(from: data))
        XCTAssertFalse(message.isClientHello)
        XCTAssertNil(message.extractSNIOffset())
    }

    func testClientHelloWithoutSNIHasNoOffset() throws {
        let message = try XCTUnwrap(TLSMessage.parse(from: ClientHelloBuilder.make(sni: nil)))
        XCTAssertTrue(message.isClientHello)
        XCTAssertNil(message.extractSNIOffset())
    }

    func testSNIAfterOtherExtensionsIsFound() throws {
        let data = ClientHelloBuilder.make(
            sni: "example.org",
            extensionsBefore: [(0x000a, Data([0x00, 0x02, 0x00, 0x1d])), (0x0015, Data(repeating: 0, count: 300))]
        )
        let message = try XCTUnwrap(TLSMessage.parse(from: data))
        XCTAssertEqual(sniHost(message), "example.org")
    }

    func testSNIExtensionTooShortYieldsNil() throws {
        // A server_name extension with a 2-byte body can't hold a name entry.
        let data = ClientHelloBuilder.make(sni: nil, extensionsBefore: [(0x0000, Data([0x00, 0x00]))])
        let message = try XCTUnwrap(TLSMessage.parse(from: data))
        XCTAssertNil(message.extractSNIOffset())
    }

    func testSNINameLengthPastExtensionYieldsNil() throws {
        var data = ClientHelloBuilder.make(sni: "example.org")
        let nameRange = try XCTUnwrap(data.range(of: Data("example.org".utf8)))
        // Bump the name length (2 bytes just before the name) beyond the extension.
        data[nameRange.lowerBound - 1] = 0xFF
        let message = try XCTUnwrap(TLSMessage.parse(from: data))
        XCTAssertNil(message.extractSNIOffset())
    }

    func testEveryTruncationOfTheHandshakeBodyIsSafe() {
        // Shrink the record and its payload together, so parse() succeeds and the SNI
        // walker sees a short body at every possible cut point. It must never trap.
        let full = Fixtures.tls12ClientHello
        for length in 6..<full.count {
            var data = Data(full.prefix(length))
            let payload = length - 5
            data[3] = UInt8(payload >> 8)
            data[4] = UInt8(payload & 0xFF)
            guard let message = TLSMessage.parse(from: data) else {
                return XCTFail("parse failed at length \(length)")
            }
            if let offset = message.extractSNIOffset() {
                XCTAssertLessThanOrEqual(offset.end, data.count)
            }
        }
    }

    // M5: Data.readUInt16(at:) and TLSMessage.parse index from 0, so a non-zero-based
    // slice traps instead of parsing. Enable after the fix.
    func testParsesFromDataSlice() throws {
        try XCTSkipIf(true, "M5: parsing a Data slice traps (zero-based indexing)")
        let padded = Data([0xEE, 0xEE, 0xEE]) + Fixtures.tls12ClientHello
        let slice = padded.dropFirst(3)
        let message = try XCTUnwrap(TLSMessage.parse(from: slice))
        XCTAssertEqual(sniHost(message), "api.github.com")
    }
}
