import XCTest
@testable import SpoofyCore

final class DNSQueryTests: XCTestCase {
    private let resolver = DoHResolver(serverURL: "https://127.0.0.1/dns-query")

    func testQueryWireFormat() throws {
        let query = try XCTUnwrap(resolver.buildDNSQuery(domain: "example.com", qtype: 1))
        // Bytes 0-1 are a random transaction ID.
        let expected: [UInt8] = [
            0x01, 0x00, // flags: RD
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QD=1 AN=0 NS=0 AR=0
            7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            3, 0x63, 0x6f, 0x6d, 0, // "com", root
            0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
        ]
        XCTAssertEqual(Array(query.dropFirst(2)), expected)
    }

    func testLabelLengthIsCountedInBytes() throws {
        // "bücher" is 6 characters but 7 UTF-8 bytes.
        let query = try XCTUnwrap(resolver.buildDNSQuery(domain: "bücher.de", qtype: 1))
        XCTAssertEqual(query[12], 7)
    }

    // C2 regression: label lengths used to go through UInt8(label.count), which traps above 255.
    func testRejectsOverlongLabels() {
        XCTAssertNotNil(resolver.buildDNSQuery(domain: String(repeating: "a", count: 63) + ".com", qtype: 1))
        XCTAssertNil(resolver.buildDNSQuery(domain: String(repeating: "a", count: 64) + ".com", qtype: 1))
        XCTAssertNil(resolver.buildDNSQuery(domain: String(repeating: "a", count: 300) + ".com", qtype: 1))
    }

    func testRejectsOverlongNames() {
        let label63 = String(repeating: "a", count: 63)
        let name253 = [label63, label63, label63, String(repeating: "b", count: 61)].joined(separator: ".")
        let name254 = [label63, label63, label63, String(repeating: "b", count: 62)].joined(separator: ".")
        XCTAssertNotNil(resolver.buildDNSQuery(domain: name253, qtype: 1))
        XCTAssertNil(resolver.buildDNSQuery(domain: name254, qtype: 1))
    }

    func testRejectsEmptyName() {
        XCTAssertNil(resolver.buildDNSQuery(domain: "", qtype: 1))
        XCTAssertNil(resolver.buildDNSQuery(domain: "...", qtype: 1))
    }
}
