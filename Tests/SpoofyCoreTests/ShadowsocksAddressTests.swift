import XCTest
@testable import SpoofyCore

final class ShadowsocksAddressTests: XCTestCase {
    func testIPv4() {
        XCTAssertEqual(ShadowsocksAEADCodec.addressHeader(host: "1.2.3.4", port: 443).map(Array.init),
                       [0x01, 1, 2, 3, 4, 0x01, 0xbb])
    }

    func testIPv6() {
        XCTAssertEqual(ShadowsocksAEADCodec.addressHeader(host: "::1", port: 80).map(Array.init),
                       [0x04] + [UInt8](repeating: 0, count: 15) + [1, 0x00, 0x50])
    }

    func testDomain() {
        XCTAssertEqual(ShadowsocksAEADCodec.addressHeader(host: "a.io", port: 8080).map(Array.init),
                       [0x03, 4, 0x61, 0x2e, 0x69, 0x6f, 0x1f, 0x90])
    }

    // C3 regression: the length byte used to go through UInt8(count), which traps above 255.
    func testDomainLengthLimits() {
        XCTAssertNotNil(ShadowsocksAEADCodec.addressHeader(host: String(repeating: "a", count: 255), port: 443))
        XCTAssertNil(ShadowsocksAEADCodec.addressHeader(host: String(repeating: "a", count: 256), port: 443))
        XCTAssertNil(ShadowsocksAEADCodec.addressHeader(host: "", port: 443))
    }
}
