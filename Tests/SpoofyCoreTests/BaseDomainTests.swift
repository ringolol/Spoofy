import XCTest
@testable import SpoofyCore

final class BaseDomainTests: XCTestCase {
    func testLastTwoLabels() {
        XCTAssertEqual(BaseDomain.of("www.example.com"), "example.com")
        XCTAssertEqual(BaseDomain.of("a.b.c.Example.COM."), "example.com")
        XCTAssertEqual(BaseDomain.of("example.com"), "example.com")
    }

    func testKnownTwoLevelSuffixes() {
        XCTAssertEqual(BaseDomain.of("news.bbc.co.uk"), "bbc.co.uk")
        XCTAssertEqual(BaseDomain.of("shop.msk.ru"), "shop.msk.ru")
        XCTAssertNil(BaseDomain.of("co.uk"))
    }

    func testIPsAndSingleLabels() {
        XCTAssertNil(BaseDomain.of("192.168.1.1"))
        XCTAssertNil(BaseDomain.of("2606:4700::1111"))
        XCTAssertNil(BaseDomain.of("localhost"))
    }

    func testSuggestedWildcard() {
        XCTAssertEqual(BaseDomain.suggestWildcard(for: "i.ytimg.com"), "*.ytimg.com")
        XCTAssertNil(BaseDomain.suggestWildcard(for: "1.2.3.4"))
    }
}
