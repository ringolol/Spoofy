import XCTest
@testable import SpoofyCore

/// Characterization of `AppSettings.matchesPatterns`, the current domain matcher.
/// Rows that encode a known bug are expected failures tagged with the finding ID.
final class DomainMatcherTests: XCTestCase {
    private func matches(_ host: String, _ pattern: String) -> Bool {
        AppSettings.matchesPatterns(host: host, patterns: [pattern])
    }

    func testExactPattern() {
        XCTAssertTrue(matches("example.com", "example.com"))
        XCTAssertTrue(matches("EXAMPLE.com", "example.COM"))
        XCTAssertFalse(matches("www.example.com", "example.com"))
        XCTAssertFalse(matches("example.com.evil", "example.com"))
    }

    func testLeadingWildcardMatchesApexAndSubdomains() {
        XCTAssertTrue(matches("example.com", "*.example.com"))
        XCTAssertTrue(matches("www.example.com", "*.example.com"))
        XCTAssertTrue(matches("a.b.example.com", "*.example.com"))
        XCTAssertFalse(matches("badexample.com", "*.example.com"))
        XCTAssertFalse(matches("example.com.evil", "*.example.com"))
    }

    func testTrailingWildcardMatchesAnyTLD() {
        XCTAssertTrue(matches("example.com", "example.*"))
        XCTAssertTrue(matches("example.co.uk", "example.*"))
        XCTAssertTrue(matches("example", "example.*"))
        XCTAssertFalse(matches("examples.com", "example.*"))
        XCTAssertFalse(matches("www.example.com", "example.*"))
    }

    func testBothWildcards() {
        XCTAssertTrue(matches("google.com", "*.google.*"))
        XCTAssertTrue(matches("www.google.co.uk", "*.google.*"))
    }

    // U3: `*.x.*` is a substring test, so it matches unrelated hosts.
    func testBothWildcardsAreLabelAware() {
        XCTExpectFailure("U3: *.google.* matches by substring")
        XCTAssertFalse(matches("notgoogle.community.org", "*.google.*"))
    }

    func testDegeneratePatternsMatchNothing() {
        XCTAssertFalse(AppSettings.matchesPatterns(host: "example.com", patterns: []))
        XCTAssertFalse(matches("example.com", ""))
        XCTAssertFalse(matches("example.com", "*"))
    }

    func testAnyPatternInListMatches() {
        XCTAssertTrue(AppSettings.matchesPatterns(host: "b.org", patterns: ["a.org", "*.b.org"]))
    }
}
