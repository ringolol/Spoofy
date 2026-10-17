import XCTest
@testable import SpoofyCore

/// `DomainMatcher` (plan §6.6). The first group keeps the characterization of the pre-4e
/// `AppSettings.matchesPatterns` that users rely on; the rest is the new label-aware semantics.
final class DomainMatcherTests: XCTestCase {
    private func matches(_ host: String, _ pattern: String) -> Bool {
        DomainMatcher(patterns: [pattern]).matches(host)
    }

    // MARK: - Kept from the old matcher

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
        XCTAssertTrue(matches("google", "*.google.*"))
    }

    func testDegeneratePatternsMatchNothing() {
        XCTAssertFalse(DomainMatcher(patterns: []).matches("example.com"))
        XCTAssertFalse(matches("example.com", ""))
        XCTAssertFalse(matches("example.com", "*"))
        XCTAssertTrue(DomainMatcher(patterns: ["", "*", "  "]).isEmpty)
    }

    func testAnyPatternInListMatches() {
        XCTAssertTrue(DomainMatcher(patterns: ["a.org", "*.b.org"]).matches("b.org"))
    }

    // MARK: - New semantics

    /// U3: the middle of `*.x.*` is a whole label, not a substring.
    func testBothWildcardsAreLabelAware() {
        XCTAssertFalse(matches("notgoogle.community.org", "*.google.*"))
        XCTAssertFalse(matches("googles.com", "*.google.*"))
        XCTAssertFalse(matches("www.go.ogle.com", "*.google.*"))
    }

    func testMultiLabelMiddle() {
        XCTAssertTrue(matches("r1.youtube.googleapis.com", "*.youtube.googleapis.*"))
        XCTAssertTrue(matches("youtube.googleapis.com", "*.youtube.googleapis.*"))
        XCTAssertFalse(matches("youtube.com.googleapis.com", "*.youtube.googleapis.*"))
    }

    /// The old matcher matched nothing here (`contains("")` is false); every host is the only
    /// useful reading of "anything dot anything".
    func testStarDotStarMatchesEveryHost() {
        XCTAssertTrue(matches("example.com", "*.*"))
        XCTAssertTrue(matches("localhost", "*.*"))
        XCTAssertTrue(matches("1.2.3.4", "*.*"))
        XCTAssertFalse(DomainMatcher(patterns: ["*.*"]).isEmpty)
    }

    /// IP literals are matched by their dotted labels, so a prefix covers a range.
    func testIPv4Prefix() {
        XCTAssertTrue(matches("149.154.167.51", "149.154.*"))
        XCTAssertFalse(matches("149.15.167.51", "149.154.*"))
    }

    func testTrailingDotsAndWhitespaceAreIgnored() {
        XCTAssertTrue(matches("example.com.", "example.com"))
        XCTAssertTrue(matches("www.example.com", " *.example.com. "))
        XCTAssertTrue(matches("Example.COM..", "example.com"))
    }

    func testEmptyLabelsMakeAPatternInvalid() {
        XCTAssertFalse(matches("example.com", ".example.com"))
        XCTAssertFalse(matches("example.com", "example..com"))
        XCTAssertFalse(matches("a.example.com", "*..example.com"))
        XCTAssertFalse(matches("example..com", "example..com"), "an invalid pattern matches nothing, even itself")
    }

    func testWildcardInsideALabelIsLiteral() {
        XCTAssertFalse(matches("www.example.com", "w*.example.com"))
        XCTAssertFalse(matches("a.example.com", "a.*.com"))
    }
}
