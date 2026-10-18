import XCTest
@testable import SpoofyCore

final class AddPatternsPlanTests: XCTestCase {
    private typealias Plan = AddPatternsPlan

    // MARK: - Patterns

    func testWildcardByDefaultExceptForIPs() {
        XCTAssertTrue(Plan.canWildcard("rr3.googlevideo.com"))
        XCTAssertFalse(Plan.canWildcard("1.2.3.4"))
        XCTAssertFalse(Plan.canWildcard("2001:db8::1"))
        XCTAssertEqual(Plan.pattern(for: "rr3.googlevideo.com", wildcard: true), "*.googlevideo.com")
        XCTAssertEqual(Plan.pattern(for: "rr3.googlevideo.com", wildcard: false), "rr3.googlevideo.com")
        XCTAssertEqual(Plan.pattern(for: "1.2.3.4", wildcard: true), "1.2.3.4")
    }

    func testEntriesAreDedupedByPattern() {
        let entries = Plan.entries(hosts: ["a.youtube.com", "b.youtube.com", "youtu.be", "1.2.3.4"],
                                   wildcard: ["a.youtube.com": true, "b.youtube.com": true, "youtu.be": false])
        XCTAssertEqual(entries.map(\.pattern), ["*.youtube.com", "youtu.be", "1.2.3.4"])
        XCTAssertEqual(entries.first?.hosts, ["a.youtube.com", "b.youtube.com"])
    }

    func testDefaultNameIsTheBaseDomain() {
        XCTAssertEqual(Plan.defaultName(hosts: ["rr3.googlevideo.com", "x.com"]), "googlevideo.com")
        XCTAssertEqual(Plan.defaultName(hosts: ["1.2.3.4"]), "1.2.3.4")
        XCTAssertEqual(Plan.defaultName(hosts: []), "")
    }

    // MARK: - Suggested route

    func testSuggestionFollowsTheDominantKind() {
        let sni = Plan.suggestion(kinds: [.sni, .sni, .dns], payloads: [.tls], masterHasOutline: false)
        XCTAssertEqual(sni, .init(routeMode: .split, splitMode: .sni, dohEnabled: false, note: nil))
        XCTAssertEqual(Plan.suggestion(kinds: [.injected], payloads: [.tls], masterHasOutline: false).splitMode, .sni)
        XCTAssertEqual(Plan.suggestion(kinds: [.dns], payloads: [.tls], masterHasOutline: true),
                       .init(routeMode: .split, splitMode: .none, dohEnabled: true, note: nil))
        XCTAssertEqual(Plan.suggestion(kinds: [], payloads: [.tls], masterHasOutline: true),
                       .init(routeMode: .split, splitMode: .sni, dohEnabled: false, note: nil))
    }

    func testIPAndFreezeWantVPN() {
        for kind in [BlockKind.ip, .freeze, .whitelist] {
            XCTAssertEqual(Plan.suggestion(kinds: [kind], payloads: [.tls], masterHasOutline: true).routeMode, .vpn)
            XCTAssertEqual(Plan.suggestion(kinds: [kind], payloads: [.tls], masterHasOutline: false),
                           .init(routeMode: .split, splitMode: .sni, dohEnabled: false, note: .ipNeedsVPN))
        }
        XCTAssertEqual(Plan.suggestion(kinds: [.httpBlockPage], payloads: [.http], masterHasOutline: true).routeMode, .vpn)
        XCTAssertEqual(Plan.suggestion(kinds: [.httpBlockPage], payloads: [.http], masterHasOutline: false),
                       .init(routeMode: .split, splitMode: .none, dohEnabled: true, note: nil))
    }

    func testNonTLSHostsGetVPNOrANote() {
        XCTAssertEqual(Plan.suggestion(kinds: [.sni], payloads: [.ssh], masterHasOutline: true).routeMode, .vpn)
        XCTAssertEqual(Plan.suggestion(kinds: [], payloads: [.ssh, .tcp], masterHasOutline: false),
                       .init(routeMode: .split, splitMode: .none, dohEnabled: false, note: .splitOnlyChangesTLS))
        XCTAssertEqual(Plan.suggestion(kinds: [.sni], payloads: [.ssh, .tls], masterHasOutline: false).splitMode, .sni,
                       "any TLS host gets the TLS rules")
    }

    // MARK: - Warnings

    private let master = SpoofProfile.makeDefault()

    private func custom(_ name: String, _ patterns: [String], enabled: Bool = true) -> SpoofProfile {
        var profile = SpoofProfile.makeCustom(name: name, domainPatterns: patterns, splitMode: .sni)
        profile.isEnabled = enabled
        return profile
    }

    func testPatternsAlreadyInTheTargetAreSkipped() {
        let youtube = custom("YouTube", ["*.YouTube.com"])
        let warnings = Plan.warnings(entries: Plan.entries(hosts: ["www.youtube.com", "i.ytimg.com"], wildcard: [:]),
                                     target: youtube, isNew: false, profiles: [youtube, master])
        XCTAssertEqual(warnings, [.alreadyInTarget("*.youtube.com")])
    }

    func testAnEarlierProfileStillWins() {
        let google = custom("Google", ["*.google.*", "*.googlevideo.com"])
        let youtube = custom("YouTube", [])
        let entries = Plan.entries(hosts: ["rr3.googlevideo.com", "www.youtube.com"], wildcard: [:])
        XCTAssertEqual(Plan.warnings(entries: entries, target: youtube, isNew: false, profiles: [google, youtube, master]),
                       [.shadowed(host: "rr3.googlevideo.com", by: "Google")])
        XCTAssertEqual(Plan.warnings(entries: entries, target: youtube, isNew: false, profiles: [youtube, google, master]), [],
                       "above the other profile it wins")
        let draft = custom("New", [])
        XCTAssertEqual(Plan.warnings(entries: entries, target: draft, isNew: true, profiles: [google, master]),
                       [.shadowed(host: "rr3.googlevideo.com", by: "Google")], "a new profile goes last, before Master")
    }

    func testADisabledTargetSaysSo() {
        let off = custom("Off", [], enabled: false)
        let warnings = Plan.warnings(entries: Plan.entries(hosts: ["a.com"], wildcard: [:]), target: off, isNew: false,
                                     profiles: [off, master])
        XCTAssertEqual(warnings, [.targetDisabled])
    }

    func testSimulatedProfiles() {
        let youtube = custom("YouTube", ["*.youtube.com"])
        let entries = Plan.entries(hosts: ["i.ytimg.com", "www.youtube.com"], wildcard: [:])
        let existing = Plan.simulated(entries: entries, target: youtube, isNew: false, profiles: [youtube, master])
        XCTAssertEqual(existing.first?.domainPatterns, ["*.youtube.com", "*.ytimg.com"])
        let draft = custom("New", [])
        let added = Plan.simulated(entries: entries, target: draft, isNew: true, profiles: [youtube, master])
        XCTAssertEqual(added.map(\.name), ["YouTube", "New", "Master"])
        XCTAssertEqual(added[1].domainPatterns, ["*.ytimg.com", "*.youtube.com"])
    }
}
