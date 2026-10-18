import XCTest
@testable import SpoofyCore

final class AddPatternsPlanTests: XCTestCase {
    private typealias Plan = AddPatternsPlan

    // MARK: - Patterns

    func testSuggestionsAreTheHostThenTheSite() {
        XCTAssertEqual(Plan.suggestions(for: "test.example.com"), ["*.test.example.com", "*.example.com"])
        XCTAssertEqual(Plan.suggestions(for: "Rr3.GoogleVideo.com"), ["*.rr3.googlevideo.com", "*.googlevideo.com"])
        XCTAssertEqual(Plan.suggestions(for: "example.com"), ["*.example.com"], "the host is the site")
        XCTAssertEqual(Plan.suggestions(for: "www.youtube.com"), ["*.youtube.com"], "www. adds nothing")
        XCTAssertEqual(Plan.suggestions(for: "a.bbc.co.uk"), ["*.a.bbc.co.uk", "*.bbc.co.uk"])
        XCTAssertEqual(Plan.suggestions(for: "1.2.3.4"), ["1.2.3.4"], "IPs stay exact")
        XCTAssertEqual(Plan.suggestions(for: "2001:db8::1"), ["2001:db8::1"])
        XCTAssertEqual(Plan.suggestions(for: "localhost"), ["localhost"])
    }

    func testCheckingAnEditedPattern() {
        XCTAssertEqual(Plan.check("*.test.example.com", host: "test.example.com"), .wider)
        XCTAssertEqual(Plan.check("*.example.com", host: "test.example.com"), .wider)
        XCTAssertEqual(Plan.check(" Test.Example.com ", host: "test.example.com"), .exact)
        XCTAssertEqual(Plan.check("1.2.3.4", host: "1.2.3.4"), .exact)
        XCTAssertEqual(Plan.check("*.exmaple.com", host: "test.example.com"), .noMatch)
        XCTAssertEqual(Plan.check("", host: "a.com"), .invalid)
        XCTAssertEqual(Plan.check("*", host: "a.com"), .invalid)
        XCTAssertEqual(Plan.check(".example.com", host: "a.example.com"), .invalid)
    }

    func testEntriesUseTheEditedPatternsAndMerge() {
        let entries = Plan.entries(hosts: ["a.youtube.com", "b.youtube.com", "youtu.be", "1.2.3.4", "bad.com"],
                                   patterns: ["a.youtube.com": "*.youtube.com", "b.youtube.com": " *.YouTube.com ",
                                              "youtu.be": "youtu.be", "bad.com": "*"])
        XCTAssertEqual(entries.map(\.pattern), ["*.youtube.com", "youtu.be", "1.2.3.4"], "invalid patterns are left out")
        XCTAssertEqual(entries.first?.hosts, ["a.youtube.com", "b.youtube.com"])
        XCTAssertEqual(Plan.entries(hosts: ["test.example.com"], patterns: [:]).map(\.pattern), ["*.test.example.com"],
                       "the first suggestion by default")
    }

    func testDefaultNameIsTheBaseDomain() {
        XCTAssertEqual(Plan.defaultName(hosts: ["rr3.googlevideo.com", "x.com"]), "googlevideo.com")
        XCTAssertEqual(Plan.defaultName(hosts: ["1.2.3.4"]), "1.2.3.4")
        XCTAssertEqual(Plan.defaultName(hosts: []), "")
    }

    // MARK: - Suggested route

    func testSuggestionFollowsTheDominantKind() {
        let sni = Plan.suggestion(kinds: [.sni, .sni, .dns], payloads: [.tls], masterHasOutline: false)
        XCTAssertEqual(sni, .init(routeMode: .split, splitMode: .sni, dohEnabled: false, note: nil, reason: .blocked(.sni)))
        XCTAssertEqual(Plan.suggestion(kinds: [.injected], payloads: [.tls], masterHasOutline: false).splitMode, .sni)
        XCTAssertEqual(Plan.suggestion(kinds: [.dns], payloads: [.tls], masterHasOutline: true),
                       .init(routeMode: .split, splitMode: .none, dohEnabled: true, note: nil, reason: .blocked(.dns)))
        XCTAssertEqual(Plan.suggestion(kinds: [], payloads: [.tls], masterHasOutline: true),
                       .init(routeMode: .split, splitMode: .sni, dohEnabled: false, note: nil, reason: .noEvidence),
                       "no block seen: a default, not a recommendation")
    }

    func testIPAndFreezeWantVPN() {
        for kind in [BlockKind.ip, .freeze, .whitelist] {
            XCTAssertEqual(Plan.suggestion(kinds: [kind], payloads: [.tls], masterHasOutline: true).routeMode, .vpn)
            XCTAssertEqual(Plan.suggestion(kinds: [kind], payloads: [.tls], masterHasOutline: false),
                           .init(routeMode: .split, splitMode: .sni, dohEnabled: false, note: .ipNeedsVPN, reason: .blocked(kind)))
        }
        XCTAssertEqual(Plan.suggestion(kinds: [.httpBlockPage], payloads: [.http], masterHasOutline: true).routeMode, .vpn)
        XCTAssertEqual(Plan.suggestion(kinds: [.httpBlockPage], payloads: [.http], masterHasOutline: false),
                       .init(routeMode: .split, splitMode: .none, dohEnabled: true, note: nil, reason: .blocked(.httpBlockPage)))
    }

    func testNonTLSHostsGetVPNOrANote() {
        XCTAssertEqual(Plan.suggestion(kinds: [.sni], payloads: [.ssh], masterHasOutline: true).routeMode, .vpn)
        XCTAssertEqual(Plan.suggestion(kinds: [], payloads: [.ssh, .tcp], masterHasOutline: false),
                       .init(routeMode: .split, splitMode: .none, dohEnabled: false, note: .splitOnlyChangesTLS, reason: .nonTLS))
        XCTAssertEqual(Plan.suggestion(kinds: [.sni], payloads: [.ssh], masterHasOutline: true).reason, .nonTLS)
        XCTAssertEqual(Plan.suggestion(kinds: [.sni], payloads: [.ssh, .tls], masterHasOutline: false).splitMode, .sni,
                       "any TLS host gets the TLS rules")
    }

    func testSuggestionMatchesAProfileOnItsRouteSettingsOnly() {
        let suggestion = Plan.suggestion(kinds: [.dns], payloads: [.tls], masterHasOutline: false)
        var profile = SpoofProfile.makeCustom(name: "x", domainPatterns: [], routeMode: .split, splitMode: .none, dohEnabled: true)
        XCTAssertTrue(suggestion.matches(profile))
        profile.name = "renamed"
        profile.domainPatterns = ["*.x.com"]
        XCTAssertTrue(suggestion.matches(profile), "name and patterns aren't part of it")
        profile.dohEnabled = false
        XCTAssertFalse(suggestion.matches(profile))

        let vpn = Plan.suggestion(kinds: [.ip], payloads: [.tls], masterHasOutline: true)
        profile = .makeCustom(name: "x", domainPatterns: [], routeMode: .vpn, splitMode: .chunk, dohEnabled: false)
        XCTAssertTrue(vpn.matches(profile), "split mode doesn't apply to VPN")
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
        let warnings = Plan.warnings(entries: Plan.entries(hosts: ["www.youtube.com", "i.ytimg.com"], patterns: ["i.ytimg.com": "*.ytimg.com"]),
                                     target: youtube, isNew: false, profiles: [youtube, master])
        XCTAssertEqual(warnings, [.alreadyInTarget("*.youtube.com")])
    }

    func testAnEarlierProfileStillWins() {
        let google = custom("Google", ["*.google.*", "*.googlevideo.com"])
        let youtube = custom("YouTube", [])
        let entries = Plan.entries(hosts: ["rr3.googlevideo.com", "www.youtube.com"], patterns: ["rr3.googlevideo.com": "*.googlevideo.com"])
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
        let warnings = Plan.warnings(entries: Plan.entries(hosts: ["a.com"], patterns: [:]), target: off, isNew: false,
                                     profiles: [off, master])
        XCTAssertEqual(warnings, [.targetDisabled])
    }

    func testSimulatedProfiles() {
        let youtube = custom("YouTube", ["*.youtube.com"])
        let entries = Plan.entries(hosts: ["i.ytimg.com", "www.youtube.com"], patterns: ["i.ytimg.com": "*.ytimg.com"])
        let existing = Plan.simulated(entries: entries, target: youtube, isNew: false, profiles: [youtube, master])
        XCTAssertEqual(existing.first?.domainPatterns, ["*.youtube.com", "*.ytimg.com"])
        let draft = custom("New", [])
        let added = Plan.simulated(entries: entries, target: draft, isNew: true, profiles: [youtube, master])
        XCTAssertEqual(added.map(\.name), ["YouTube", "New", "Master"])
        XCTAssertEqual(added[1].domainPatterns, ["*.ytimg.com", "*.youtube.com"])
    }
}
