import XCTest
@testable import SpoofyCore

/// Host → profile through `ProxyConfig`.
final class ProfileMatchingTests: XCTestCase {
    private func custom(_ name: String, patterns: [String], enabled: Bool = true) -> SpoofProfile {
        var profile = SpoofProfile.makeDefault()
        profile.id = UUID()
        profile.name = name
        profile.isDefault = false
        profile.isEnabled = enabled
        profile.domainPatterns = patterns
        return profile
    }

    private func config(_ profiles: [SpoofProfile]) -> ProxyConfig {
        ProxyConfig(profiles: profiles, port: 8090, allowLANAccess: false)
    }

    // U1 regression: an enabled profile with no patterns used to match every host.
    func testEmptyCustomProfileMatchesNothing() {
        let master = SpoofProfile.makeDefault()
        let config = config([custom("new", patterns: []), master])
        XCTAssertEqual(config.profile(for: "example.com").id, master.id)
        XCTAssertTrue(config.rules.isEmpty)
    }

    func testFirstMatchingEnabledProfileWins() {
        let master = SpoofProfile.makeDefault()
        let disabled = custom("disabled", patterns: ["example.com"], enabled: false)
        let first = custom("first", patterns: ["*.example.com"])
        let second = custom("second", patterns: ["example.com"])
        let config = config([disabled, first, second, master])
        XCTAssertEqual(config.profile(for: "example.com").id, first.id)
        XCTAssertEqual(config.profile(for: "other.org").id, master.id)
    }

    // U2: the fallback is Master by identity, not whichever profile is last.
    func testFallbackIsMasterRegardlessOfPosition() {
        let master = SpoofProfile.makeDefault()
        let config = config([master, custom("last", patterns: ["x.com"])])
        XCTAssertEqual(config.profile(for: "other.org").id, master.id)
    }

    func testMissingMasterFallsBackToDefaults() {
        let config = config([custom("only", patterns: ["x.com"])])
        XCTAssertTrue(config.master.isDefault)
        XCTAssertTrue(config.profile(for: "other.org").isDefault)
    }

    func testInheritanceIsAppliedToRules() {
        var master = SpoofProfile.makeDefault()
        master.dohServerURL = "https://dns.example/dns-query"
        master.outlineConfig = OutlineServerConfig(host: "m", port: 1, password: "p", cipher: .aes256Gcm, prefix: nil)
        var inheriting = custom("inheriting", patterns: ["a.com"])
        inheriting.inheritDoH = true
        inheriting.inheritOutlineConfig = true
        var own = custom("own", patterns: ["b.com"])
        own.dohServerURL = "https://own.example/dns-query"

        let config = config([inheriting, own, master])
        XCTAssertEqual(config.profile(for: "a.com").dohServerURL, master.dohServerURL)
        XCTAssertEqual(config.profile(for: "a.com").outlineConfig, master.outlineConfig)
        XCTAssertEqual(config.profile(for: "b.com").dohServerURL, "https://own.example/dns-query")
        XCTAssertNil(config.profile(for: "b.com").outlineConfig)
    }
}
