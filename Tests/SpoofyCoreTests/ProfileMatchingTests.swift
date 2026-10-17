import XCTest
@testable import SpoofyCore

final class ProfileMatchingTests: XCTestCase {
    private var suiteName: String!
    private var settings: AppSettings!

    override func setUp() {
        suiteName = "SpoofyTests.\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suiteName)!)
    }

    override func tearDown() {
        UserDefaults().removePersistentDomain(forName: suiteName)
    }

    private func custom(_ name: String, patterns: [String], enabled: Bool = true) -> SpoofProfile {
        var profile = SpoofProfile.makeDefault()
        profile.id = UUID()
        profile.name = name
        profile.isDefault = false
        profile.isEnabled = enabled
        profile.domainPatterns = patterns
        return profile
    }

    // U1 regression: an enabled profile with no patterns used to match every host.
    func testEmptyCustomProfileMatchesNothing() {
        let master = SpoofProfile.makeDefault()
        settings.profiles = [custom("new", patterns: []), master]
        XCTAssertEqual(settings.matchingProfile(for: "example.com").id, master.id)
    }

    func testFirstMatchingEnabledProfileWins() {
        let master = SpoofProfile.makeDefault()
        let disabled = custom("disabled", patterns: ["example.com"], enabled: false)
        let first = custom("first", patterns: ["*.example.com"])
        let second = custom("second", patterns: ["example.com"])
        settings.profiles = [disabled, first, second, master]
        XCTAssertEqual(settings.matchingProfile(for: "example.com").id, first.id)
        XCTAssertEqual(settings.matchingProfile(for: "other.org").id, master.id)
    }

    // U2: the fallback is Master by identity, not whichever profile is last.
    func testFallbackIsMasterRegardlessOfPosition() {
        let master = SpoofProfile.makeDefault()
        settings.profiles = [master, custom("last", patterns: ["x.com"])]
        XCTAssertEqual(settings.matchingProfile(for: "other.org").id, master.id)
    }

    // U6: a VPN route without a config is detectable so handlers can reject it.
    func testVPNMissingConfig() {
        var profile = SpoofProfile.makeDefault()
        XCTAssertFalse(profile.isVPNMissingConfig)
        profile.routeMode = .vpn
        XCTAssertTrue(profile.isVPNMissingConfig)
        profile.outlineConfig = OutlineServerConfig(host: "h", port: 1, password: "p", cipher: .aes256Gcm, prefix: nil)
        XCTAssertFalse(profile.isVPNMissingConfig)
    }

    func testInheritedVPNConfigComesFromMaster() {
        var master = SpoofProfile.makeDefault()
        master.outlineConfig = OutlineServerConfig(host: "h", port: 1, password: "p", cipher: .aes256Gcm, prefix: nil)
        var vpn = custom("vpn", patterns: ["example.com"])
        vpn.routeMode = .vpn
        vpn.inheritOutlineConfig = true
        settings.profiles = [vpn, master]
        XCTAssertFalse(settings.matchingProfile(for: "example.com").isVPNMissingConfig)
    }
}
