import XCTest
@testable import SpoofyCore

final class SettingsStoreTests: XCTestCase {
    private var suiteName: String!
    private var defaults: UserDefaults!
    private var settings: AppSettings!

    override func setUp() {
        suiteName = "SpoofyTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)!
        settings = AppSettings(defaults: defaults)
    }

    override func tearDown() {
        UserDefaults().removePersistentDomain(forName: suiteName)
    }

    func testFreshInstallDefaults() {
        XCTAssertEqual(settings.proxyPort, 8090)
        XCTAssertFalse(settings.allowLANAccess)
        XCTAssertEqual(settings.profiles.count, 1)
        XCTAssertTrue(settings.profiles[0].isDefault)
    }

    func testProfilesRoundTrip() {
        var custom = SpoofProfile.makeDefault()
        custom.id = UUID()
        custom.isDefault = false
        custom.domainPatterns = ["*.example.com"]
        custom.outlineConfig = OutlineServerConfig(host: "h", port: 1, password: "p", cipher: .aes256Gcm, prefix: Data([0x16]))
        settings.profiles = [custom, .makeDefault()]
        XCTAssertEqual(AppSettings(defaults: defaults).profiles.map(\.id), settings.profiles.map(\.id))
        XCTAssertEqual(AppSettings(defaults: defaults).profiles[0].outlineConfig?.prefix, Data([0x16]))
    }

    func testExportImportRoundTrip() throws {
        settings.proxyPort = 9000
        settings.allowLANAccess = true
        let json = try XCTUnwrap(settings.exportJSON())

        let other = AppSettings(defaults: UserDefaults(suiteName: suiteName + ".other")!)
        defer { UserDefaults().removePersistentDomain(forName: suiteName + ".other") }
        try other.importJSON(json)
        XCTAssertEqual(other.proxyPort, 9000)
        XCTAssertTrue(other.allowLANAccess)
        XCTAssertEqual(other.profiles.map(\.id), settings.profiles.map(\.id))
    }

    func testImportRejectsGarbage() {
        XCTAssertThrowsError(try settings.importJSON("not json"))
        XCTAssertThrowsError(try settings.importJSON(#"{"profiles": []}"#))
    }

    // U4: an undecodable blob is replaced with defaults, losing the user's profiles.
    func testCorruptedProfilesBlobIsPreserved() {
        XCTExpectFailure("U4: corrupted profiles are overwritten with defaults")
        let garbage = Data("{corrupted".utf8)
        defaults.set(garbage, forKey: "spoofProfiles")
        _ = settings.profiles
        XCTAssertEqual(defaults.data(forKey: "spoofProfiles"), garbage)
    }

    // U5: import accepts a profile list without a Master profile.
    func testImportRejectsMissingMaster() throws {
        var custom = SpoofProfile.makeDefault()
        custom.isDefault = false
        let json = String(decoding: try JSONEncoder().encode(
            ExportedSettings(profiles: [custom], proxyPort: 8090, allowLANAccess: false)), as: UTF8.self)
        XCTExpectFailure("U5: import is not validated")
        XCTAssertThrowsError(try settings.importJSON(json))
    }

    // U5: import accepts duplicate profile IDs.
    func testImportRejectsDuplicateIDs() throws {
        let master = SpoofProfile.makeDefault()
        var copy = master
        copy.isDefault = false
        let json = String(decoding: try JSONEncoder().encode(
            ExportedSettings(profiles: [copy, master], proxyPort: 8090, allowLANAccess: false)), as: UTF8.self)
        XCTExpectFailure("U5: import is not validated")
        XCTAssertThrowsError(try settings.importJSON(json))
    }

    // M4: `UInt16(defaults.integer(...))` traps on out-of-range values. Enable after the fix.
    func testOutOfRangePortFallsBack() throws {
        try XCTSkipIf(true, "M4: out-of-range stored port traps")
        defaults.set(70000, forKey: "proxyPort")
        XCTAssertEqual(settings.proxyPort, 8090)
    }
}
