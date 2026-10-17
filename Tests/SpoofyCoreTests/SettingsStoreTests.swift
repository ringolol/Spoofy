import XCTest
@testable import SpoofyCore

@MainActor
final class SettingsStoreTests: XCTestCase {
    private var suiteName: String!
    private var defaults: UserDefaults!
    private var store: SettingsStore!

    override func setUp() async throws {
        suiteName = "SpoofyTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)!
        store = SettingsStore(defaults: defaults)
    }

    override func tearDown() async throws {
        UserDefaults().removePersistentDomain(forName: suiteName)
    }

    private func custom(_ name: String = "custom", patterns: [String] = ["*.example.com"]) -> SpoofProfile {
        var profile = SpoofProfile.makeDefault()
        profile.id = UUID()
        profile.name = name
        profile.isDefault = false
        profile.domainPatterns = patterns
        return profile
    }

    private func json(_ profiles: [SpoofProfile], port: UInt16 = 8090) throws -> String {
        String(decoding: try JSONEncoder().encode(
            ExportedSettings(profiles: profiles, proxyPort: port, allowLANAccess: false)), as: UTF8.self)
    }

    private func importIssues(_ json: String) -> [ProfileValidator.Issue] {
        do {
            try store.importJSON(json)
            return []
        } catch SettingsStore.ImportError.invalid(let issues) {
            return issues
        } catch {
            XCTFail("unexpected \(error)")
            return []
        }
    }

    // MARK: - Load

    func testFreshInstallDefaults() {
        XCTAssertEqual(store.proxyPort, 8090)
        XCTAssertFalse(store.allowLANAccess)
        XCTAssertEqual(store.profiles.count, 1)
        XCTAssertTrue(store.profiles[0].isDefault)
        XCTAssertNil(store.loadError)
        XCTAssertNil(defaults.data(forKey: SettingsStore.Key.profiles), "nothing is written until a change")
    }

    func testProfilesRoundTrip() {
        var profile = store.addProfile()
        profile.domainPatterns = ["*.example.com"]
        profile.outlineConfig = OutlineServerConfig(host: "h", port: 1, password: "p", cipher: .aes256Gcm, prefix: Data([0x16]))
        store.update(profile)

        let reloaded = SettingsStore(defaults: defaults)
        XCTAssertEqual(reloaded.profiles, store.profiles)
        XCTAssertEqual(reloaded.profiles[0].outlineConfig?.prefix, Data([0x16]))
    }

    /// Data written by the pre-4e `AppSettings`: same key, same JSON, no `inherit*` fields in
    /// older versions.
    func testReadsTheOldFormat() throws {
        let master = SpoofProfile.makeDefault()
        let old = """
        [{"id":"\(UUID().uuidString)","name":"old","isEnabled":true,"domainPatterns":["*.youtube.*"],
          "splitMode":"sni","chunkSize":5,"tlsRecordFragmentation":true,"dohEnabled":false,
          "dohServerURL":"https://1.1.1.1/dns-query","isDefault":false},
         \(String(decoding: try JSONEncoder().encode(master), as: UTF8.self))]
        """
        defaults.set(Data(old.utf8), forKey: SettingsStore.Key.profiles)
        defaults.set(9000, forKey: SettingsStore.Key.proxyPort)
        defaults.set(true, forKey: SettingsStore.Key.allowLANAccess)

        let store = SettingsStore(defaults: defaults)
        XCTAssertNil(store.loadError)
        XCTAssertEqual(store.profiles.map(\.name), ["old", "Master"])
        XCTAssertEqual(store.profiles[0].routeMode, .split)
        XCTAssertFalse(store.profiles[0].inheritDoH)
        XCTAssertEqual(store.master.id, master.id)
        XCTAssertEqual(store.proxyPort, 9000)
        XCTAssertTrue(store.allowLANAccess)
    }

    // U4: an undecodable blob is kept, and defaults are used in memory only.
    func testCorruptedProfilesBlobIsPreserved() {
        let garbage = Data("{corrupted".utf8)
        defaults.set(garbage, forKey: SettingsStore.Key.profiles)
        let store = SettingsStore(defaults: defaults, now: { Date(timeIntervalSince1970: 1_700_000_000) })

        XCTAssertEqual(store.profiles.count, 1)
        XCTAssertTrue(store.profiles[0].isDefault)
        XCTAssertNotNil(store.loadError)
        XCTAssertEqual(store.backupKey, "spoofProfiles.backup.1700000000")
        XCTAssertEqual(defaults.data(forKey: "spoofProfiles.backup.1700000000"), garbage)
        XCTAssertEqual(defaults.data(forKey: SettingsStore.Key.profiles), garbage, "not overwritten on load")

        // The first change writes the new profiles; the backup stays.
        store.addProfile()
        XCTAssertNil(store.loadError)
        XCTAssertNotEqual(defaults.data(forKey: SettingsStore.Key.profiles), garbage)
        XCTAssertEqual(defaults.data(forKey: "spoofProfiles.backup.1700000000"), garbage)
    }

    func testStoredDataWithoutMasterGetsOne() throws {
        let only = custom("only")
        defaults.set(try JSONEncoder().encode([only]), forKey: SettingsStore.Key.profiles)
        let store = SettingsStore(defaults: defaults)
        XCTAssertEqual(store.profiles.map(\.id).first, only.id)
        XCTAssertEqual(store.profiles.filter(\.isDefault).count, 1)
        XCTAssertTrue(store.profiles.last!.isDefault)
    }

    func testSeveralMastersKeepTheFirst() throws {
        let first = SpoofProfile.makeDefault()
        let second = SpoofProfile.makeDefault()
        defaults.set(try JSONEncoder().encode([first, second]), forKey: SettingsStore.Key.profiles)
        let store = SettingsStore(defaults: defaults)
        XCTAssertEqual(store.master.id, first.id)
        XCTAssertEqual(store.profiles.map(\.id), [second.id, first.id])
    }

    // M4: an out-of-range stored port falls back instead of trapping.
    func testOutOfRangePortFallsBack() {
        for bad in [70000, -1, 0] {
            defaults.set(bad, forKey: SettingsStore.Key.proxyPort)
            XCTAssertEqual(SettingsStore(defaults: defaults).proxyPort, 8090, "\(bad)")
        }
    }

    // MARK: - Mutations

    func testMutationsAreWrittenAndReported() {
        var changes = 0
        store.onChange = { changes += 1 }
        let a = store.addProfile()
        let b = store.addProfile()
        XCTAssertEqual(store.profiles.map(\.id), [a.id, b.id, store.master.id], "new profiles go before Master")

        store.moveCustomProfiles(from: [1], to: 0)
        XCTAssertEqual(store.customProfiles.map(\.id), [b.id, a.id])
        store.moveCustomProfiles(from: [0], to: 2)
        XCTAssertEqual(store.customProfiles.map(\.id), [a.id, b.id])

        store.deleteProfiles(ids: [a.id, store.master.id])
        XCTAssertEqual(store.profiles.map(\.id), [b.id, store.master.id], "Master is never deleted")

        store.setProxyPort(9001)
        store.setProxyPort(80)
        store.setAllowLANAccess(true)
        XCTAssertEqual(changes, 7, "an ignored port change is not reported")

        let reloaded = SettingsStore(defaults: defaults)
        XCTAssertEqual(reloaded.profiles.map(\.id), store.profiles.map(\.id))
        XCTAssertEqual(reloaded.proxyPort, 9001)
        XCTAssertTrue(reloaded.allowLANAccess)
    }

    func testUpdateKeepsMasterIdentity() {
        var master = store.master
        master.isDefault = false
        master.splitMode = .sni
        store.update(master)
        XCTAssertTrue(store.master.isDefault)
        XCTAssertEqual(store.master.splitMode, .sni)

        var promoted = store.addProfile()
        promoted.isDefault = true
        store.update(promoted)
        XCTAssertEqual(store.profiles.filter(\.isDefault).count, 1)
    }

    func testUnchangedUpdateIsNotReported() {
        var changes = 0
        store.onChange = { changes += 1 }
        store.update(store.master)
        XCTAssertEqual(changes, 0)
    }

    func testSnapshotReflectsTheStore() {
        var profile = store.addProfile()
        profile.domainPatterns = ["example.com"]
        profile.splitMode = .sni
        store.update(profile)
        store.setProxyPort(9002)

        let snapshot = store.snapshot
        XCTAssertEqual(snapshot.port, 9002)
        XCTAssertEqual(snapshot.profile(for: "example.com").id, profile.id)
        XCTAssertEqual(snapshot.profile(for: "other.org").id, store.master.id)
    }

    // MARK: - Export / import

    func testExportImportRoundTrip() throws {
        store.addProfile()
        store.setProxyPort(9000)
        store.setAllowLANAccess(true)
        let json = try XCTUnwrap(store.exportJSON())

        let otherSuite = suiteName + ".other"
        defer { UserDefaults().removePersistentDomain(forName: otherSuite) }
        let other = SettingsStore(defaults: UserDefaults(suiteName: otherSuite)!)
        try other.importJSON(json)
        XCTAssertEqual(other.proxyPort, 9000)
        XCTAssertTrue(other.allowLANAccess)
        XCTAssertEqual(other.profiles, store.profiles)
        XCTAssertEqual(SettingsStore(defaults: UserDefaults(suiteName: otherSuite)!).profiles, store.profiles)
    }

    func testImportRejectsGarbage() {
        XCTAssertThrowsError(try store.importJSON("not json"))
        XCTAssertThrowsError(try store.importJSON(#"{"profiles": []}"#))
    }

    // U5: import is validated, and a rejected import changes nothing.
    func testImportRejectsMissingMaster() throws {
        let before = store.profiles
        XCTAssertEqual(importIssues(try json([custom()])), [.masterCount(0)])
        XCTAssertEqual(store.profiles, before)
    }

    func testImportRejectsDuplicateIDs() throws {
        let master = SpoofProfile.makeDefault()
        var copy = master
        copy.isDefault = false
        XCTAssertEqual(importIssues(try json([copy, master])), [.duplicateID(master.id)])
    }

    func testImportRejectsBadValues() throws {
        var master = SpoofProfile.makeDefault()
        master.chunkSize = 0
        var doh = custom("doh")
        doh.dohEnabled = true
        doh.dohServerURL = "http://1.1.1.1/dns-query"
        var inheriting = custom("inheriting")
        inheriting.dohEnabled = true
        inheriting.inheritDoH = true
        inheriting.dohServerURL = "junk, but unused"

        XCTAssertEqual(importIssues(try json([doh, inheriting, master, SpoofProfile.makeDefault()], port: 80)), [
            .masterCount(2),
            .dohURL(profile: "doh", "http://1.1.1.1/dns-query"),
            .chunkSize(profile: "Master", 0),
            .port(80),
        ])
    }

    func testImportErrorDescribesEveryIssue() throws {
        do {
            try store.importJSON(try json([custom()], port: 80))
            XCTFail("import should fail")
        } catch {
            let message = error.localizedDescription
            XCTAssertTrue(message.contains("Master"), message)
            XCTAssertTrue(message.contains("Port 80"), message)
        }
    }
}
