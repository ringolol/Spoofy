import Combine
import Foundation

/// The settings the UI reads and edits (plan §6.7). Profiles are decoded once at init (U4); every
/// mutation is written through to `UserDefaults` at once and reported via `onChange`, so a running
/// server can take the new `snapshot`.
///
/// Storage keeps the pre-4e keys and JSON shape, so existing installs need no migration.
@MainActor
final class SettingsStore: ObservableObject {
    static let defaultPort: UInt16 = 8090

    enum Key {
        static let profiles = "spoofProfiles"
        static let proxyPort = "proxyPort"
        static let allowLANAccess = "allowLANAccess"
        static let backupPrefix = "spoofProfiles.backup."
        static let scannerHiddenHosts = "scannerHiddenHosts"
    }

    @Published private(set) var profiles: [SpoofProfile]
    @Published private(set) var proxyPort: UInt16
    @Published private(set) var allowLANAccess: Bool
    /// `DomainMatcher` patterns the scanner leaves out (network-scanner plan §7.3). Not exported.
    @Published private(set) var hiddenHosts: [String]
    /// Set when the stored profiles could not be decoded. The original blob is kept under
    /// `backupKey` and is not overwritten until the user changes something.
    @Published private(set) var loadError: String?
    private(set) var backupKey: String?

    /// Called on the main actor after every change.
    var onChange: (() -> Void)?

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard, now: () -> Date = Date.init) {
        self.defaults = defaults

        var loaded = [SpoofProfile.makeDefault()]
        if let data = defaults.data(forKey: Key.profiles) {
            do {
                loaded = try JSONDecoder().decode([SpoofProfile].self, from: data)
            } catch {
                // U4: keep the user's data. Defaults are used in memory only.
                let key = Key.backupPrefix + String(Int(now().timeIntervalSince1970))
                defaults.set(data, forKey: key)
                backupKey = key
                loadError = "Saved profiles could not be read (\(error.localizedDescription)). A copy was kept; defaults are in use until you change something."
            }
        }
        profiles = Self.normalized(loaded)

        // M4: an out-of-range or missing port falls back instead of trapping.
        let storedPort = defaults.object(forKey: Key.proxyPort) as? Int
        proxyPort = storedPort.flatMap { UInt16(exactly: $0) }.flatMap { $0 == 0 ? nil : $0 } ?? Self.defaultPort
        allowLANAccess = defaults.bool(forKey: Key.allowLANAccess)
        hiddenHosts = defaults.stringArray(forKey: Key.scannerHiddenHosts) ?? []
    }

    var master: SpoofProfile { profiles.first { $0.isDefault } ?? .makeDefault() }
    var customProfiles: [SpoofProfile] { profiles.filter { !$0.isDefault } }

    /// What the network side needs, with inheritance applied and patterns compiled.
    var snapshot: ProxyConfig {
        ProxyConfig(profiles: profiles, port: proxyPort, allowLANAccess: allowLANAccess)
    }

    // MARK: - Mutations

    /// Replaces the profile with the same id. Master stays Master and a custom profile can't become it.
    func update(_ profile: SpoofProfile) {
        guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else { return }
        guard profiles[index] != profile else { return }
        var profile = profile
        profile.isDefault = profiles[index].isDefault
        profiles[index] = profile
        commitProfiles()
    }

    /// Adds an empty custom profile in front of Master and returns it.
    @discardableResult
    func addProfile() -> SpoofProfile {
        addProfile(.makeCustom(name: "", domainPatterns: []))
    }

    /// Adds `profile` in front of Master, always as a custom profile.
    @discardableResult
    func addProfile(_ profile: SpoofProfile) -> SpoofProfile {
        var profile = profile
        profile.isDefault = false
        profiles = customProfiles + [profile] + [master]
        commitProfiles()
        return profile
    }

    /// Appends the patterns the profile doesn't have yet (case-insensitive, blanks skipped) in
    /// one change. Returns how many were added.
    @discardableResult
    func addPatterns(_ patterns: [String], to id: UUID) -> Int {
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { return 0 }
        var seen = Set(profiles[index].domainPatterns.map { $0.lowercased() })
        let added = patterns
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && seen.insert($0.lowercased()).inserted }
        guard !added.isEmpty else { return 0 }
        profiles[index].domainPatterns += added
        commitProfiles()
        return added.count
    }

    /// Master is never deleted.
    func deleteProfiles(ids: Set<UUID>) {
        let kept = profiles.filter { $0.isDefault || !ids.contains($0.id) }
        guard kept.count != profiles.count else { return }
        profiles = kept
        commitProfiles()
    }

    /// Reorders custom profiles with `List.onMove` semantics: offsets are into `customProfiles`,
    /// and `destination` is an index in the list before the move. Master stays last.
    func moveCustomProfiles(from source: IndexSet, to destination: Int) {
        let custom = customProfiles
        let moving = source.filter { custom.indices.contains($0) }.map { custom[$0] }
        var rest = custom.enumerated().filter { !source.contains($0.offset) }.map(\.element)
        let insertAt = min(destination, custom.count) - source.count(in: 0..<min(destination, custom.count))
        rest.insert(contentsOf: moving, at: max(0, min(insertAt, rest.count)))
        profiles = rest + [master]
        commitProfiles()
    }

    func setProxyPort(_ port: UInt16) {
        guard ProfileValidator.portRange.contains(port), port != proxyPort else { return }
        proxyPort = port
        defaults.set(Int(port), forKey: Key.proxyPort)
        onChange?()
    }

    func setAllowLANAccess(_ allow: Bool) {
        guard allow != allowLANAccess else { return }
        allowLANAccess = allow
        defaults.set(allow, forKey: Key.allowLANAccess)
        onChange?()
    }

    /// Display only: the running server doesn't care, so no `onChange`.
    func setHiddenHosts(_ patterns: [String]) {
        guard patterns != hiddenHosts else { return }
        hiddenHosts = patterns
        defaults.set(patterns, forKey: Key.scannerHiddenHosts)
    }

    private func commitProfiles() {
        if let data = try? JSONEncoder().encode(profiles) {
            defaults.set(data, forKey: Key.profiles)
        }
        loadError = nil
        onChange?()
    }

    // MARK: - Export / import

    func exportJSON() -> String? {
        let exported = ExportedSettings(profiles: profiles, proxyPort: proxyPort, allowLANAccess: allowLANAccess)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(exported) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    enum ImportError: LocalizedError, Equatable {
        case unreadable(String)
        case invalid([ProfileValidator.Issue])

        var errorDescription: String? {
            switch self {
            case .unreadable(let reason): return "Clipboard does not contain valid settings data (\(reason))."
            case .invalid(let issues): return issues.map(\.description).joined(separator: "\n")
            }
        }
    }

    /// Replaces everything, or nothing if the settings don't pass `ProfileValidator` (U5).
    func importJSON(_ json: String) throws {
        let imported: ExportedSettings
        do {
            imported = try JSONDecoder().decode(ExportedSettings.self, from: Data(json.utf8))
        } catch {
            throw ImportError.unreadable(error.localizedDescription)
        }
        let issues = ProfileValidator.validate(imported)
        guard issues.isEmpty else { throw ImportError.invalid(issues) }

        profiles = Self.normalized(imported.profiles)
        proxyPort = imported.proxyPort
        allowLANAccess = imported.allowLANAccess
        defaults.set(Int(proxyPort), forKey: Key.proxyPort)
        defaults.set(allowLANAccess, forKey: Key.allowLANAccess)
        commitProfiles()
    }

    /// Exactly one Master, last. Stored data from before 4e may lack one, or (after a bad
    /// import) have several: the first stays Master, the others become custom profiles.
    static func normalized(_ profiles: [SpoofProfile]) -> [SpoofProfile] {
        var master: SpoofProfile?
        var custom: [SpoofProfile] = []
        for var profile in profiles {
            if profile.isDefault && master == nil {
                master = profile
            } else {
                profile.isDefault = false
                custom.append(profile)
            }
        }
        return custom + [master ?? .makeDefault()]
    }
}

/// Checks imported settings before they replace the current ones (U5).
enum ProfileValidator {
    static let portRange: ClosedRange<UInt16> = 1024...65535
    static let chunkSizeRange = 1...1000

    enum Issue: Equatable, CustomStringConvertible {
        case masterCount(Int)
        case duplicateID(UUID)
        case chunkSize(profile: String, Int)
        case dohURL(profile: String, String)
        case port(UInt16)

        var description: String {
            switch self {
            case .masterCount(let n): return "Expected exactly one Master profile, found \(n)."
            case .duplicateID(let id): return "Two profiles share the id \(id.uuidString)."
            case .chunkSize(let name, let size): return "\(name): chunk size \(size) is outside \(chunkSizeRange.lowerBound)…\(chunkSizeRange.upperBound)."
            case .dohURL(let name, let url): return "\(name): DoH URL \"\(url)\" is not an https URL."
            case .port(let port): return "Port \(port) is outside \(portRange.lowerBound)…\(portRange.upperBound)."
            }
        }
    }

    static func validate(_ settings: ExportedSettings) -> [Issue] {
        var issues: [Issue] = []
        let masters = settings.profiles.filter(\.isDefault).count
        if masters != 1 { issues.append(.masterCount(masters)) }

        var seen = Set<UUID>()
        for profile in settings.profiles where !seen.insert(profile.id).inserted {
            issues.append(.duplicateID(profile.id))
        }

        for profile in settings.profiles {
            let name = profile.isDefault ? "Master" : (profile.name.isEmpty ? "Unnamed profile" : profile.name)
            if !chunkSizeRange.contains(profile.chunkSize) {
                issues.append(.chunkSize(profile: name, profile.chunkSize))
            }
            // An inheriting profile uses Master's URL, which is checked on Master.
            let ownsURL = profile.isDefault || !profile.inheritDoH
            if profile.dohEnabled && ownsURL && !isHTTPSURL(profile.dohServerURL) {
                issues.append(.dohURL(profile: name, profile.dohServerURL))
            }
        }

        if !portRange.contains(settings.proxyPort) { issues.append(.port(settings.proxyPort)) }
        return issues
    }

    static func isHTTPSURL(_ text: String) -> Bool {
        guard let url = URL(string: text), url.scheme?.lowercased() == "https", let host = url.host else { return false }
        return !host.isEmpty
    }
}
