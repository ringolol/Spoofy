import Foundation

enum SplitMode: String, CaseIterable, Identifiable, Codable {
    case sni
    case random
    case chunk
    case firstByte
    case none

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .sni: return "SNI"
        case .random: return "Random"
        case .chunk: return "Chunk"
        case .firstByte: return "First Byte"
        case .none: return "None"
        }
    }
}

struct SpoofProfile: Codable, Identifiable, Equatable {
    var id: UUID
    var name: String
    var isEnabled: Bool
    var domainPatterns: [String]
    var splitMode: SplitMode
    var chunkSize: Int
    var tlsRecordFragmentation: Bool
    var dohEnabled: Bool
    var dohServerURL: String
    var isDefault: Bool

    static func makeDefault() -> SpoofProfile {
        SpoofProfile(
            id: UUID(),
            name: "Master",
            isEnabled: true,
            domainPatterns: [],
            splitMode: .none,
            chunkSize: 5,
            tlsRecordFragmentation: false,
            dohEnabled: false,
            dohServerURL: "https://1.1.1.1/dns-query",
            isDefault: true
        )
    }
}

struct ExportedSettings: Codable {
    var profiles: [SpoofProfile]
    var proxyPort: UInt16
    var allowLANAccess: Bool
}

final class AppSettings {
    static let shared = AppSettings()

    private let defaults: UserDefaults

    init() {
        defaults = .standard
        defaults.register(defaults: [
            "proxyPort": 8090,
            "allowLANAccess": false,
        ])
    }

    var profiles: [SpoofProfile] {
        get {
            guard let data = defaults.data(forKey: "spoofProfiles"),
                  let decoded = try? JSONDecoder().decode([SpoofProfile].self, from: data) else {
                let defaultProfiles = [SpoofProfile.makeDefault()]
                if let data = try? JSONEncoder().encode(defaultProfiles) {
                    defaults.set(data, forKey: "spoofProfiles")
                }
                return defaultProfiles
            }
            return decoded
        }
        set {
            if let data = try? JSONEncoder().encode(newValue) {
                defaults.set(data, forKey: "spoofProfiles")
            }
        }
    }

    var proxyPort: UInt16 {
        get { UInt16(defaults.integer(forKey: "proxyPort")) }
        set { defaults.set(Int(newValue), forKey: "proxyPort") }
    }

    var allowLANAccess: Bool {
        get { defaults.bool(forKey: "allowLANAccess") }
        set { defaults.set(newValue, forKey: "allowLANAccess") }
    }

    func matchingProfile(for host: String) -> SpoofProfile {
        let h = host.lowercased()
        for profile in profiles where profile.isEnabled {
            if profile.domainPatterns.isEmpty {
                return profile
            }
            if Self.matchesPatterns(host: h, patterns: profile.domainPatterns) {
                return profile
            }
        }
        // Fallback: return default profile (should always be present)
        return profiles.last ?? SpoofProfile.makeDefault()
    }

    func exportJSON() -> String? {
        let exported = ExportedSettings(
            profiles: profiles,
            proxyPort: proxyPort,
            allowLANAccess: allowLANAccess
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(exported) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func importJSON(_ json: String) throws {
        guard let data = json.data(using: .utf8) else {
            throw NSError(domain: "AppSettings", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid text encoding"])
        }
        let imported = try JSONDecoder().decode(ExportedSettings.self, from: data)
        profiles = imported.profiles
        proxyPort = imported.proxyPort
        allowLANAccess = imported.allowLANAccess
    }

    static func matchesPatterns(host: String, patterns: [String]) -> Bool {
        let h = host.lowercased()
        for pattern in patterns {
            let p = pattern.lowercased()
            let hasWildcardPrefix = p.hasPrefix("*.")
            let hasWildcardSuffix = p.hasSuffix(".*")
            if hasWildcardPrefix && hasWildcardSuffix {
                let middle = String(p.dropFirst(2).dropLast(2))
                if h.contains(middle) { return true }
            } else if hasWildcardPrefix {
                let suffix = String(p.dropFirst(1))
                if h.hasSuffix(suffix) || h == String(p.dropFirst(2)) {
                    return true
                }
            } else if hasWildcardSuffix {
                let prefix = String(p.dropLast(2))
                if h.hasPrefix(prefix + ".") || h == prefix {
                    return true
                }
            } else {
                if h == p { return true }
            }
        }
        return false
    }
}
