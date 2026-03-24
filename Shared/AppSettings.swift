import Foundation

// MARK: - Route Mode

enum RouteMode: String, CaseIterable, Identifiable, Codable {
    case split   // Existing DPI bypass behavior
    case vpn     // Route through a VPN server

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .split: return "Split"
        case .vpn: return "VPN"
        }
    }
}

enum VPNType: String, CaseIterable, Identifiable, Codable {
    case outline  // Shadowsocks (Outline)

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .outline: return "Outline"
        }
    }
}

// MARK: - Shadowsocks / Outline Config

enum ShadowsocksCipher: String, Codable, CaseIterable, Identifiable {
    case chacha20IetfPoly1305 = "chacha20-ietf-poly1305"
    case aes256Gcm = "aes-256-gcm"

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .chacha20IetfPoly1305: return "ChaCha20-Poly1305"
        case .aes256Gcm: return "AES-256-GCM"
        }
    }
}

struct OutlineServerConfig: Codable, Equatable {
    var host: String
    var port: UInt16
    var password: String
    var cipher: ShadowsocksCipher
    var prefix: Data?
}

// MARK: - Split Mode

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

struct SpoofProfile: Identifiable, Equatable, Codable {
    var id: UUID
    var name: String
    var isEnabled: Bool
    var domainPatterns: [String]

    // Route mode: split (DPI bypass) or vpn
    var routeMode: RouteMode
    var vpnType: VPNType
    var outlineConfig: OutlineServerConfig?

    // Split mode settings (used when routeMode == .split)
    var splitMode: SplitMode
    var chunkSize: Int
    var tlsRecordFragmentation: Bool
    var dohEnabled: Bool
    var dohServerURL: String
    var isDefault: Bool

    // Inheritance from Master profile (only meaningful for non-default profiles)
    var inheritDoH: Bool
    var inheritOutlineConfig: Bool

    static func makeDefault() -> SpoofProfile {
        SpoofProfile(
            id: UUID(),
            name: "Master",
            isEnabled: true,
            domainPatterns: [],
            routeMode: .split,
            vpnType: .outline,
            outlineConfig: nil,
            splitMode: .none,
            chunkSize: 5,
            tlsRecordFragmentation: false,
            dohEnabled: false,
            dohServerURL: "https://1.1.1.1/dns-query",
            isDefault: true,
            inheritDoH: false,
            inheritOutlineConfig: false
        )
    }

    // Custom Decodable for backward compatibility with old settings
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        isEnabled = try container.decode(Bool.self, forKey: .isEnabled)
        domainPatterns = try container.decode([String].self, forKey: .domainPatterns)
        routeMode = try container.decodeIfPresent(RouteMode.self, forKey: .routeMode) ?? .split
        vpnType = try container.decodeIfPresent(VPNType.self, forKey: .vpnType) ?? .outline
        outlineConfig = try container.decodeIfPresent(OutlineServerConfig.self, forKey: .outlineConfig)
        splitMode = try container.decode(SplitMode.self, forKey: .splitMode)
        chunkSize = try container.decode(Int.self, forKey: .chunkSize)
        tlsRecordFragmentation = try container.decode(Bool.self, forKey: .tlsRecordFragmentation)
        dohEnabled = try container.decode(Bool.self, forKey: .dohEnabled)
        dohServerURL = try container.decode(String.self, forKey: .dohServerURL)
        isDefault = try container.decode(Bool.self, forKey: .isDefault)
        inheritDoH = try container.decodeIfPresent(Bool.self, forKey: .inheritDoH) ?? false
        inheritOutlineConfig = try container.decodeIfPresent(Bool.self, forKey: .inheritOutlineConfig) ?? false
    }

    // Memberwise init
    init(
        id: UUID, name: String, isEnabled: Bool, domainPatterns: [String],
        routeMode: RouteMode, vpnType: VPNType, outlineConfig: OutlineServerConfig?,
        splitMode: SplitMode, chunkSize: Int, tlsRecordFragmentation: Bool,
        dohEnabled: Bool, dohServerURL: String, isDefault: Bool,
        inheritDoH: Bool = false, inheritOutlineConfig: Bool = false
    ) {
        self.id = id
        self.name = name
        self.isEnabled = isEnabled
        self.domainPatterns = domainPatterns
        self.routeMode = routeMode
        self.vpnType = vpnType
        self.outlineConfig = outlineConfig
        self.splitMode = splitMode
        self.chunkSize = chunkSize
        self.tlsRecordFragmentation = tlsRecordFragmentation
        self.dohEnabled = dohEnabled
        self.dohServerURL = dohServerURL
        self.isDefault = isDefault
        self.inheritDoH = inheritDoH
        self.inheritOutlineConfig = inheritOutlineConfig
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

    var masterProfile: SpoofProfile {
        profiles.first { $0.isDefault } ?? SpoofProfile.makeDefault()
    }

    func resolvedProfile(_ profile: SpoofProfile) -> SpoofProfile {
        guard !profile.isDefault else { return profile }
        var resolved = profile
        let master = masterProfile
        if profile.inheritDoH {
            resolved.dohServerURL = master.dohServerURL
        }
        if profile.inheritOutlineConfig {
            resolved.outlineConfig = master.outlineConfig
        }
        return resolved
    }

    func matchingProfile(for host: String) -> SpoofProfile {
        let h = host.lowercased()
        for profile in profiles where profile.isEnabled {
            if profile.domainPatterns.isEmpty {
                return resolvedProfile(profile)
            }
            if Self.matchesPatterns(host: h, patterns: profile.domainPatterns) {
                return resolvedProfile(profile)
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
