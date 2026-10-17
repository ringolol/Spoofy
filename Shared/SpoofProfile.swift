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
