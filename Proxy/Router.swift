import Foundation

/// How the first TLS record of a tunnel is cut up (`TLSDesyncer`).
struct DesyncParameters: Equatable {
    let mode: SplitMode
    let chunkSize: Int
    let recordFragmentation: Bool

    init(mode: SplitMode, chunkSize: Int, recordFragmentation: Bool) {
        self.mode = mode
        self.chunkSize = chunkSize
        self.recordFragmentation = recordFragmentation
    }

    init(profile: SpoofProfile) {
        self.init(mode: profile.splitMode, chunkSize: profile.chunkSize,
                  recordFragmentation: profile.tlsRecordFragmentation)
    }
}

enum OutboundKind: Equatable {
    /// Dial the target and relay as-is: split mode `.none`, or plain HTTP.
    case direct
    /// Dial the target and desync the client's first TLS record.
    case desync(DesyncParameters)
    /// Through an Outline / Shadowsocks server.
    case shadowsocks(OutlineServerConfig)
    /// Refuse the request (U6: a VPN route without a server must not fall back to direct).
    case reject(reason: String)
}

struct RouteDecision {
    /// The matched profile, with Master's inherited settings applied.
    let profile: SpoofProfile
    let outbound: OutboundKind
}

/// Request → outbound (plan §6.5). The only place that looks at a profile's route mode and its
/// Outline config. Pure apart from the profile lookup, which tests replace.
struct Router {
    private let profileForHost: (String) -> SpoofProfile

    init(profileForHost: @escaping (String) -> SpoofProfile) {
        self.profileForHost = profileForHost
    }

    init(settings: AppSettings) {
        self.init(profileForHost: settings.matchingProfile(for:))
    }

    func route(_ target: DialTarget, kind: InboundRequest.Kind) -> RouteDecision {
        let profile = profileForHost(target.host)
        return RouteDecision(profile: profile, outbound: Self.outbound(for: profile, kind: kind))
    }

    static func outbound(for profile: SpoofProfile, kind: InboundRequest.Kind) -> OutboundKind {
        switch profile.routeMode {
        case .vpn:
            guard let config = profile.outlineConfig else {
                return .reject(reason: "VPN route has no Outline config")
            }
            return .shadowsocks(config)
        case .split:
            // There is no TLS record to desync in plain HTTP.
            if case .http = kind { return .direct }
            return profile.splitMode == .none ? .direct : .desync(DesyncParameters(profile: profile))
        }
    }
}
