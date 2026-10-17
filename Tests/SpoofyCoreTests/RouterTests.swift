import XCTest
@testable import SpoofyCore

final class RouterTests: XCTestCase {
    private static let outline = OutlineServerConfig(host: "h", port: 1, password: "p", cipher: .aes256Gcm, prefix: nil)
    private static let head = InboundRequest.Kind.http(head: Data("GET / HTTP/1.1\r\n\r\n".utf8))

    private func profile(route: RouteMode = .split, split: SplitMode = .sni, outline: OutlineServerConfig? = nil) -> SpoofProfile {
        var profile = SpoofProfile.makeDefault()
        profile.routeMode = route
        profile.splitMode = split
        profile.chunkSize = 7
        profile.tlsRecordFragmentation = true
        profile.outlineConfig = outline
        return profile
    }

    func testDecisionTable() {
        let desync = OutboundKind.desync(DesyncParameters(mode: .sni, chunkSize: 7, recordFragmentation: true))
        let cases: [(SpoofProfile, InboundRequest.Kind, OutboundKind, String)] = [
            (profile(split: .sni), .tunnel, desync, "split tunnel desyncs"),
            (profile(split: .none), .tunnel, .direct, "mode none is direct"),
            (profile(split: .sni), Self.head, .direct, "plain HTTP has no ClientHello to desync"),
            (profile(route: .vpn, outline: Self.outline), .tunnel, .shadowsocks(Self.outline), "VPN tunnel"),
            (profile(route: .vpn, outline: Self.outline), Self.head, .shadowsocks(Self.outline), "VPN plain HTTP"),
            (profile(route: .vpn), .tunnel, .reject(reason: "VPN route has no Outline config"), "U6 tunnel"),
            (profile(route: .vpn), Self.head, .reject(reason: "VPN route has no Outline config"), "U6 plain HTTP"),
        ]
        for (profile, kind, expected, name) in cases {
            XCTAssertEqual(Router.outbound(for: profile, kind: kind), expected, name)
        }
    }

    func testEverySplitModeButNoneDesyncs() {
        for mode in SplitMode.allCases where mode != .none {
            guard case .desync(let parameters) = Router.outbound(for: profile(split: mode), kind: .tunnel) else {
                return XCTFail("\(mode)")
            }
            XCTAssertEqual(parameters.mode, mode)
        }
    }

    func testRouteLooksUpTheTargetHost() {
        var asked: [String] = []
        let router = Router { host in
            asked.append(host)
            return self.profile(split: .none)
        }
        let decision = router.route(DialTarget(host: "example.com", port: 443), kind: .tunnel)
        XCTAssertEqual(asked, ["example.com"])
        XCTAssertEqual(decision.outbound, .direct)
    }

    /// Through `AppSettings`: a custom VPN profile that inherits Master's server gets it.
    func testInheritedVPNConfigComesFromMaster() {
        let suite = "RouterTests.\(UUID().uuidString)"
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        var master = SpoofProfile.makeDefault()
        master.outlineConfig = Self.outline
        var vpn = SpoofProfile.makeDefault()
        vpn.id = UUID()
        vpn.isDefault = false
        vpn.domainPatterns = ["example.com"]
        vpn.routeMode = .vpn
        vpn.inheritOutlineConfig = true
        settings.profiles = [vpn, master]

        let router = Router(settings: settings)
        XCTAssertEqual(router.route(DialTarget(host: "example.com", port: 443), kind: .tunnel).outbound, .shadowsocks(Self.outline))
        XCTAssertEqual(router.route(DialTarget(host: "other.org", port: 443), kind: .tunnel).outbound, .direct)
    }
}
