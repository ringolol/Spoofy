import Foundation

/// An immutable settings snapshot for the network side (plan §6.7). `SettingsStore` builds one
/// on every change and hands it to the running server; nothing on the network side reads the
/// store or `UserDefaults`.
struct ProxyConfig {
    /// An enabled custom profile, with Master's inherited settings applied and its patterns compiled.
    struct Rule {
        let profile: SpoofProfile
        let matcher: DomainMatcher
    }

    let port: UInt16
    let allowLANAccess: Bool
    /// The catch-all, found by `isDefault` rather than by position (U2).
    let master: SpoofProfile
    /// In user order: the first match wins.
    let rules: [Rule]

    init(profiles: [SpoofProfile], port: UInt16, allowLANAccess: Bool) {
        let master = profiles.first { $0.isDefault } ?? .makeDefault()
        self.port = port
        self.allowLANAccess = allowLANAccess
        self.master = master
        // A custom profile with no usable patterns matches nothing (U1), so a freshly added
        // profile can't take over all traffic.
        self.rules = profiles
            .filter { $0.isEnabled && !$0.isDefault }
            .map { Rule(profile: Self.resolve($0, master: master), matcher: DomainMatcher(patterns: $0.domainPatterns)) }
            .filter { !$0.matcher.isEmpty }
    }

    /// The profile for `host`: the first enabled custom profile that matches, otherwise Master.
    func profile(for host: String) -> SpoofProfile {
        let labels = DomainMatcher.labels(of: host)
        return rules.first { $0.matcher.matches(labels: labels) }?.profile ?? master
    }

    /// `profile` with the settings it inherits from Master filled in.
    static func resolve(_ profile: SpoofProfile, master: SpoofProfile) -> SpoofProfile {
        guard !profile.isDefault else { return profile }
        var resolved = profile
        if profile.inheritDoH {
            resolved.dohServerURL = master.dohServerURL
        }
        if profile.inheritOutlineConfig {
            resolved.outlineConfig = master.outlineConfig
        }
        return resolved
    }
}
