import Foundation

/// The pure part of the add-to-profile sheet (network-scanner plan §7.4): which patterns, which
/// route a new profile should start with, and what saving would actually do.
enum AddPatternsPlan {
    /// One pattern and the selected hosts that produced it.
    struct Entry: Equatable {
        let pattern: String
        var hosts: [String]
    }

    struct Suggestion: Equatable {
        let routeMode: RouteMode
        let splitMode: SplitMode
        let dohEnabled: Bool
        let note: Note?
        let reason: Reason

        /// Whether `profile` has these route settings; split mode only counts on the split route.
        func matches(_ profile: SpoofProfile) -> Bool {
            profile.routeMode == routeMode && profile.dohEnabled == dohEnabled
                && (routeMode != .split || profile.splitMode == splitMode)
        }
    }

    /// What the suggestion is based on.
    enum Reason: Equatable {
        /// The selected hosts' most common problem.
        case blocked(BlockKind)
        /// The hosts carry protocols split modes don't change.
        case nonTLS
        /// Nothing pointed at a block: the defaults, not a recommendation.
        case noEvidence
    }

    enum Note: Equatable {
        /// IP or freeze blocks without an Outline server on Master.
        case ipNeedsVPN
        /// Only non-TLS hosts, and no Outline server to suggest.
        case splitOnlyChangesTLS
    }

    enum Warning: Equatable {
        case alreadyInTarget(String)
        /// `host` will still match an earlier profile.
        case shadowed(host: String, by: String)
        case targetDisabled
    }

    // MARK: - Patterns

    /// How an edited pattern relates to the host it was made for.
    enum PatternCheck: Equatable {
        /// Matches only the host.
        case exact
        /// Matches the host and others.
        case wider
        /// Valid, but not for this host (a typo, or meant for something else).
        case noMatch
        /// Matches nothing (`DomainMatcher` drops it).
        case invalid
    }

    /// `*.test.example.com` (the host and its subdomains), then `*.example.com` (the site). One
    /// entry when they're the same; IPs and single labels stay exact.
    static func suggestions(for host: String) -> [String] {
        var host = host.lowercased()
        guard let site = BaseDomain.of(host) else { return [host] }
        if host.hasPrefix("www."), host.count > 4 { host.removeFirst(4) }
        return host == site ? ["*.\(site)"] : ["*.\(host)", "*.\(site)"]
    }

    static func check(_ pattern: String, host: String) -> PatternCheck {
        let pattern = normalized(pattern)
        let matcher = DomainMatcher(patterns: [pattern])
        if matcher.isEmpty { return .invalid }
        if !matcher.matches(host) { return .noMatch }
        return pattern == host.lowercased() ? .exact : .wider
    }

    /// `patterns[host]` defaults to the first suggestion. Invalid patterns are left out; identical
    /// ones are merged, in host order.
    static func entries(hosts: [String], patterns: [String: String]) -> [Entry] {
        var entries: [Entry] = []
        for host in hosts {
            let pattern = normalized(patterns[host] ?? suggestions(for: host)[0])
            guard !DomainMatcher(patterns: [pattern]).isEmpty else { continue }
            if let index = entries.firstIndex(where: { $0.pattern == pattern }) {
                entries[index].hosts.append(host)
            } else {
                entries.append(Entry(pattern: pattern, hosts: [host]))
            }
        }
        return entries
    }

    static func normalized(_ pattern: String) -> String {
        pattern.trimmingCharacters(in: .whitespaces).lowercased()
    }

    static func defaultName(hosts: [String]) -> String {
        guard let first = hosts.first else { return "" }
        return BaseDomain.of(first) ?? first
    }

    // MARK: - Suggested route

    /// `kinds`: the selected hosts' problem kinds, one per host. `payloads`: what they carried.
    static func suggestion(kinds: [BlockKind], payloads: Set<PayloadKindTag>, masterHasOutline: Bool) -> Suggestion {
        // §2.5.5: split modes only change TLS.
        let carriesWeb = payloads.contains(.tls) || payloads.contains(.http)
        let nonTLS = !payloads.subtracting([.none]).isEmpty && !carriesWeb
        let kind = dominant(kinds)
        let reason: Reason = nonTLS ? .nonTLS : kind.map { .blocked($0) } ?? .noEvidence

        let split = { (mode: SplitMode, doh: Bool, note: Note?) in
            Suggestion(routeMode: .split, splitMode: mode, dohEnabled: doh, note: note, reason: reason)
        }
        let vpn = Suggestion(routeMode: .vpn, splitMode: .none, dohEnabled: false, note: nil, reason: reason)

        if nonTLS {
            return masterHasOutline ? vpn : split(.none, false, .splitOnlyChangesTLS)
        }

        switch kind {
        case .dns:
            return split(.none, true, nil)
        case .ip, .freeze, .whitelist:
            return masterHasOutline ? vpn : split(.sni, false, .ipNeedsVPN)
        case .httpBlockPage:
            return masterHasOutline ? vpn : split(.none, true, nil)
        case .sni, .injected, .outline, nil:
            return split(.sni, false, nil)
        }
    }

    /// The most common kind; a tie goes to the one seen first.
    private static func dominant(_ kinds: [BlockKind]) -> BlockKind? {
        var counts: [BlockKind: Int] = [:]
        kinds.forEach { counts[$0, default: 0] += 1 }
        return kinds.max { counts[$0]! < counts[$1]! || (counts[$0]! == counts[$1]! && kinds.firstIndex(of: $0)! > kinds.firstIndex(of: $1)!) }
    }

    // MARK: - Saving

    /// `profiles` as they would be after saving. A new target goes last, in front of Master.
    static func simulated(entries: [Entry], target: SpoofProfile, isNew: Bool, profiles: [SpoofProfile]) -> [SpoofProfile] {
        var profiles = profiles
        if isNew {
            var profile = target
            profile.isDefault = false
            profile.domainPatterns = merged(profile.domainPatterns, entries)
            let masterIndex = profiles.firstIndex(where: \.isDefault) ?? profiles.endIndex
            profiles.insert(profile, at: masterIndex)
        } else if let index = profiles.firstIndex(where: { $0.id == target.id }) {
            profiles[index].domainPatterns = merged(profiles[index].domainPatterns, entries)
        }
        return profiles
    }

    /// What saving would do that the user might not expect.
    static func warnings(entries: [Entry], target: SpoofProfile, isNew: Bool, profiles: [SpoofProfile]) -> [Warning] {
        var warnings: [Warning] = []
        if !isNew {
            let existing = Set(target.domainPatterns.map { $0.lowercased() })
            warnings += entries.filter { existing.contains($0.pattern.lowercased()) }.map { .alreadyInTarget($0.pattern) }
        }
        guard target.isEnabled else { return warnings + [.targetDisabled] }

        let config = ProxyConfig(profiles: simulated(entries: entries, target: target, isNew: isNew, profiles: profiles),
                                 port: 0, allowLANAccess: false)
        for host in entries.flatMap(\.hosts) {
            let match = config.profile(for: host)
            if match.id != target.id {
                warnings.append(.shadowed(host: host, by: match.isDefault ? "Master" : match.name))
            }
        }
        return warnings
    }

    private static func merged(_ patterns: [String], _ entries: [Entry]) -> [String] {
        var seen = Set(patterns.map { $0.lowercased() })
        return patterns + entries.map(\.pattern).filter { seen.insert($0.lowercased()).inserted }
    }
}
