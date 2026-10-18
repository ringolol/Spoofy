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

    /// IP literals are always exact.
    static func canWildcard(_ host: String) -> Bool {
        BaseDomain.suggestWildcard(for: host) != nil
    }

    static func pattern(for host: String, wildcard: Bool) -> String {
        wildcard ? BaseDomain.suggestWildcard(for: host) ?? host : host
    }

    /// `wildcard[host]` defaults to true; identical patterns are merged, in host order.
    static func entries(hosts: [String], wildcard: [String: Bool]) -> [Entry] {
        var entries: [Entry] = []
        for host in hosts {
            let pattern = pattern(for: host, wildcard: wildcard[host] ?? true)
            if let index = entries.firstIndex(where: { $0.pattern.lowercased() == pattern.lowercased() }) {
                entries[index].hosts.append(host)
            } else {
                entries.append(Entry(pattern: pattern, hosts: [host]))
            }
        }
        return entries
    }

    static func defaultName(hosts: [String]) -> String {
        guard let first = hosts.first else { return "" }
        return BaseDomain.of(first) ?? first
    }

    // MARK: - Suggested route

    /// `kinds`: the selected hosts' problem kinds, one per host. `payloads`: what they carried.
    static func suggestion(kinds: [BlockKind], payloads: Set<PayloadKindTag>, masterHasOutline: Bool) -> Suggestion {
        let split = { (mode: SplitMode, doh: Bool, note: Note?) in
            Suggestion(routeMode: .split, splitMode: mode, dohEnabled: doh, note: note)
        }
        let vpn = Suggestion(routeMode: .vpn, splitMode: .none, dohEnabled: false, note: nil)

        // §2.5.5: split modes only change TLS.
        let carriesWeb = payloads.contains(.tls) || payloads.contains(.http)
        if !payloads.subtracting([.none]).isEmpty, !carriesWeb {
            return masterHasOutline ? vpn : split(.none, false, .splitOnlyChangesTLS)
        }

        switch dominant(kinds) {
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
