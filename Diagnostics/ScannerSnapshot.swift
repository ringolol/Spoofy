import Foundation

/// One host in the scanner list (network-scanner plan §7.2).
struct HostRow: Identifiable, Sendable {
    var id: String { host }
    let host: String
    let ports: [UInt16]
    let ips: [String]
    /// For an IP-literal host: the name its ClientHello asked for.
    let sni: String?
    /// Every name seen in ClientHellos to this IP, sorted.
    let snis: [String]
    let kinds: Set<PayloadKindTag>
    /// Finished connections; `openCount` counts the live ones.
    let connectionCount: Int
    let openCount: Int
    let lastSeen: Date
    let profileID: UUID
    let profileName: String
    let isDefaultProfile: Bool
    let verdict: HostVerdict
    /// The host's latest connections, oldest first.
    let recent: [ClassifiedTrace]
}

/// What the main screen shows (§7.1 b).
struct LogSummary: Equatable, Sendable {
    let hostCount: Int
    let blockedCount: Int
    let network: NetworkState
}

/// The verdict pass shared by the scanner screen and the main-screen summary (§7.1). Pure, so it
/// runs off the main thread on copies taken there.
struct ScannerSnapshot: Sendable {
    /// Blocked, suspicious, rule changed, the rest; newest first within each.
    let rows: [HostRow]
    /// Newest first.
    let refusals: [RefusalGroup]
    let network: NetworkState
    let activeCount: Int
    /// Hosts left out by `hiddenHosts`.
    let hiddenCount: Int

    var summary: LogSummary {
        LogSummary(hostCount: rows.count, blockedCount: rows.filter { if case .blocked = $0.verdict.status { return true }; return false }.count,
                   network: network)
    }

    static func build(log: LogSnapshot, config: ProxyConfig, hiddenHosts: [String] = [], now: Date) -> ScannerSnapshot {
        let recentGlobal = log.recentGlobal.elements
        let network = NetworkState.evaluate(recentGlobal, now: now)
        let hidden = DomainMatcher(patterns: hiddenHosts)

        // A browser keeps its connection open for minutes; list the host before the first one closes.
        let open = Dictionary(grouping: log.active.values, by: \.host)
        var records = log.hosts
        for (host, entries) in open where records[host] == nil {
            var record = HostRecord(host: host, firstSeen: entries.map(\.startedAt).min()!)
            record.ports = Set(entries.map(\.port))
            record.lastSeen = entries.map(\.startedAt).max()!
            records[host] = record
        }

        var rows: [HostRow] = []
        var hiddenCount = 0
        for record in records.values {
            if !hidden.isEmpty, hidden.matches(record.host) {
                hiddenCount += 1
                continue
            }
            let profile = config.profile(for: record.host)
            let verdict = HostVerdict.verdict(for: record, currentFingerprint: profile.routingFingerprint,
                                              network: network, recentGlobal: recentGlobal, now: now)
            let recent = record.recent.elements
            let kinds = Set(recent.map(\.summary.kind.tag)).subtracting([.none])
            let snis = record.snis.sorted()
            rows.append(HostRow(host: record.host, ports: record.ports.sorted(), ips: record.ips,
                                sni: snis.first { $0 != record.host }, snis: snis, kinds: kinds,
                                connectionCount: record.connectionCount, openCount: open[record.host]?.count ?? 0,
                                lastSeen: record.lastSeen,
                                profileID: profile.id, profileName: profile.name,
                                isDefaultProfile: profile.isDefault, verdict: verdict, recent: recent))
        }
        rows.sort {
            let (l, r) = (rank($0.verdict.status), rank($1.verdict.status))
            if l != r { return l < r }
            if $0.lastSeen != $1.lastSeen { return $0.lastSeen > $1.lastSeen }
            return $0.host < $1.host
        }
        return ScannerSnapshot(rows: rows, refusals: log.refusals.values.sorted { $0.lastSeen > $1.lastSeen },
                               network: network, activeCount: log.active.count, hiddenCount: hiddenCount)
    }

    private static func rank(_ status: HostStatus) -> Int {
        switch status {
        case .blocked: return 0
        case .suspicious: return 1
        case .ruleChanged: return 2
        case .working, .unknown: return 3
        }
    }
}
