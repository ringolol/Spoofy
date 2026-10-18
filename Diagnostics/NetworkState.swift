import Foundation

/// The network as a whole, for the scanner banner (network-scanner plan §6.3). Pure.
enum NetworkState: Equatable, Sendable {
    case normal
    /// Nothing gets through: host verdicts stop updating.
    case offline
    /// Only approved sites work.
    case whitelistMode
    /// A VPN profile's Outline server is unreachable or blocked.
    case outlineDown(profileName: String)

    static let window: TimeInterval = 90

    static func evaluate(_ recent: [GlobalOutcome], now: Date) -> NetworkState {
        let inWindow = recent.filter { now.timeIntervalSince($0.endedAt) <= window && $0.endedAt <= now.addingTimeInterval(1) }

        // Offline and whitelist look at what the network did to hosts directly; each host counts
        // once, by its latest outcome that says anything.
        var latest: [String: TraceOutcome.Kind] = [:]
        for entry in inWindow.sorted(by: { $0.endedAt < $1.endedAt }) where entry.outbound.isDirectRoute {
            if entry.outcome.kind.isEvidence { latest[entry.host] = entry.outcome.kind }
        }
        let kinds = Array(latest.values)
        let okCount = kinds.filter { $0 == .ok }.count

        if kinds.count >= 3, okCount == 0, kinds.allSatisfy(\.isConnectOrDNS) { return .offline }

        let failing = kinds.filter {
            if case .helloBlackhole = $0 { return true }
            return $0 == .connectTimeout
        }.count
        if failing >= 6, okCount >= 1, Double(failing) / Double(kinds.count) >= 0.7 { return .whitelistMode }

        // Outline: every connection counts, per profile.
        var outline: [UUID: (name: String, failed: Int, ok: Bool)] = [:]
        for entry in inWindow {
            guard case .shadowsocks = entry.outbound else { continue }
            var tally = outline[entry.profileID] ?? (entry.profileName, 0, false)
            if entry.outcome.kind == .outlineFailed { tally.failed += 1 }
            if entry.outcome.kind == .ok { tally.ok = true }
            outline[entry.profileID] = tally
        }
        if let down = outline.values.filter({ $0.failed >= 3 && !$0.ok }).max(by: { $0.failed < $1.failed }) {
            return .outlineDown(profileName: down.name)
        }
        return .normal
    }
}

extension TraceOutcome.Kind {
    /// Says something about the host or the network, as opposed to the client or the proxy.
    var isEvidence: Bool {
        switch self {
        case .clientAborted, .interrupted, .inconclusive: return false
        default: return true
        }
    }

    var isConnectOrDNS: Bool {
        switch self {
        case .connectRefused, .connectTimeout, .connectUnreachable, .dnsFailed, .dnsBogus: return true
        default: return false
        }
    }
}

extension TraceOutbound {
    /// DPI sees the host itself, not an Outline server.
    var isDirectRoute: Bool {
        if case .shadowsocks = self { return false }
        return true
    }
}
