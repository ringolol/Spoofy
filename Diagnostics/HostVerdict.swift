import Foundation

/// What kind of block a host's evidence points to (network-scanner plan §6.2).
enum BlockKind: Hashable, Sendable {
    case sni, ip, dns, httpBlockPage, freeze, injected, whitelist, outline

    /// Nil for outcomes that don't point at a block, and for `midStreamReset`, which is too weak.
    init?(_ kind: TraceOutcome.Kind) {
        switch kind {
        case .helloReset, .helloSilentClose, .helloBlackhole: self = .sni
        case .connectRefused, .connectTimeout, .connectUnreachable: self = .ip
        case .dnsBogus, .dnsFailed: self = .dns
        case .httpBlockPage: self = .httpBlockPage
        case .injectedResponse: self = .injected
        case .freeze: self = .freeze
        case .outlineFailed: self = .outline
        case .ok, .clientAborted, .interrupted, .midStreamReset, .inconclusive: return nil
        }
    }
}

enum HostStatus: Equatable, Sendable {
    case unknown
    case working
    case suspicious(BlockKind)
    case blocked(BlockKind)
    /// The evidence was gathered under other routing settings.
    case ruleChanged

    var isProblem: Bool {
        switch self {
        case .suspicious, .blocked: return true
        default: return false
        }
    }
}

struct HostVerdict: Sendable {
    let status: HostStatus
    /// Nil for `unknown` and `ruleChanged`.
    let confidence: TraceOutcome.Confidence?
    /// A ClientHello in the evidence offered ECH.
    let echSeen: Bool
    /// The connections the verdict rests on, oldest first.
    let evidence: [ClassifiedTrace]

    static let window: TimeInterval = 15 * 60
    /// "Network healthy": another host was fine within this much of a failure.
    static let healthyWindow: TimeInterval = 60

    /// Pure: one host's recent connections → a verdict (§6.2).
    static func verdict(for record: HostRecord, currentFingerprint: String, network: NetworkState,
                        recentGlobal: [GlobalOutcome], now: Date) -> HostVerdict {
        // Offline: nothing new counts until the network is back.
        let cutoff = network == .offline ? now.addingTimeInterval(-NetworkState.window) : now.addingTimeInterval(1)
        let recent = record.recent.elements.filter {
            $0.outcome.kind.isEvidence && $0.outcome.kind != .outlineFailed
                && now.timeIntervalSince($0.summary.endedDate) <= window && $0.summary.endedDate <= cutoff
        }
        var current = recent.filter { $0.summary.start.fingerprint == currentFingerprint }
        // §2.5.5: TLS and HTTP get the full rules; other protocols on the same host only add noise.
        let full = current.filter { $0.summary.kind.tag == .tls || $0.summary.kind.tag == .http }
        if !full.isEmpty { current = full }

        guard !current.isEmpty else {
            return HostVerdict(status: recent.isEmpty ? .unknown : .ruleChanged, confidence: nil, echSeen: false, evidence: recent)
        }
        let echSeen = current.contains { $0.outcome.echPresent }
        func make(_ status: HostStatus, _ confidence: TraceOutcome.Confidence, _ evidence: [ClassifiedTrace]) -> HostVerdict {
            HostVerdict(status: status, confidence: confidence, echSeen: echSeen, evidence: evidence)
        }

        var scores: [BlockKind: Double] = [:]
        var lastSeen: [BlockKind: Date] = [:]
        for trace in current {
            guard let kind = BlockKind(trace.outcome.kind) else { continue }
            scores[kind, default: 0] += weight(trace.outcome.confidence)
            lastSeen[kind] = trace.summary.endedDate
        }

        // Freeze first: small requests still succeed under it.
        if scores[.freeze, default: 0] >= 2 {
            return make(.blocked(.freeze), .medium, current.filter { BlockKind($0.outcome.kind) == .freeze })
        }
        if current.suffix(2).count == 2, current.suffix(2).allSatisfy({ $0.outcome.kind == .ok }) {
            return make(.working, .high, current)
        }
        guard let (top, score) = scores.max(by: { ($0.value, lastSeen[$0.key]!) < ($1.value, lastSeen[$1.key]!) }),
              score > 0 else {
            return current.last?.outcome.kind == .ok ? make(.working, .high, current) : make(.unknown, .low, current)
        }

        let evidence = current.filter { BlockKind($0.outcome.kind) == top }
        if network == .whitelistMode, top == .sni || top == .ip {
            return make(.blocked(.whitelist), .medium, evidence)
        }
        let healthy = evidence.contains { trace in
            recentGlobal.contains {
                $0.host != record.host && $0.outcome.kind == .ok
                    && abs($0.endedAt.timeIntervalSince(trace.summary.endedDate)) <= healthyWindow
            }
        }
        guard score >= 2, healthy else { return make(.suspicious(top), .low, evidence) }
        let high = evidence.contains { $0.outcome.confidence == .high }
        return make(.blocked(top), high ? .high : .medium, evidence)
    }

    private static func weight(_ confidence: TraceOutcome.Confidence) -> Double {
        switch confidence {
        case .high: return 2
        case .medium: return 1
        case .low: return 0.5
        }
    }
}
