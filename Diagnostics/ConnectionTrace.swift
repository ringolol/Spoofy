import Foundation
import Network

/// One routed session, as the scanner sees it (network-scanner plan §2). Created by the observer
/// in `Session.begin` and touched only on the session queue, so it has no lock.
///
/// ```
/// created ─▶ resolving ─▶ connecting ─▶ connected ─▶ payloadSent ─▶ responding ─▶ ended
///    └────────────┴────────────┴────────────┴─────────────┴─────────────┴──────────▶ ended
/// ```
///
/// Phases only move forward: an event for an earlier phase is recorded but doesn't move it back.
/// Of the terminal events the first wins. `finish` closes the trace; the summary goes to
/// `onFinish` once, after the last transport report or `reportWait`, whichever comes first (§2.3).
final class ConnectionTrace {
    static let maxAttempts = 4
    static let downPrefixLength = 128

    let start: TraceStart
    private(set) var phase: TracePhase = .created

    private let queue: DispatchQueue
    private let clock: () -> UInt64
    private let reportWait: TimeInterval
    private var onFinish: ((TraceSummary) -> Void)?
    private var endReason: EndReason?
    private var fields = TraceFields()

    private var reports: TransportReports?
    private var pendingTransfer: PendingTransfer?
    private var collectedEarly = false
    private var lastUpAt: UInt64?
    private var lastDownAt: UInt64?

    init(_ start: TraceStart, queue: DispatchQueue,
         clock: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
         reportWait: TimeInterval = 1, onFinish: @escaping (TraceSummary) -> Void) {
        self.start = start
        self.queue = queue
        self.clock = clock
        self.reportWait = reportWait
        self.onFinish = onFinish
    }

    private func advance(to next: TracePhase) {
        if next > phase { phase = next }
    }

    // MARK: - Dial (ServerConnector, ShadowsocksOutbound)

    /// The resolver (DoH) was asked about the target name.
    func dnsStarted() {
        guard phase != .ended else { return }
        if fields.dnsStart == nil { fields.dnsStart = clock() }
        advance(to: .resolving)
    }

    /// Nil or empty: DoH gave nothing and the system resolver takes over.
    func dnsFinished(ips: [String]?) {
        guard phase != .ended else { return }
        fields.dnsEnd = clock()
        fields.dohIPs = ips.flatMap { $0.isEmpty ? nil : $0 }
    }

    func attemptStarted(_ address: String) {
        guard phase != .ended else { return }
        let now = clock()
        if fields.connectStart == nil { fields.connectStart = now }
        if fields.attempts.count < Self.maxAttempts {
            fields.attempts.append(DialAttemptRecord(address: address, startedAt: now, outcome: nil))
        }
        advance(to: .connecting)
    }

    func attemptFailed(_ address: String, _ error: NWError) {
        settle(address, .failed(error))
    }

    func attemptCancelled(_ address: String) {
        settle(address, .cancelled)
    }

    /// `reports` is the connection that won; its transport reports fill in RTT, DNS and
    /// retransmits (§2.3).
    func attemptReady(_ address: String, reports: TransportReports? = nil) {
        guard phase != .ended else { return }
        settle(address, .ready)
        fields.connectEnd = clock()
        fields.connectedAddress = address
        advance(to: .connected)
        guard let reports else { return }
        self.reports = reports
        reports.establishment(queue: queue) { [self] info in
            if let info { fields.establishment = info }
        }
        pendingTransfer = reports.startTransfer()
    }

    private func settle(_ address: String, _ outcome: DialAttemptRecord.Outcome) {
        guard phase != .ended,
              let index = fields.attempts.lastIndex(where: { $0.address == address && $0.outcome == nil }) else { return }
        fields.attempts[index].outcome = outcome
    }

    // MARK: - First payload (§2.2)

    /// What the session did with the first flight. Set before `payloadSent`, or before the
    /// relay when the relay will carry the first bytes.
    func setApplied(_ applied: AppliedStrategy) {
        guard phase != .ended else { return }
        fields.applied = applied
    }

    /// The first client bytes were fully written upstream: the moment the DPI saw them.
    /// Nil `kind` leaves the kind to the relay (`FirstFlight.empty`).
    func payloadSent(kind: PayloadKind?) {
        guard phase != .ended, fields.payloadSentAt == nil else { return }
        let now = clock()
        fields.payloadSentAt = now
        lastUpAt = now
        if fields.payloadKind == nil { fields.payloadKind = kind }
        advance(to: .payloadSent)
    }

    // MARK: - End

    /// A terminal event. Only the first is kept.
    func end(_ reason: EndReason) {
        guard phase != .ended, endReason == nil else { return }
        endReason = reason
    }

    /// Called once from `Session.close`, before the connections are cancelled; `fallback`
    /// applies when nothing ended the trace earlier.
    func finish(fallback: EndReason) {
        guard phase != .ended else { return }
        var reason = endReason ?? fallback
        // Only DNS errors, and DoH (if on) had no answer either: the name never resolved.
        if reason == .connectFailed(.dns), fields.dohIPs == nil { reason = .dnsFailed }
        endReason = reason
        let reached = phase
        phase = .ended
        fields.endedAt = clock()
        for i in fields.attempts.indices where fields.attempts[i].outcome == nil {
            fields.attempts[i].outcome = .cancelled
        }
        let summary = { [self] in
            TraceSummary(start: start, reached: reached, endReason: reason, fields: fields)
        }
        guard let pending = pendingTransfer else { return deliver(summary()) }
        pendingTransfer = nil
        pending.collect(queue: queue) { [self] info in
            fields.transfer.add(info)
            deliver(summary())
        }
        queue.asyncAfter(deadline: .now() + reportWait) { [self] in deliver(summary()) }
    }

    private func deliver(_ summary: TraceSummary) {
        guard let onFinish else { return }
        self.onFinish = nil
        reports = nil
        onFinish(summary)
    }
}

/// All calls on the relay's queue, the session queue (network-scanner plan §3).
extension ConnectionTrace: RelayObserver {
    func relayed(_ count: Int, fromLeft: Bool, prefix: Data) {
        guard phase != .ended else { return }
        let now = clock()
        if fromLeft {
            fields.bytesUp += count
            lastUpAt = now
            if fields.payloadSentAt == nil {
                fields.payloadSentAt = now
                if fields.payloadKind == nil { fields.payloadKind = PayloadSniffer.sniff(client: prefix) }
                advance(to: .payloadSent)
            }
        } else {
            fields.bytesDown += count
            lastDownAt = now
            if fields.firstDownAt == nil {
                fields.firstDownAt = now
                fields.firstDownPrefix = Data(prefix.prefix(Self.downPrefixLength))
                if fields.payloadKind == nil { fields.payloadKind = PayloadSniffer.sniff(server: prefix) }
                advance(to: .responding)
            }
        }
    }

    func relayEnded(_ event: RelayEndEvent) {
        end(event.endReason)
    }

    /// The stall check. It only observes; the client decides when to give up.
    func relayTick(now: UInt64) {
        guard phase != .ended, let sentAt = fields.payloadSentAt else { return }
        let lastUp = lastUpAt ?? sentAt
        let waitingOnServer = lastDownAt.map { lastUp > $0 } ?? true
        let silence = Self.seconds(now &- max(lastUp, lastDownAt ?? sentAt))

        if var stall = fields.stall {
            if !stall.resumed, fields.bytesDown > stall.bytesDownAtStall {
                // Data came back: not a freeze.
                stall.resumed = true
                fields.stall = stall
            }
        } else if waitingOnServer, silence >= DetectionConfig.stallSeconds {
            fields.stall = StallInfo(at: now, bytesDownAtStall: fields.bytesDown,
                                     phase: fields.firstDownAt == nil ? .beforeResponse : .midStream)
        }

        // §2.3 #1: a suspected hello blackhole is when the retransmit count is informative.
        if fields.firstDownAt == nil, !collectedEarly,
           Self.seconds(now &- sentAt) >= DetectionConfig.helloBlackholeMin,
           let pending = pendingTransfer, let reports {
            collectedEarly = true
            pending.collect(queue: queue) { [self] info in fields.transfer.add(info) }
            pendingTransfer = reports.startTransfer()
        }
    }

    private static func seconds(_ nanos: UInt64) -> TimeInterval { Double(nanos) / 1e9 }
}


enum TracePhase: Int, Comparable, Sendable {
    case created, resolving, connecting, connected, payloadSent, responding, ended

    static func < (lhs: TracePhase, rhs: TracePhase) -> Bool { lhs.rawValue < rhs.rawValue }
}

struct DialAttemptRecord: Equatable, Sendable {
    enum Outcome: Equatable, Sendable {
        case ready
        case failed(NWError)
        case cancelled
    }

    let address: String
    let startedAt: UInt64
    /// Nil while the attempt is running.
    var outcome: Outcome?
}

/// Why a traced connection ended (§2.1, terminal events).
enum EndReason: Equatable, Sendable {
    case connectFailed(ConnectError)
    /// Only DNS errors, and DoH had no answer.
    case dnsFailed
    case outlineConnectFailed
    case serverReset
    case serverError(Int32)
    case serverFin
    case clientClosed
    case idleTimeout
    /// U13: the user changed the rules. Never evidence of blocking.
    case rerouted
    /// Never evidence of blocking.
    case proxyStopped
}

enum ConnectError: Equatable, Sendable {
    case refused
    case unreachable
    case dns
    case timeout
    /// POSIX code (or DNS service error) of the last attempt; 0 when there was none.
    case other(Int32)

    /// From `DialError.allFailed`: refused beats unreachable beats DNS.
    init(_ errors: [NWError]) {
        func posix(_ error: NWError) -> POSIXErrorCode? {
            if case .posix(let code) = error { return code }
            return nil
        }
        if errors.contains(where: { posix($0) == .ECONNREFUSED }) {
            self = .refused
        } else if errors.contains(where: { posix($0) == .EHOSTUNREACH || posix($0) == .ENETUNREACH }) {
            self = .unreachable
        } else if !errors.isEmpty, errors.allSatisfy({ if case .dns = $0 { return true } else { return false } }) {
            self = .dns
        } else {
            self = .other(errors.last.map(Self.code) ?? 0)
        }
    }

    static func code(_ error: NWError) -> Int32 {
        switch error {
        case .posix(let code): return code.rawValue
        case .dns(let code): return code
        case .tls(let status): return status
        default: return -1  // newer SDKs add cases (Wi-Fi Aware)
        }
    }
}

/// What a trace recorded. Timestamps are `DispatchTime` uptime nanoseconds.
struct TraceFields: Sendable {
    var dnsStart: UInt64?
    var dnsEnd: UInt64?
    /// Nil when DoH was off or gave nothing.
    var dohIPs: [String]?
    var connectStart: UInt64?
    var connectEnd: UInt64?
    var connectedAddress: String?
    /// At most `ConnectionTrace.maxAttempts`, in start order. For the VPN route these are the
    /// Outline server's addresses.
    var attempts: [DialAttemptRecord] = []
    var establishment = EstablishmentInfo()
    var transfer = TransferInfo()
    var payloadSentAt: UInt64?
    /// Nil until the first payload in either direction.
    var payloadKind: PayloadKind?
    var applied: AppliedStrategy?
    var firstDownAt: UInt64?
    /// The first `ConnectionTrace.downPrefixLength` bytes from the server.
    var firstDownPrefix: Data?
    /// Relayed bytes; the first flight isn't counted.
    var bytesUp = 0
    var bytesDown = 0
    var stall: StallInfo?
    var endedAt: UInt64 = 0
}

/// Everything the trace recorded, handed to the observer once (§2.4). The recorded fields are
/// read straight through (`summary.dohIPs`).
@dynamicMemberLookup
struct TraceSummary: Sendable {
    let start: TraceStart
    /// The last phase before `ended`.
    let reached: TracePhase
    let endReason: EndReason
    let fields: TraceFields

    subscript<T>(dynamicMember keyPath: KeyPath<TraceFields, T>) -> T { fields[keyPath: keyPath] }

    /// `.none` when nothing was sent either way.
    var kind: PayloadKind { fields.payloadKind ?? .none }

    /// Handshake RTT, else the transport's minimum RTT.
    var rtt: TimeInterval? { fields.establishment.tcpRTT ?? fields.transfer.minimumRTT }
    /// Connect duration, a coarse stand-in for the RTT.
    var connectDuration: TimeInterval? { Self.interval(fields.connectStart, fields.connectEnd) }
    var tFirstDown: TimeInterval? { Self.interval(fields.payloadSentAt, fields.firstDownAt) }
    var tEnd: TimeInterval? { Self.interval(fields.payloadSentAt, fields.endedAt) }

    private static func interval(_ from: UInt64?, _ to: UInt64?) -> TimeInterval? {
        guard let from, let to, to >= from else { return nil }
        return Double(to - from) / 1e9
    }
}

/// Silence while waiting on the server (§3). Observed, never acted on.
struct StallInfo: Equatable, Sendable {
    enum Phase: Equatable, Sendable { case beforeResponse, midStream }

    let at: UInt64
    let bytesDownAtStall: Int
    let phase: Phase
    /// Data came back later: not a freeze.
    var resumed = false
}

/// What the session did with the first flight, next to the configured `TraceOutbound` (§2.5.3).
enum AppliedStrategy: Equatable, Sendable {
    case desync(DesyncParameters)
    case passthrough(PassthroughReason)
    case shadowsocks
}

enum PassthroughReason: Equatable, Sendable {
    /// A desync route, but the first flight wasn't a ClientHello.
    case notTLS
    /// A desync route, but the client didn't speak first.
    case clientSilent
    case plainHTTP
    /// Split mode `.none`.
    case splitNone
}

extension RelayEndEvent {
    var endReason: EndReason {
        switch self {
        case .readError(fromLeft: false, .posix(.ECONNRESET)): return .serverReset
        case .readError(fromLeft: false, let error): return .serverError(ConnectError.code(error))
        case .eof(fromLeft: false): return .serverFin
        case .readError(fromLeft: true, _), .eof(fromLeft: true), .writeError(toLeft: true, _): return .clientClosed
        case .writeError(toLeft: false, let error): return .serverError(ConnectError.code(error))
        case .idleTimeout: return .idleTimeout
        }
    }
}

extension OutboundError {
    var endReason: EndReason {
        switch self {
        case .dial(.allFailed(let errors)): return .connectFailed(ConnectError(errors))
        case .dial(.timeout): return .connectFailed(.timeout)
        case .dial(.cancelled): return .clientClosed
        case .shadowsocks: return .outlineConnectFailed
        }
    }
}

extension CloseReason {
    /// The trace's fallback end reason. No `default`, so a new close reason has to be mapped.
    var endReason: EndReason {
        switch self {
        case .connectFailed(let error): return error.endReason
        case .routeChanged: return .rerouted
        case .proxyStopped: return .proxyStopped
        case .idleTimeout: return .idleTimeout
        case .upstreamWriteFailed(let error), .firstFlightWriteFailed(let error):
            return .serverError(ConnectError.code(error))
        case .handshakeReadError, .clientClosedInHandshake, .handshakeFailed, .rejected,
             .clientClosedBeforeFirstFlight, .relayFinished, .clientWriteFailed, .deadline,
             .clientConnectionFailed, .clientConnectionCancelled:
            return .clientClosed
        }
    }
}
