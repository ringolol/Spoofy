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
/// Of the terminal events the first wins; `finish` closes the trace and hands its summary on once.
final class ConnectionTrace {
    static let maxAttempts = 4

    let start: TraceStart
    private(set) var phase: TracePhase = .created

    private let onFinish: (TraceSummary) -> Void
    private var endReason: EndReason?
    private var dnsStart: UInt64?
    private var dnsEnd: UInt64?
    private var dohIPs: [String]?
    private var connectStart: UInt64?
    private var connectEnd: UInt64?
    private var connectedAddress: String?
    private var attempts: [DialAttemptRecord] = []

    init(_ start: TraceStart, onFinish: @escaping (TraceSummary) -> Void) {
        self.start = start
        self.onFinish = onFinish
    }

    private static func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    private func advance(to next: TracePhase) {
        if next > phase { phase = next }
    }

    // MARK: - Dial (ServerConnector, ShadowsocksOutbound)

    /// The resolver (DoH) was asked about the target name.
    func dnsStarted() {
        guard phase != .ended else { return }
        if dnsStart == nil { dnsStart = Self.now() }
        advance(to: .resolving)
    }

    /// Nil or empty: DoH gave nothing and the system resolver takes over.
    func dnsFinished(ips: [String]?) {
        guard phase != .ended else { return }
        dnsEnd = Self.now()
        dohIPs = ips.flatMap { $0.isEmpty ? nil : $0 }
    }

    func attemptStarted(_ address: String) {
        guard phase != .ended else { return }
        let now = Self.now()
        if connectStart == nil { connectStart = now }
        if attempts.count < Self.maxAttempts {
            attempts.append(DialAttemptRecord(address: address, startedAt: now, outcome: nil))
        }
        advance(to: .connecting)
    }

    func attemptFailed(_ address: String, _ error: NWError) {
        settle(address, .failed(error))
    }

    func attemptCancelled(_ address: String) {
        settle(address, .cancelled)
    }

    func attemptReady(_ address: String) {
        guard phase != .ended else { return }
        settle(address, .ready)
        connectEnd = Self.now()
        connectedAddress = address
        advance(to: .connected)
    }

    private func settle(_ address: String, _ outcome: DialAttemptRecord.Outcome) {
        guard phase != .ended,
              let index = attempts.lastIndex(where: { $0.address == address && $0.outcome == nil }) else { return }
        attempts[index].outcome = outcome
    }

    // MARK: - End

    /// A terminal event. Only the first is kept.
    func end(_ reason: EndReason) {
        guard phase != .ended, endReason == nil else { return }
        endReason = reason
    }

    /// Called once from `Session.close`; `fallback` applies when nothing ended the trace earlier.
    func finish(fallback: EndReason) {
        guard phase != .ended else { return }
        var reason = endReason ?? fallback
        // Only DNS errors, and DoH (if on) had no answer either: the name never resolved.
        if reason == .connectFailed(.dns), dohIPs == nil { reason = .dnsFailed }
        let reached = phase
        phase = .ended
        for i in attempts.indices where attempts[i].outcome == nil {
            attempts[i].outcome = .cancelled
        }
        onFinish(TraceSummary(start: start, reached: reached, endReason: reason, endedAt: Self.now(),
                              dnsStart: dnsStart, dnsEnd: dnsEnd, dohIPs: dohIPs,
                              connectStart: connectStart, connectEnd: connectEnd,
                              connectedAddress: connectedAddress, attempts: attempts))
    }
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

/// Everything the trace recorded, handed to the observer once at `finish`. Timestamps are
/// `DispatchTime` uptime nanoseconds.
struct TraceSummary: Sendable {
    let start: TraceStart
    /// The last phase before `ended`.
    let reached: TracePhase
    let endReason: EndReason
    let endedAt: UInt64
    let dnsStart: UInt64?
    let dnsEnd: UInt64?
    /// Nil when DoH was off or gave nothing.
    let dohIPs: [String]?
    let connectStart: UInt64?
    let connectEnd: UInt64?
    let connectedAddress: String?
    /// At most `ConnectionTrace.maxAttempts`, in start order. For the VPN route these are the
    /// Outline server's addresses.
    let attempts: [DialAttemptRecord]
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
