import Foundation
import Network
import os.log

/// A host to dial: a name, or an IPv4/IPv6 literal (without brackets).
struct DialTarget: Hashable {
    let host: String
    let port: UInt16
}

enum DialError: Error, CustomStringConvertible {
    /// Every address failed; one error per attempt, in start order.
    case allFailed([NWError])
    /// No attempt became ready within the connect timeout.
    case timeout
    /// The session closed while dialing.
    case cancelled

    var description: String {
        switch self {
        case .allFailed(let errors): return "all \(errors.count) attempt(s) failed: \(errors.map(\.localizedDescription))"
        case .timeout: return "connect timed out"
        case .cancelled: return "cancelled"
        }
    }
}

/// Name → addresses. `completion` runs on `queue`; nil or empty means "not resolved",
/// and the dialer falls back to the system resolver.
protocol Resolver: AnyObject {
    func resolve(domain: String, on queue: DispatchQueue, completion: @escaping ([String]?) -> Void)
}

protocol Dialing {
    /// Resolves (via `resolver`, else the system) and connects. Runs entirely on `session.queue`,
    /// every attempt is adopted by `session`, and `completion` is called exactly once on that queue.
    func dial(_ target: DialTarget, resolver: Resolver?, session: SessionScope,
              completion: @escaping (Result<NWConnection, DialError>) -> Void)
}

/// The single dial implementation (plan §6.2; network-scanner §1). Replaces the three
/// copied `resolveAndConnect` / `waitForReady` helpers and the Shadowsocks server connect.
final class ServerConnector: Dialing {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Connector")

    private let connectTimeout: TimeInterval
    private let stagger: TimeInterval

    init(connectTimeout: TimeInterval = 10, stagger: TimeInterval = 0.25) {
        self.connectTimeout = connectTimeout
        self.stagger = stagger
    }

    func dial(_ target: DialTarget, resolver: Resolver?, session: SessionScope,
              completion: @escaping (Result<NWConnection, DialError>) -> Void) {
        let attempt = DialAttempt(target: target, session: session, connectTimeout: connectTimeout,
                                  stagger: stagger, completion: completion)
        // N10: an IP literal needs no lookup.
        if Self.isIPLiteral(target.host) || resolver == nil {
            attempt.start(hosts: [target.host])
            return
        }
        session.trace?.dnsStarted()
        resolver?.resolve(domain: target.host, on: session.queue) { ips in
            session.trace?.dnsFinished(ips: ips)
            guard let ips, !ips.isEmpty else {
                Self.logger.debug("[\(target.host)] DoH gave no addresses, using the system resolver")
                attempt.start(hosts: [target.host])
                return
            }
            attempt.start(hosts: Self.interleave(ips))
        }
    }

    static func isIPLiteral(_ host: String) -> Bool {
        IPv4Address(host) != nil || IPv6Address(host) != nil
    }

    /// RFC 8305-lite: alternate families, IPv4 first. Order within a family is kept.
    static func interleave(_ ips: [String]) -> [String] {
        let v4 = ips.filter { IPv4Address($0) != nil }
        let v6 = ips.filter { IPv4Address($0) == nil }
        var out: [String] = []
        for i in 0..<max(v4.count, v6.count) {
            if i < v4.count { out.append(v4[i]) }
            if i < v6.count { out.append(v6[i]) }
        }
        return out
    }

    static func makeParameters() -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        // Always: Nagle would merge the segments a desync splits on purpose.
        tcp.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcp)
        params.preferNoProxies = true
        return params
    }
}

/// One dial: a staggered race over `hosts`. All state is touched only on `session.queue`.
private final class DialAttempt {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Connector")

    private let target: DialTarget
    private let session: SessionScope
    private let connectTimeout: TimeInterval
    private let stagger: TimeInterval
    private var completion: ((Result<NWConnection, DialError>) -> Void)?

    private var pending: [String] = []
    /// Attempts started and not yet finished.
    private var live: [ObjectIdentifier: NWConnection] = [:]
    private var errors: [NWError] = []
    private var staggerGeneration = 0

    init(target: DialTarget, session: SessionScope, connectTimeout: TimeInterval, stagger: TimeInterval,
         completion: @escaping (Result<NWConnection, DialError>) -> Void) {
        self.target = target
        self.session = session
        self.connectTimeout = connectTimeout
        self.stagger = stagger
        self.completion = completion
    }

    func start(hosts: [String]) {
        guard !session.isClosed else { return finish(.failure(.cancelled)) }
        pending = hosts
        // Weak: once finished, nothing should keep the attempt (and its session) alive.
        session.queue.asyncAfter(deadline: .now() + connectTimeout) { [weak self] in
            guard let self, completion != nil else { return }
            Self.logger.warning("[\(target.host)] connect timeout")
            finish(.failure(.timeout))
        }
        startNext()
    }

    private func startNext() {
        guard completion != nil else { return }
        guard !session.isClosed else { return finish(.failure(.cancelled)) }
        guard !pending.isEmpty else {
            if live.isEmpty { finish(.failure(errors.isEmpty ? .cancelled : .allFailed(errors))) }
            return
        }
        let host = pending.removeFirst()
        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: target.port)!,
                                using: ServerConnector.makeParameters())
        let id = ObjectIdentifier(conn)
        live[id] = conn
        session.adopt(conn)
        session.trace?.attemptStarted(host)
        conn.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                guard live.removeValue(forKey: id) != nil else { return }
                conn.stateUpdateHandler = nil
                session.trace?.attemptReady(host)
                finish(.success(conn))
            case .failed(let error), .waiting(let error):
                // N11: .waiting is a failure for this address, not something to sit out.
                guard live.removeValue(forKey: id) != nil else { return }
                Self.logger.debug("[\(self.target.host)] \(host) failed: \(error.localizedDescription)")
                errors.append(error)
                session.trace?.attemptFailed(host, error)
                conn.stateUpdateHandler = nil
                conn.cancel()
                startNext()
            case .cancelled:
                // Cancelled from outside (the session closed): this attempt is over.
                guard live.removeValue(forKey: id) != nil else { return }
                session.trace?.attemptCancelled(host)
                startNext()
            default:
                break
            }
        }
        conn.start(queue: session.queue)

        guard !pending.isEmpty else { return }
        staggerGeneration += 1
        let generation = staggerGeneration
        session.queue.asyncAfter(deadline: .now() + stagger) { [weak self] in
            // Only if nothing else started an attempt in the meantime.
            guard let self, generation == staggerGeneration else { return }
            startNext()
        }
    }

    private func finish(_ result: Result<NWConnection, DialError>) {
        guard let completion else { return }
        self.completion = nil
        pending = []
        for conn in live.values {
            conn.stateUpdateHandler = nil
            conn.cancel()
        }
        live = [:]
        completion(result)
    }
}
