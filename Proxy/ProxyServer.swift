import Foundation
import Network
import os.log

/// Local HTTP and SOCKS5 proxy server: accepts connections and runs a `Session` for each.
///
/// Concurrency (plan §6.1): the listener, admission and the session registry live on the serial
/// `serverQueue`. Each accepted connection gets a `Session` with its own serial queue, and
/// everything that session does runs there. Both target the concurrent `ioRoot`, so sessions
/// still run in parallel.
final class ProxyServer {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "ProxyServer")
    static let maxConcurrentConnections = 200

    private let requestedPort: UInt16
    private let allowLANAccess: Bool
    private let ioRoot = DispatchQueue(label: "com.rnglol.Spoofy.io", qos: .userInitiated, attributes: .concurrent)
    private let serverQueue: DispatchQueue
    private let resolverCache: DoHResolverCache
    private let dialer: Dialing
    private let limits: Session.Limits

    // serverQueue only
    private var config: ProxyConfig
    private var listener: NWListener?
    private var sessions: [UInt64: Session] = [:]
    private var nextSessionID: UInt64 = 0

    /// Called if the listener fails after `start` has already reported its result.
    var onFailure: ((Error) -> Void)?

    /// The bound port once the listener is ready. Differs from the requested port when that was 0 (ephemeral).
    var port: UInt16? { serverQueue.sync { listener?.port?.rawValue } }

    /// Sessions currently admitted (for tests and diagnostics).
    var activeSessionCount: Int { serverQueue.sync { sessions.count } }

    /// The listener is bound to `config.port` and `config.allowLANAccess` for its lifetime;
    /// `update` changes routing only.
    init(config: ProxyConfig,
         resolverCache: DoHResolverCache = DoHResolverCache(), dialer: Dialing = ServerConnector(),
         limits: Session.Limits = Session.Limits()) {
        self.requestedPort = config.port
        self.allowLANAccess = config.allowLANAccess
        self.config = config
        self.limits = limits
        self.resolverCache = resolverCache
        self.dialer = dialer
        self.serverQueue = DispatchQueue(label: "com.rnglol.Spoofy.server", target: ioRoot)
    }

    /// `completion` is called exactly once: nil on the first `.ready`, or the startup error.
    /// Later listener failures go to `onFailure`.
    func start(completion: @escaping (Error?) -> Void) {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true

        let params = NWParameters(tls: nil, tcp: tcpOptions)
        let bindAddress: NWEndpoint.Host = allowLANAccess ? .ipv4(.any) : .ipv4(.loopback)
        params.requiredLocalEndpoint = NWEndpoint.hostPort(
            host: bindAddress,
            port: NWEndpoint.Port(rawValue: requestedPort)!
        )

        let listener: NWListener
        do {
            listener = try NWListener(using: params)
        } catch {
            completion(error)
            return
        }

        let startReported = LockedFlag()
        listener.stateUpdateHandler = { [weak listener] state in
            switch state {
            case .ready:
                // .ready can repeat (e.g. after .waiting on a network change); report it once.
                guard startReported.setIfFalse() else { return }
                let addr = self.allowLANAccess ? "0.0.0.0" : "127.0.0.1"
                let port = listener?.port?.rawValue ?? self.requestedPort
                Self.logger.info("Proxy listening on \(addr):\(port)")
                completion(nil)
            case .failed(let error):
                Self.logger.error("Listener failed: \(error.localizedDescription)")
                if startReported.setIfFalse() {
                    completion(error)
                } else {
                    self.onFailure?(error)
                }
            case .cancelled:
                Self.logger.info("Listener cancelled")
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            self?.admit(connection)
        }

        serverQueue.sync { self.listener = listener }
        listener.start(queue: serverQueue)
    }

    /// Stops listening and cancels every session, including their outbound connections (M2).
    /// Synchronous for the listener, so a following `start` on the same port can bind;
    /// sessions close asynchronously on their own queues. Never call it from `serverQueue`.
    func stop() {
        serverQueue.sync {
            self.listener?.cancel()
            self.listener = nil
            let open = Array(self.sessions.values)
            self.sessions.removeAll()
            for session in open {
                session.queue.async { session.close(.proxyStopped) }
            }
            Self.logger.info("Proxy server stopped, closed \(open.count, privacy: .public) sessions")
        }
    }

    /// Swaps the routing snapshot. New sessions use it; live sessions are re-routed against it
    /// and closed if their route changed (U13), so the client reconnects on the new route.
    /// Never call it from `serverQueue`.
    func update(_ config: ProxyConfig) {
        serverQueue.sync {
            self.config = config
            let router = Router(config: config)
            for session in self.sessions.values {
                session.queue.async { session.reroute(router) }
            }
        }
    }

    // MARK: - Sessions

    /// Runs on `serverQueue`, so the check and the insert can't interleave (M1).
    private func admit(_ clientConn: NWConnection) {
        guard sessions.count < Self.maxConcurrentConnections else {
            Self.logger.warning("Max connections reached (\(self.sessions.count, privacy: .public)), rejecting")
            clientConn.cancel()
            return
        }

        nextSessionID += 1
        let deps = Session.Dependencies(router: Router(config: config), limits: limits,
                                        dialer: dialer, resolverCache: resolverCache)
        let session = Session(id: nextSessionID, client: clientConn, target: ioRoot, deps: deps)
        sessions[session.id] = session
        Self.logger.info("Connection opened (active: \(self.sessions.count, privacy: .public))")

        session.onClose = { [weak self] in
            self?.serverQueue.async {
                guard let self, self.sessions.removeValue(forKey: session.id) != nil else { return }
                Self.logger.info("Connection closed (active: \(self.sessions.count, privacy: .public))")
            }
        }
        session.queue.async {
            session.accept()
            clientConn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    clientConn.stateUpdateHandler = nil
                    session.clientReady()
                case .failed(let error):
                    clientConn.stateUpdateHandler = nil
                    session.close(.clientConnectionFailed(error))
                case .cancelled:
                    clientConn.stateUpdateHandler = nil
                    session.close(.clientConnectionCancelled)
                default:
                    break
                }
            }
            clientConn.start(queue: session.queue)
        }
    }
}

/// Thread-safe cache of resolvers keyed by DoH server URL.
final class DoHResolverCache {
    private var cache: [String: Resolver] = [:]
    private let lock = NSLock()
    private let makeResolver: (String) -> Resolver

    /// `makeResolver` is injectable so tests can map names without a network.
    init(makeResolver: @escaping (String) -> Resolver = { DoHResolver(serverURL: $0) }) {
        self.makeResolver = makeResolver
    }

    func resolver(for profile: SpoofProfile) -> Resolver? {
        guard profile.dohEnabled else { return nil }
        let url = profile.dohServerURL
        lock.lock()
        defer { lock.unlock() }
        if let existing = cache[url] {
            return existing
        }
        let resolver = makeResolver(url)
        cache[url] = resolver
        return resolver
    }
}
