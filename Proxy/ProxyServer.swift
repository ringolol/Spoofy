import Foundation
import Network
import os.log

/// Local HTTP proxy server that accepts connections and dispatches to HTTP/HTTPS handlers.
///
/// Concurrency (plan §6.1): the listener, admission and the session registry live on the serial
/// `serverQueue`. Each accepted connection gets a `SessionScope` with its own serial queue, and
/// everything that session does runs there. Both target the concurrent `ioRoot`, so sessions
/// still run in parallel.
final class ProxyServer {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "ProxyServer")
    static let maxConcurrentConnections = 200

    private let requestedPort: UInt16
    private let settings: AppSettings
    private let ioRoot = DispatchQueue(label: "com.rnglol.Spoofy.io", qos: .userInitiated, attributes: .concurrent)
    private let serverQueue: DispatchQueue
    private let resolverCache = DoHResolverCache()

    // serverQueue only
    private var listener: NWListener?
    private var sessions: [UInt64: SessionScope] = [:]
    private var nextSessionID: UInt64 = 0

    /// Called if the listener fails after `start` has already reported its result.
    var onFailure: ((Error) -> Void)?

    /// The bound port once the listener is ready. Differs from the requested port when that was 0 (ephemeral).
    var port: UInt16? { serverQueue.sync { listener?.port?.rawValue } }

    /// Sessions currently admitted (for tests and diagnostics).
    var activeSessionCount: Int { serverQueue.sync { sessions.count } }

    init(port: UInt16, settings: AppSettings) {
        self.requestedPort = port
        self.settings = settings
        self.serverQueue = DispatchQueue(label: "com.rnglol.Spoofy.server", target: ioRoot)
    }

    /// `completion` is called exactly once: nil on the first `.ready`, or the startup error.
    /// Later listener failures go to `onFailure`.
    func start(completion: @escaping (Error?) -> Void) {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true

        let params = NWParameters(tls: nil, tcp: tcpOptions)
        let bindAddress: NWEndpoint.Host = settings.allowLANAccess ? .ipv4(.any) : .ipv4(.loopback)
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
                let addr = self.settings.allowLANAccess ? "0.0.0.0" : "127.0.0.1"
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
                session.queue.async { session.close() }
            }
            Self.logger.info("Proxy server stopped, closed \(open.count, privacy: .public) sessions")
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
        let session = SessionScope(id: nextSessionID, target: ioRoot)
        sessions[session.id] = session
        Self.logger.info("Connection opened (active: \(self.sessions.count, privacy: .public))")

        session.queue.async {
            session.adopt(clientConn)
            clientConn.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    // Clear state handler before dispatching to avoid interference
                    clientConn.stateUpdateHandler = nil
                    self?.readRequest(from: clientConn, session: session)
                case .failed, .cancelled:
                    clientConn.stateUpdateHandler = nil
                    self?.closeSession(session)
                default:
                    break
                }
            }
            clientConn.start(queue: session.queue)
        }
    }

    /// Runs on the session's queue. Safe to call more than once.
    private func closeSession(_ session: SessionScope) {
        session.close()
        serverQueue.async {
            guard self.sessions.removeValue(forKey: session.id) != nil else { return }
            Self.logger.info("Connection closed (active: \(self.sessions.count, privacy: .public))")
        }
    }

    private func readRequest(from clientConn: NWConnection, session: SessionScope) {
        let closeConnection = { [weak self] in
            clientConn.cancel()
            if let self {
                self.closeSession(session)
            } else {
                session.close()
            }
        }

        // Read enough for an HTTP request line + headers
        clientConn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] content, _, _, error in
            guard let self = self else {
                closeConnection()
                return
            }

            if let error = error {
                Self.logger.debug("Read error: \(error.localizedDescription)")
                closeConnection()
                return
            }

            guard let data = content, !data.isEmpty else {
                closeConnection()
                return
            }

            // SOCKS5 greeting starts with version byte 0x05; HTTP always starts with ASCII letter
            if data[0] == 0x05 {
                SOCKS5Handler(session: session, settings: self.settings, resolverCache: self.resolverCache)
                    .handleGreeting(clientConn: clientConn, data: data, completion: closeConnection)
                return
            }

            guard let request = HTTPRequestLine.parse(from: data) else {
                Self.logger.debug("Failed to parse HTTP request")
                let badRequest = "HTTP/1.1 400 Bad Request\r\n\r\n"
                clientConn.send(content: badRequest.data(using: .utf8), completion: .contentProcessed { _ in
                    closeConnection()
                })
                return
            }

            guard request.isValidMethod else {
                Self.logger.debug("Invalid method: \(request.method)")
                let notImpl = "HTTP/1.1 501 Not Implemented\r\n\r\n"
                clientConn.send(content: notImpl.data(using: .utf8), completion: .contentProcessed { _ in
                    closeConnection()
                })
                return
            }

            if request.isConnect {
                HTTPSHandler(session: session, settings: self.settings, resolverCache: self.resolverCache)
                    .handleRequest(clientConn: clientConn, host: request.host, port: request.port, completion: closeConnection)
            } else {
                HTTPHandler(session: session, settings: self.settings, resolverCache: self.resolverCache)
                    .handleRequest(clientConn: clientConn, request: request, completion: closeConnection)
            }
        }
    }
}

/// Thread-safe cache of DoHResolver instances keyed by server URL.
final class DoHResolverCache {
    private var cache: [String: DoHResolver] = [:]
    private let lock = NSLock()

    func resolver(for profile: SpoofProfile) -> DoHResolver? {
        guard profile.dohEnabled else { return nil }
        let url = profile.dohServerURL
        lock.lock()
        defer { lock.unlock() }
        if let existing = cache[url] {
            return existing
        }
        let resolver = DoHResolver(serverURL: url)
        cache[url] = resolver
        return resolver
    }
}
