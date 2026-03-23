import Foundation
import Network
import os.log

/// Local HTTP proxy server that accepts connections and dispatches to HTTP/HTTPS handlers.
final class ProxyServer {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "ProxyServer")
    private static let maxConcurrentConnections = 200

    private let port: UInt16
    private let settings: AppSettings
    private var listener: NWListener?
    private let httpHandler: HTTPHandler
    private let httpsHandler: HTTPSHandler
    private let activeConnections = AtomicCounter()
    private let proxyQueue = DispatchQueue(label: "com.rnglol.Spoofy.proxy", qos: .userInitiated, attributes: .concurrent)
    private let resolverCache = DoHResolverCache()

    init(port: UInt16, settings: AppSettings) {
        self.port = port
        self.settings = settings
        self.httpHandler = HTTPHandler(queue: proxyQueue, settings: settings, resolverCache: resolverCache)
        self.httpsHandler = HTTPSHandler(queue: proxyQueue, settings: settings, resolverCache: resolverCache)
    }

    func start(completion: @escaping (Error?) -> Void) {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true

        let params = NWParameters(tls: nil, tcp: tcpOptions)
        let bindAddress: NWEndpoint.Host = settings.allowLANAccess ? .ipv4(.any) : .ipv4(.loopback)
        params.requiredLocalEndpoint = NWEndpoint.hostPort(
            host: bindAddress,
            port: NWEndpoint.Port(rawValue: port)!
        )

        do {
            listener = try NWListener(using: params)
        } catch {
            completion(error)
            return
        }

        listener?.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let addr = self.settings.allowLANAccess ? "0.0.0.0" : "127.0.0.1"
                Self.logger.info("Proxy listening on \(addr):\(self.port)")
                completion(nil)
            case .failed(let error):
                Self.logger.error("Listener failed: \(error.localizedDescription)")
                completion(error)
            case .cancelled:
                Self.logger.info("Listener cancelled")
            default:
                break
            }
        }

        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleNewConnection(connection)
        }

        listener?.start(queue: proxyQueue)
    }

    func stop() {
        listener?.cancel()
        listener = nil
        Self.logger.info("Proxy server stopped")
    }

    private func handleNewConnection(_ clientConn: NWConnection) {
        guard activeConnections.value < Self.maxConcurrentConnections else {
            Self.logger.warning("Max connections reached, rejecting")
            clientConn.cancel()
            return
        }

        activeConnections.increment()

        clientConn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                // Clear state handler before dispatching to avoid interference
                clientConn.stateUpdateHandler = nil
                self?.readRequest(from: clientConn)
            case .failed, .cancelled:
                clientConn.stateUpdateHandler = nil
                self?.activeConnections.decrement()
            default:
                break
            }
        }

        clientConn.start(queue: proxyQueue)
    }

    private func closeConnection(_ clientConn: NWConnection) {
        clientConn.cancel()
        activeConnections.decrement()
    }

    private func readRequest(from clientConn: NWConnection) {
        // Read enough for an HTTP request line + headers
        clientConn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] content, _, _, error in
            guard let self = self else { return }

            if let error = error {
                Self.logger.debug("Read error: \(error.localizedDescription)")
                self.closeConnection(clientConn)
                return
            }

            guard let data = content, !data.isEmpty else {
                self.closeConnection(clientConn)
                return
            }

            guard let request = HTTPRequestLine.parse(from: data) else {
                Self.logger.debug("Failed to parse HTTP request")
                let badRequest = "HTTP/1.1 400 Bad Request\r\n\r\n"
                clientConn.send(content: badRequest.data(using: .utf8), completion: .contentProcessed { _ in
                    self.closeConnection(clientConn)
                })
                return
            }

            guard request.isValidMethod else {
                Self.logger.debug("Invalid method: \(request.method)")
                let notImpl = "HTTP/1.1 501 Not Implemented\r\n\r\n"
                clientConn.send(content: notImpl.data(using: .utf8), completion: .contentProcessed { _ in
                    self.closeConnection(clientConn)
                })
                return
            }

            if request.isConnect {
                self.httpsHandler.handleRequest(
                    clientConn: clientConn,
                    host: request.host,
                    port: request.port
                ) {
                    self.closeConnection(clientConn)
                }
            } else {
                self.httpHandler.handleRequest(
                    clientConn: clientConn,
                    request: request
                ) {
                    self.closeConnection(clientConn)
                }
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

/// Simple thread-safe counter for tracking active connections.
final class AtomicCounter {
    private var _value: Int = 0
    private let lock = NSLock()

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return _value
    }

    func increment() {
        lock.lock()
        _value += 1
        lock.unlock()
    }

    func decrement() {
        lock.lock()
        _value -= 1
        lock.unlock()
    }
}
