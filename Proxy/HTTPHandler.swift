import Foundation
import Network
import os.log

/// Handles plain HTTP requests: connect to destination, forward the request, relay bidirectionally.
final class HTTPHandler {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "HTTP")

    private let settings: AppSettings
    private let resolverCache: DoHResolverCache
    private let dialer: Dialing
    private let session: SessionScope
    /// The session's serial queue: every connection, timer and callback of this session runs here.
    private let queue: DispatchQueue

    /// One handler per session; its callbacks keep it alive until the session ends.
    init(session: SessionScope, settings: AppSettings, resolverCache: DoHResolverCache, dialer: Dialing) {
        self.session = session
        self.queue = session.queue
        self.settings = settings
        self.resolverCache = resolverCache
        self.dialer = dialer
    }

    func handleRequest(
        clientConn: NWConnection,
        request: HTTPRequestLine,
        completion: @escaping () -> Void
    ) {
        let host = request.host
        let port = request.port
        let profile = settings.matchingProfile(for: host)
        let dohResolver = resolverCache.resolver(for: profile)

        Self.logger.info("HTTP \(request.method) -> \(host):\(port)")

        if profile.isVPNMissingConfig {
            Self.logger.error("[\(host)] VPN route has no Outline config, rejecting")
            let badGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
            clientConn.send(content: badGateway.data(using: .utf8), completion: .contentProcessed { _ in
                clientConn.cancel()
                completion()
            })
            return
        }

        // VPN mode: route through Outline/Shadowsocks server
        if profile.routeMode == .vpn, let outlineConfig = profile.outlineConfig {
            Self.logger.info("[\(host)] VPN mode, connecting via Outline...")
            let connectVPN = { (targetHost: String) in
                ShadowsocksStream.connect(config: outlineConfig, targetHost: targetHost, targetPort: port, dialer: self.dialer, session: self.session) { stream in
                    if let stream { self.session.adopt(stream) }
                    guard let stream = stream else {
                        Self.logger.error("[\(host)] Failed to connect to Outline server")
                        clientConn.cancel()
                        completion()
                        return
                    }

                    stream.send(content: request.rawData, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { error in
                        if let error = error {
                            Self.logger.error("[\(host)] Failed to send request via Outline: \(error.localizedDescription)")
                            stream.cancel()
                            clientConn.cancel()
                            completion()
                            return
                        }
                        ConnectionRelay.relay(left: clientConn, right: stream, label: host, queue: self.queue) {
                            stream.cancel()
                            completion()
                        }
                    })
                }
            }
            if let resolver = dohResolver {
                resolver.resolve(domain: host, on: self.queue) { ips in
                    connectVPN(ips.flatMap { ServerConnector.interleave($0).first } ?? host)
                }
            } else {
                connectVPN(host)
            }
            return
        }

        resolveAndConnect(host: host, port: port, dohResolver: dohResolver) { serverConn in
            guard let serverConn = serverConn else {
                Self.logger.error("Failed to connect to \(host):\(port)")
                clientConn.cancel()
                completion()
                return
            }

            // Forward the raw HTTP request to the server
            serverConn.send(content: request.rawData, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { error in
                if let error = error {
                    Self.logger.error("Failed to send request: \(error.localizedDescription)")
                    serverConn.cancel()
                    clientConn.cancel()
                    completion()
                    return
                }

                // Relay bidirectionally
                ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: self.queue) {
                    serverConn.cancel()
                    completion()
                }
            })
        }
    }

    private func resolveAndConnect(host: String, port: UInt16, dohResolver: Resolver?, completion: @escaping (NWConnection?) -> Void) {
        dialer.dial(DialTarget(host: host, port: port), resolver: dohResolver, session: session) { result in
            switch result {
            case .success(let conn):
                completion(conn)
            case .failure(let error):
                Self.logger.error("[\(host)] Server connect failed: \(error.description)")
                completion(nil)
            }
        }
    }
}
