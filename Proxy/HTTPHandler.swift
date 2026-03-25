import Foundation
import Network
import os.log

/// Handles plain HTTP requests: connect to destination, forward the request, relay bidirectionally.
final class HTTPHandler {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "HTTP")

    private let settings: AppSettings
    private let resolverCache: DoHResolverCache
    private let queue: DispatchQueue

    init(queue: DispatchQueue, settings: AppSettings, resolverCache: DoHResolverCache) {
        self.queue = queue
        self.settings = settings
        self.resolverCache = resolverCache
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

        // VPN mode: route through Outline/Shadowsocks server
        if profile.routeMode == .vpn, let outlineConfig = profile.outlineConfig {
            Self.logger.info("[\(host)] VPN mode, connecting via Outline...")
            let connectVPN = { (targetHost: String) in
                ShadowsocksStream.connect(config: outlineConfig, targetHost: targetHost, targetPort: port, queue: self.queue) { stream in
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
                resolver.resolve(domain: host) { ips in
                    connectVPN(ips?.first ?? host)
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

    private func resolveAndConnect(host: String, port: UInt16, dohResolver: DoHResolver?, completion: @escaping (NWConnection?) -> Void) {
        if let resolver = dohResolver {
            resolver.resolve(domain: host) { ips in
                let targetHost: NWEndpoint.Host
                if let ip = ips?.first {
                    targetHost = NWEndpoint.Host(ip)
                } else {
                    targetHost = NWEndpoint.Host(host)
                }
                let conn = self.createConnection(host: targetHost, port: port)
                self.waitForReady(conn: conn, completion: completion)
            }
        } else {
            let conn = createConnection(host: NWEndpoint.Host(host), port: port)
            waitForReady(conn: conn, completion: completion)
        }
    }

    private func createConnection(host: NWEndpoint.Host, port: UInt16) -> NWConnection {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcpOptions)
        params.preferNoProxies = true
        return NWConnection(
            host: host,
            port: NWEndpoint.Port(rawValue: port)!,
            using: params
        )
    }

    private func waitForReady(conn: NWConnection, completion: @escaping (NWConnection?) -> Void) {
        let completed = LockedFlag()

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.stateUpdateHandler = nil
                guard completed.setIfFalse() else { return }
                completion(conn)
            case .failed, .cancelled:
                conn.stateUpdateHandler = nil
                guard completed.setIfFalse() else { return }
                conn.cancel()
                completion(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)

        // Timeout: if connection doesn't become ready within 10 seconds, give up
        queue.asyncAfter(deadline: .now() + 10) {
            guard completed.setIfFalse() else { return }
            conn.stateUpdateHandler = nil
            conn.cancel()
            completion(nil)
        }
    }
}
