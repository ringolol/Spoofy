import Foundation
import Network
import os.log

/// Handles CONNECT (HTTPS) requests: respond 200, read ClientHello,
/// fragment it via TLSDesyncer, send fragments to server, then relay.
/// Non-TLS first bytes, and silence (server-first protocols), are relayed unmodified.
final class HTTPSHandler {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "HTTPS")

    private let settings: AppSettings
    private let resolverCache: DoHResolverCache
    private let dialer: Dialing
    private let session: SessionScope
    /// How long a split-mode tunnel waits for the client to speak before relaying as-is (U7).
    private let firstByteTimeout: TimeInterval
    /// The session's serial queue: every connection, timer and callback of this session runs here.
    private let queue: DispatchQueue

    /// One handler per session; its callbacks keep it alive until the session ends.
    init(session: SessionScope, settings: AppSettings, resolverCache: DoHResolverCache, dialer: Dialing,
         firstByteTimeout: TimeInterval) {
        self.session = session
        self.firstByteTimeout = firstByteTimeout
        self.queue = session.queue
        self.settings = settings
        self.resolverCache = resolverCache
        self.dialer = dialer
    }

    func handleRequest(
        clientConn: NWConnection,
        host: String,
        port: UInt16,
        completion: @escaping () -> Void
    ) {
        let profile = settings.matchingProfile(for: host)
        let dohResolver = resolverCache.resolver(for: profile)

        Self.logger.info("[\(host)] CONNECT \(host):\(port) clientState=\(String(describing: clientConn.state))")

        if profile.isVPNMissingConfig {
            Self.logger.error("[\(host)] VPN route has no Outline config, rejecting")
            let badGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
            clientConn.send(content: badGateway.data(using: .utf8), completion: .contentProcessed { _ in
                clientConn.cancel()
                completion()
            })
            return
        }

        // Step 1: Send "200 Connection Established" to client
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n"
        clientConn.send(content: response.data(using: .utf8), contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { [self] error in
            if let error = error {
                Self.logger.error("[\(host)] Failed to send 200: \(error.localizedDescription)")
                clientConn.cancel()
                completion()
                return
            }

            Self.logger.info("[\(host)] Sent 200 OK, clientState=\(String(describing: clientConn.state))")

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
                        Self.logger.info("[\(host)] Outline connected, starting relay")
                        ConnectionRelay.relay(left: clientConn, right: stream, label: host, queue: self.queue) {
                            stream.cancel()
                            completion()
                        }
                    }
                }
                if let resolver = dohResolver {
                    resolver.resolve(domain: host, on: self.queue) { ips in
                        let resolved = ips.flatMap { ServerConnector.interleave($0).first } ?? host
                        if resolved != host { Self.logger.debug("[\(host)] DoH resolved to \(resolved)") }
                        connectVPN(resolved)
                    }
                } else {
                    connectVPN(host)
                }
                return
            }

            // If no fragmentation, skip TLS parsing and just do a blind relay
            if profile.splitMode == .none {
                Self.logger.info("[\(host)] Mode=none, connecting to server...")
                self.resolveAndConnect(host: host, port: port, dohResolver: dohResolver) { serverConn in
                    guard let serverConn = serverConn else {
                        Self.logger.error("[\(host)] Failed to connect to server")
                        clientConn.cancel()
                        completion()
                        return
                    }
                    Self.logger.info("[\(host)] Server connected, serverState=\(String(describing: serverConn.state)), starting blind relay")
                    ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: self.queue) {
                        serverConn.cancel()
                        completion()
                    }
                }
                return
            }

            // Step 2: Read the client's first flight (a ClientHello, or passthrough)
            Self.logger.info("[\(host)] Reading ClientHello...")
            let reader = FirstFlightReader(client: clientConn, queue: self.queue, firstByteTimeout: self.firstByteTimeout, label: host)
            reader.read { flight in
                guard let flight else {
                    clientConn.cancel()
                    completion()
                    return
                }
                self.connectAndSend(flight, reader: reader, clientConn: clientConn, host: host, port: port,
                                    profile: profile, dohResolver: dohResolver, completion: completion)
            }
        })
    }

    /// Dials, writes the (desynced) first flight, then relays. A failed write cancels both
    /// sides instead of relaying (N7).
    private func connectAndSend(
        _ flight: FirstFlight,
        reader: FirstFlightReader,
        clientConn: NWConnection,
        host: String,
        port: UInt16,
        profile: SpoofProfile,
        dohResolver: Resolver?,
        completion: @escaping () -> Void
    ) {
        resolveAndConnect(host: host, port: port, dohResolver: dohResolver) { [self] serverConn in
            guard let serverConn = serverConn else {
                Self.logger.error("[\(host)] Failed to connect to server")
                clientConn.cancel()
                completion()
                return
            }
            SegmentWriter.writeFirstFlight(flight, profile: profile, to: serverConn, label: host) { [self] error in
                if let error {
                    Self.logger.error("[\(host)] First flight send failed: \(error.localizedDescription)")
                    serverConn.cancel()
                    clientConn.cancel()
                    completion()
                    return
                }
                ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: queue,
                                      firstLeftReceive: reader.inFlightRead) {
                    serverConn.cancel()
                    completion()
                }
            }
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
