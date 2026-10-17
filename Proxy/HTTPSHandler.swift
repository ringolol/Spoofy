import Foundation
import Network
import os.log

/// Handles CONNECT (HTTPS) requests: respond 200, read ClientHello,
/// fragment it via TLSDesyncer, send fragments to server, then relay.
final class HTTPSHandler {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "HTTPS")

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

            // Step 2: Read ClientHello from client
            Self.logger.info("[\(host)] Reading ClientHello...")
            self.readClientHello(from: clientConn, host: host, port: port, profile: profile, dohResolver: dohResolver, completion: completion)
        })
    }

    private func readClientHello(
        from clientConn: NWConnection,
        host: String,
        port: UInt16,
        profile: SpoofProfile,
        dohResolver: Resolver?,
        completion: @escaping () -> Void
    ) {
        clientConn.receive(minimumIncompleteLength: 5, maximumLength: 16389) { [self] content, contentContext, isComplete, error in
            if let error = error {
                Self.logger.error("[\(host)] ClientHello read error: \(error.localizedDescription)")
                clientConn.cancel()
                completion()
                return
            }

            Self.logger.info("[\(host)] ClientHello read: \(content?.count ?? 0) bytes, isComplete=\(isComplete)")

            guard let data = content, !data.isEmpty else {
                Self.logger.warning("[\(host)] Empty ClientHello, closing")
                clientConn.cancel()
                completion()
                return
            }

            self.ensureFullTLSRecord(data: data, from: clientConn, host: host) { fullData in
                guard let fullData = fullData else {
                    clientConn.cancel()
                    completion()
                    return
                }

                self.processClientHello(
                    data: fullData,
                    clientConn: clientConn,
                    host: host,
                    port: port,
                    profile: profile,
                    dohResolver: dohResolver,
                    completion: completion
                )
            }
        }
    }

    private func ensureFullTLSRecord(
        data: Data,
        from conn: NWConnection,
        host: String,
        completion: @escaping (Data?) -> Void
    ) {
        guard data.count >= 5 else {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 16389 - data.count) { more, _, _, error in
                if let error = error {
                    Self.logger.debug("[\(host)] Error reading more TLS data: \(error.localizedDescription)")
                    completion(nil)
                    return
                }
                guard let more = more else {
                    completion(nil)
                    return
                }
                var combined = data
                combined.append(more)
                self.ensureFullTLSRecord(data: combined, from: conn, host: host, completion: completion)
            }
            return
        }

        let payloadLen = Int(data.readUInt16(at: 3))
        let totalLen = 5 + payloadLen

        if data.count >= totalLen {
            completion(data)
            return
        }

        let remaining = totalLen - data.count
        Self.logger.debug("[\(host)] Need \(remaining) more bytes for TLS record")

        conn.receive(minimumIncompleteLength: remaining, maximumLength: remaining) { more, _, _, error in
            if let error = error {
                Self.logger.debug("[\(host)] Error reading TLS payload: \(error.localizedDescription)")
                completion(nil)
                return
            }
            guard let more = more else {
                completion(nil)
                return
            }
            var combined = data
            combined.append(more)
            completion(combined)
        }
    }

    private func processClientHello(
        data: Data,
        clientConn: NWConnection,
        host: String,
        port: UInt16,
        profile: SpoofProfile,
        dohResolver: Resolver?,
        completion: @escaping () -> Void
    ) {
        guard let tlsMsg = TLSMessage.parse(from: data) else {
            Self.logger.warning("[\(host)] Failed to parse TLS, forwarding \(data.count) raw bytes")
            connectAndForward(rawData: data, clientConn: clientConn, host: host, port: port, dohResolver: dohResolver, completion: completion)
            return
        }

        guard tlsMsg.isClientHello else {
            Self.logger.warning("[\(host)] Not a ClientHello (type=\(tlsMsg.header.type_.rawValue)), forwarding raw")
            connectAndForward(rawData: data, clientConn: clientConn, host: host, port: port, dohResolver: dohResolver, completion: completion)
            return
        }

        let mode = profile.splitMode
        let chunkSize = profile.chunkSize
        let sniOffset = tlsMsg.extractSNIOffset()

        let segments = TLSDesyncer.split(
            raw: tlsMsg.raw,
            mode: mode,
            chunkSize: chunkSize,
            sniOffset: sniOffset,
            tlsRecordFragmentation: profile.tlsRecordFragmentation
        )

        Self.logger.info("[\(host)] ClientHello \(tlsMsg.raw.count)B → \(segments.count) segments (mode=\(mode.rawValue), sniOffset=\(String(describing: sniOffset)))")

        let extraData: Data? = data.count > tlsMsg.raw.count
            ? Data(data.dropFirst(tlsMsg.raw.count))
            : nil

        Self.logger.info("[\(host)] Connecting to server...")

        resolveAndConnect(host: host, port: port, dohResolver: dohResolver) { [self] serverConn in
            guard let serverConn = serverConn else {
                Self.logger.error("[\(host)] Failed to connect to server")
                clientConn.cancel()
                completion()
                return
            }

            Self.logger.info("[\(host)] Server connected, sending \(segments.count) segments...")

            self.sendSegments(segments, to: serverConn, index: 0) { [self] in
                Self.logger.info("[\(host)] All segments sent, starting relay")

                if let extra = extraData {
                    Self.logger.info("[\(host)] Sending \(extra.count) extra bytes first")
                    serverConn.send(content: extra, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { [self] _ in
                        ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: queue) {
                            serverConn.cancel()
                            completion()
                        }
                    })
                } else {
                    ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: queue) {
                        serverConn.cancel()
                        completion()
                    }
                }
            }
        }
    }

    /// Send segments sequentially, waiting for each to be processed before sending the next.
    /// With TCP_NODELAY, each send flushes to a separate TCP packet, which is critical
    /// for DPI bypass — the SNI must be split across distinct TCP segments.
    private func sendSegments(_ segments: [Data], to conn: NWConnection, index: Int, completion: @escaping () -> Void) {
        guard index < segments.count else {
            completion()
            return
        }

        conn.send(content: segments[index], contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { [self] error in
            if let error = error {
                Self.logger.error("Failed to send segment \(index): \(error.localizedDescription)")
                completion()
                return
            }
            self.sendSegments(segments, to: conn, index: index + 1, completion: completion)
        })
    }

    private func connectAndForward(
        rawData: Data,
        clientConn: NWConnection,
        host: String,
        port: UInt16,
        dohResolver: Resolver?,
        completion: @escaping () -> Void
    ) {
        resolveAndConnect(host: host, port: port, dohResolver: dohResolver) { serverConn in
            guard let serverConn = serverConn else {
                clientConn.cancel()
                completion()
                return
            }

            serverConn.send(content: rawData, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { [self] _ in
                ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: queue) {
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
