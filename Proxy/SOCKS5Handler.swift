import Foundation
import Network
import os.log

/// Handles SOCKS5 connections: greeting, connect request, then relay
/// with the same VPN/split/none routing as HTTPSHandler.
final class SOCKS5Handler {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "SOCKS5")

    private let settings: AppSettings
    private let resolverCache: DoHResolverCache
    private let queue: DispatchQueue

    init(queue: DispatchQueue, settings: AppSettings, resolverCache: DoHResolverCache) {
        self.queue = queue
        self.settings = settings
        self.resolverCache = resolverCache
    }

    // MARK: - Phase 1: Greeting

    /// Handle a SOCKS5 greeting. The first chunk (containing version + methods) is already read.
    func handleGreeting(
        clientConn: NWConnection,
        data: Data,
        completion: @escaping () -> Void
    ) {
        // Minimum greeting: [0x05, nMethods(1), method(1)] = 3 bytes
        guard data.count >= 3, data[0] == 0x05 else {
            Self.logger.debug("Invalid SOCKS5 greeting")
            clientConn.cancel()
            completion()
            return
        }

        let nMethods = Int(data[1])
        let methodsEnd = 2 + nMethods

        // If we haven't read all method bytes yet, read the rest
        if data.count < methodsEnd {
            clientConn.receive(minimumIncompleteLength: methodsEnd - data.count, maximumLength: 257) { [self] more, _, _, error in
                if let error = error {
                    Self.logger.debug("Greeting read error: \(error.localizedDescription)")
                    clientConn.cancel()
                    completion()
                    return
                }
                guard let more = more else {
                    clientConn.cancel()
                    completion()
                    return
                }
                var combined = data
                combined.append(more)
                self.processGreeting(clientConn: clientConn, data: combined, nMethods: nMethods, completion: completion)
            }
            return
        }

        processGreeting(clientConn: clientConn, data: data, nMethods: nMethods, completion: completion)
    }

    private func processGreeting(
        clientConn: NWConnection,
        data: Data,
        nMethods: Int,
        completion: @escaping () -> Void
    ) {
        let methods = Array(data[2..<(2 + nMethods)])

        // Check if no-auth (0x00) is offered
        guard methods.contains(0x00) else {
            Self.logger.debug("No acceptable auth method (client offered: \(methods))")
            let reply = Data([0x05, 0xFF]) // no acceptable methods
            clientConn.send(content: reply, completion: .contentProcessed { _ in
                clientConn.cancel()
                completion()
            })
            return
        }

        // Accept no-auth
        let reply = Data([0x05, 0x00])
        clientConn.send(content: reply, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { [self] error in
            if let error = error {
                Self.logger.debug("Failed to send greeting reply: \(error.localizedDescription)")
                clientConn.cancel()
                completion()
                return
            }
            self.readConnectRequest(from: clientConn, completion: completion)
        })
    }

    // MARK: - Phase 2: Connect Request

    private func readConnectRequest(
        from clientConn: NWConnection,
        completion: @escaping () -> Void
    ) {
        // Read connect request: min 10 bytes (ver + cmd + rsv + atyp + IPv4(4) + port(2))
        clientConn.receive(minimumIncompleteLength: 4, maximumLength: 512) { [self] content, _, _, error in
            if let error = error {
                Self.logger.debug("Connect request read error: \(error.localizedDescription)")
                clientConn.cancel()
                completion()
                return
            }

            guard let data = content, data.count >= 4 else {
                clientConn.cancel()
                completion()
                return
            }

            guard data[0] == 0x05 else {
                Self.logger.debug("Bad SOCKS version in connect: \(data[0])")
                clientConn.cancel()
                completion()
                return
            }

            let cmd = data[1]

            // Only support CONNECT (0x01)
            guard cmd == 0x01 else {
                Self.logger.debug("Unsupported SOCKS5 command: \(cmd)")
                self.sendReply(to: clientConn, rep: 0x07) { // command not supported
                    clientConn.cancel()
                    completion()
                }
                return
            }

            let atyp = data[3]
            self.parseAddress(clientConn: clientConn, data: data, atyp: atyp, completion: completion)
        }
    }

    private func parseAddress(
        clientConn: NWConnection,
        data: Data,
        atyp: UInt8,
        completion: @escaping () -> Void
    ) {
        // Calculate expected total length based on address type
        let expectedLen: Int
        switch atyp {
        case 0x01: // IPv4: 4 header + 4 addr + 2 port = 10
            expectedLen = 10
        case 0x04: // IPv6: 4 header + 16 addr + 2 port = 22
            expectedLen = 22
        case 0x03: // Domain: 4 header + 1 len + N + 2 port (need at least 5 to read len byte)
            guard data.count >= 5 else {
                readMore(clientConn: clientConn, data: data, needed: 5, atyp: atyp, completion: completion)
                return
            }
            let domainLen = Int(data[4])
            expectedLen = 4 + 1 + domainLen + 2
        default:
            Self.logger.debug("Unsupported address type: \(atyp)")
            sendReply(to: clientConn, rep: 0x08) { // address type not supported
                clientConn.cancel()
                completion()
            }
            return
        }

        if data.count < expectedLen {
            readMore(clientConn: clientConn, data: data, needed: expectedLen, atyp: atyp, completion: completion)
            return
        }

        // Parse host and port
        let host: String
        let portOffset: Int

        switch atyp {
        case 0x01: // IPv4
            let a = data[4], b = data[5], c = data[6], d = data[7]
            host = "\(a).\(b).\(c).\(d)"
            portOffset = 8
        case 0x04: // IPv6
            var parts: [String] = []
            for i in stride(from: 4, to: 20, by: 2) {
                let word = (UInt16(data[i]) << 8) | UInt16(data[i + 1])
                parts.append(String(format: "%x", word))
            }
            host = parts.joined(separator: ":")
            portOffset = 20
        case 0x03: // Domain
            let domainLen = Int(data[4])
            host = String(data: data[5..<(5 + domainLen)], encoding: .utf8) ?? ""
            portOffset = 5 + domainLen
        default:
            clientConn.cancel()
            completion()
            return
        }

        let port = (UInt16(data[portOffset]) << 8) | UInt16(data[portOffset + 1])

        guard !host.isEmpty else {
            Self.logger.debug("Empty host in SOCKS5 request")
            sendReply(to: clientConn, rep: 0x01) {
                clientConn.cancel()
                completion()
            }
            return
        }

        Self.logger.info("SOCKS5 CONNECT \(host):\(port)")
        connectAndRelay(clientConn: clientConn, host: host, port: port, completion: completion)
    }

    private func readMore(
        clientConn: NWConnection,
        data: Data,
        needed: Int,
        atyp: UInt8,
        completion: @escaping () -> Void
    ) {
        let remaining = needed - data.count
        clientConn.receive(minimumIncompleteLength: remaining, maximumLength: 512) { [self] more, _, _, error in
            if let error = error {
                Self.logger.debug("Address read error: \(error.localizedDescription)")
                clientConn.cancel()
                completion()
                return
            }
            guard let more = more else {
                clientConn.cancel()
                completion()
                return
            }
            var combined = data
            combined.append(more)
            self.parseAddress(clientConn: clientConn, data: combined, atyp: atyp, completion: completion)
        }
    }

    // MARK: - Phase 3: Connect and Relay

    private func connectAndRelay(
        clientConn: NWConnection,
        host: String,
        port: UInt16,
        completion: @escaping () -> Void
    ) {
        let profile = settings.matchingProfile(for: host)
        let dohResolver = resolverCache.resolver(for: profile)

        // VPN mode
        if profile.routeMode == .vpn, let outlineConfig = profile.outlineConfig {
            Self.logger.info("[\(host)] SOCKS5 VPN mode")
            let connectVPN = { (targetHost: String) in
                ShadowsocksStream.connect(config: outlineConfig, targetHost: targetHost, targetPort: port, queue: self.queue) { stream in
                    guard let stream = stream else {
                        Self.logger.error("[\(host)] Failed to connect to Outline server")
                        self.sendReply(to: clientConn, rep: 0x01) {
                            clientConn.cancel()
                            completion()
                        }
                        return
                    }
                    self.sendReply(to: clientConn, rep: 0x00) {
                        ConnectionRelay.relay(left: clientConn, right: stream, label: host, queue: self.queue) {
                            stream.cancel()
                            completion()
                        }
                    }
                }
            }
            if let resolver = dohResolver {
                resolver.resolve(domain: host) { ips in
                    let resolved = ips?.first ?? host
                    if resolved != host { Self.logger.debug("[\(host)] DoH resolved to \(resolved)") }
                    connectVPN(resolved)
                }
            } else {
                connectVPN(host)
            }
            return
        }

        // Split or none mode: connect to server first, then send success reply
        resolveAndConnect(host: host, port: port, dohResolver: dohResolver) { [self] serverConn in
            guard let serverConn = serverConn else {
                Self.logger.error("[\(host)] Failed to connect to server")
                self.sendReply(to: clientConn, rep: 0x04) { // host unreachable
                    clientConn.cancel()
                    completion()
                }
                return
            }

            // Send success reply
            self.sendReply(to: clientConn, rep: 0x00) {
                // If no fragmentation, blind relay
                if profile.splitMode == .none {
                    Self.logger.info("[\(host)] SOCKS5 mode=none, blind relay")
                    ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: self.queue) {
                        serverConn.cancel()
                        completion()
                    }
                    return
                }

                // TLS-aware fragmentation: peek at client's first bytes
                Self.logger.info("[\(host)] SOCKS5 reading ClientHello...")
                self.readClientHello(from: clientConn, serverConn: serverConn, host: host, profile: profile, completion: completion)
            }
        }
    }

    // MARK: - TLS Fragmentation (mirrors HTTPSHandler)

    private func readClientHello(
        from clientConn: NWConnection,
        serverConn: NWConnection,
        host: String,
        profile: SpoofProfile,
        completion: @escaping () -> Void
    ) {
        clientConn.receive(minimumIncompleteLength: 5, maximumLength: 16389) { [self] content, _, _, error in
            if let error = error {
                Self.logger.error("[\(host)] ClientHello read error: \(error.localizedDescription)")
                serverConn.cancel()
                clientConn.cancel()
                completion()
                return
            }

            guard let data = content, !data.isEmpty else {
                Self.logger.warning("[\(host)] Empty first data after SOCKS5 handshake")
                serverConn.cancel()
                clientConn.cancel()
                completion()
                return
            }

            // Not TLS? Forward raw and relay
            guard data.count >= 5, data[0] == 0x16 else {
                Self.logger.info("[\(host)] Not TLS, forwarding \(data.count) raw bytes")
                serverConn.send(content: data, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { _ in
                    ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: self.queue) {
                        serverConn.cancel()
                        completion()
                    }
                })
                return
            }

            self.ensureFullTLSRecord(data: data, from: clientConn, host: host) { fullData in
                guard let fullData = fullData else {
                    serverConn.cancel()
                    clientConn.cancel()
                    completion()
                    return
                }
                self.processClientHello(data: fullData, clientConn: clientConn, serverConn: serverConn, host: host, profile: profile, completion: completion)
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
        serverConn: NWConnection,
        host: String,
        profile: SpoofProfile,
        completion: @escaping () -> Void
    ) {
        guard let tlsMsg = TLSMessage.parse(from: data), tlsMsg.isClientHello else {
            Self.logger.warning("[\(host)] Failed to parse TLS/not ClientHello, forwarding raw")
            serverConn.send(content: data, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { _ in
                ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: self.queue) {
                    serverConn.cancel()
                    completion()
                }
            })
            return
        }

        let segments = TLSDesyncer.split(
            raw: tlsMsg.raw,
            mode: profile.splitMode,
            chunkSize: profile.chunkSize,
            sniOffset: tlsMsg.extractSNIOffset(),
            tlsRecordFragmentation: profile.tlsRecordFragmentation
        )

        Self.logger.info("[\(host)] ClientHello \(tlsMsg.raw.count)B → \(segments.count) segments (mode=\(profile.splitMode.rawValue))")

        let extraData: Data? = data.count > tlsMsg.raw.count
            ? Data(data.dropFirst(tlsMsg.raw.count))
            : nil

        sendSegments(segments, to: serverConn, index: 0) { [self] in
            if let extra = extraData {
                serverConn.send(content: extra, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { _ in
                    ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: self.queue) {
                        serverConn.cancel()
                        completion()
                    }
                })
            } else {
                ConnectionRelay.relay(left: clientConn, right: serverConn, label: host, queue: self.queue) {
                    serverConn.cancel()
                    completion()
                }
            }
        }
    }

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

    // MARK: - Helpers

    private func sendReply(to conn: NWConnection, rep: UInt8, completion: @escaping () -> Void) {
        // Minimal success/error reply: VER=5, REP, RSV=0, ATYP=1(IPv4), BIND.ADDR=0.0.0.0, BIND.PORT=0
        let reply = Data([0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        conn.send(content: reply, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { _ in
            completion()
        })
    }

    private func resolveAndConnect(host: String, port: UInt16, dohResolver: DoHResolver?, completion: @escaping (NWConnection?) -> Void) {
        if let resolver = dohResolver {
            resolver.resolve(domain: host) { ips in
                let targetHost: NWEndpoint.Host
                if let ip = ips?.first {
                    Self.logger.debug("[\(host)] DoH resolved to \(ip)")
                    targetHost = NWEndpoint.Host(ip)
                } else {
                    targetHost = NWEndpoint.Host(host)
                }
                let conn = self.createServerConnection(host: targetHost, port: port)
                self.waitForReady(conn: conn, host: host, completion: completion)
            }
        } else {
            let conn = createServerConnection(host: NWEndpoint.Host(host), port: port)
            waitForReady(conn: conn, host: host, completion: completion)
        }
    }

    private func createServerConnection(host: NWEndpoint.Host, port: UInt16) -> NWConnection {
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

    private func waitForReady(conn: NWConnection, host: String, completion: @escaping (NWConnection?) -> Void) {
        let completed = LockedFlag()

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.stateUpdateHandler = nil
                guard completed.setIfFalse() else { return }
                completion(conn)
            case .failed(let error):
                Self.logger.error("[\(host)] Server conn failed: \(error.localizedDescription)")
                conn.stateUpdateHandler = nil
                guard completed.setIfFalse() else { return }
                conn.cancel()
                completion(nil)
            case .cancelled:
                conn.stateUpdateHandler = nil
                guard completed.setIfFalse() else { return }
                completion(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)

        queue.asyncAfter(deadline: .now() + 10) {
            guard completed.setIfFalse() else { return }
            Self.logger.warning("[\(host)] Server connect timeout")
            conn.stateUpdateHandler = nil
            conn.cancel()
            completion(nil)
        }
    }
}
