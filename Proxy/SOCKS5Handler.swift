import Foundation
import Network
import os.log

/// Handles SOCKS5 connections: greeting, connect request, then relay
/// with the same VPN/split/none routing as HTTPSHandler.
final class SOCKS5Handler {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "SOCKS5")

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

        if profile.isVPNMissingConfig {
            Self.logger.error("[\(host)] VPN route has no Outline config, rejecting")
            sendReply(to: clientConn, rep: 0x02) { // connection not allowed by ruleset
                clientConn.cancel()
                completion()
            }
            return
        }

        // VPN mode
        if profile.routeMode == .vpn, let outlineConfig = profile.outlineConfig {
            Self.logger.info("[\(host)] SOCKS5 VPN mode")
            let connectVPN = { (targetHost: String) in
                ShadowsocksStream.connect(config: outlineConfig, targetHost: targetHost, targetPort: port, dialer: self.dialer, session: self.session) { stream in
                    if let stream { self.session.adopt(stream) }
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

                // TLS-aware fragmentation: read the client's first flight
                Self.logger.info("[\(host)] SOCKS5 reading ClientHello...")
                self.desyncAndRelay(clientConn: clientConn, serverConn: serverConn, host: host, profile: profile, completion: completion)
            }
        }
    }

    // MARK: - TLS Fragmentation

    /// Reads the first flight, writes it desynced (or as-is), then relays. A failed write cancels
    /// both sides instead of relaying (N7).
    private func desyncAndRelay(
        clientConn: NWConnection,
        serverConn: NWConnection,
        host: String,
        profile: SpoofProfile,
        completion: @escaping () -> Void
    ) {
        let reader = FirstFlightReader(client: clientConn, queue: queue, firstByteTimeout: firstByteTimeout, label: host)
        reader.read { [self] flight in
            guard let flight else {
                serverConn.cancel()
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

    // MARK: - Helpers

    private func sendReply(to conn: NWConnection, rep: UInt8, completion: @escaping () -> Void) {
        // Minimal success/error reply: VER=5, REP, RSV=0, ATYP=1(IPv4), BIND.ADDR=0.0.0.0, BIND.PORT=0
        let reply = Data([0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        conn.send(content: reply, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { _ in
            completion()
        })
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
