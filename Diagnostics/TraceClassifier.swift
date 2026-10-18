import Foundation
import Network

/// What one connection says about blocking (network-scanner plan §4.3).
struct TraceOutcome: Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        case ok
        /// The client left before we could judge.
        case clientAborted
        /// Rerouted (U13) or the proxy stopped: not evidence.
        case interrupted
        case dnsFailed
        /// D: the name resolved to an address that can't be the site.
        case dnsBogus(ip: String)
        /// B: TCP level.
        case connectRefused, connectTimeout, connectUnreachable
        /// A: RST after the ClientHello, no server bytes.
        case helloReset(early: Bool)
        /// A: FIN after the ClientHello, no server bytes.
        case helloSilentClose(early: Bool)
        /// A / B / I: silence after the ClientHello.
        case helloBlackhole(retransmits: Bool)
        /// A / C: content that can't be from the server.
        case injectedResponse(InjectedKind)
        /// C.
        case httpBlockPage(status: Int, location: String?)
        /// H.
        case freeze(bytesDown: Int)
        /// Weak, informational.
        case midStreamReset(bytesDown: Int)
        /// J: the route's Outline server, not the host.
        case outlineFailed
        case inconclusive
    }

    enum InjectedKind: Equatable, Sendable { case httpOnTLS, earlyAlert, sessionIDMismatch }

    enum Confidence: Int, Comparable, Sendable {
        case low, medium, high

        static func < (lhs: Confidence, rhs: Confidence) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    let kind: Kind
    let confidence: Confidence
    /// The ClientHello offered ECH, so a block may be aimed at ECH rather than the site.
    let echPresent: Bool
}

/// Pure: one `TraceSummary` → one `TraceOutcome` (network-scanner plan §4.4). Rules run in order;
/// the first match wins.
enum TraceClassifier {
    static func classify(_ summary: TraceSummary, config: DetectionConfig = .standard) -> TraceOutcome {
        var hello: ClientHelloInfo?
        if case .tls(let info) = summary.kind { hello = info }
        let (kind, confidence) = rules(summary, hello: hello, config: config)
        return TraceOutcome(kind: kind, confidence: confidence, echPresent: hello?.hasECH ?? false)
    }

    private typealias Result = (TraceOutcome.Kind, TraceOutcome.Confidence)

    private static func rules(_ s: TraceSummary, hello: ClientHelloInfo?, config: DetectionConfig) -> Result {
        // R-1: a session closed by a rule change looks exactly like a blackhole otherwise.
        if s.endReason == .rerouted || s.endReason == .proxyStopped { return (.interrupted, .low) }

        // R0: DPI sees the Outline server, not the host.
        if case .shadowsocks = s.start.outbound {
            switch s.endReason {
            case .outlineConnectFailed: return (.outlineFailed, .high)
            case .connectFailed, .dnsFailed: return (.outlineFailed, .medium)
            default: return settled(s)
            }
        }

        // R1–R3: DNS and TCP.
        if s.endReason == .dnsFailed { return (.dnsFailed, .medium) }
        if !s.start.isIPLiteral, let bogus = resolvedAddresses(s).first(where: isBogon) {
            return (.dnsBogus(ip: bogus), .high)
        }
        if case .connectFailed(let error) = s.endReason {
            switch error {
            case .refused: return (.connectRefused, .medium)
            case .unreachable: return (.connectUnreachable, .low)
            case .timeout: return (.connectTimeout, .medium)
            case .dns: return (.dnsFailed, .medium)
            case .other: return (.inconclusive, .low)
            }
        }

        // R4, and the §2.5.5 gate: past here only TLS and HTTP get the full rules.
        switch s.kind {
        case .none:
            return (.clientAborted, .low)
        case .tls:
            if let result = helloRules(s, hello: hello, config: config) { return result }
        case .http(_, let host):
            if s.firstDownAt == nil { return (.inconclusive, .low) }  // a slow origin is normal
            if let result = blockPageRule(s, requestHost: host ?? s.start.host, config: config) { return result }
        case .tlsOther, .ssh, .unknown, .serverFirst:
            if let freeze = freezeRule(s, config: config) { return (freeze, .low) }
            return (.inconclusive, .low)
        }

        // R8: streaming. Freeze is a byte-count cut, so it beats everything else.
        if let freeze = freezeRule(s, config: config) { return (freeze, .medium) }
        if s.endReason == .serverReset, s.bytesDown < config.midStreamResetMax {
            return (.midStreamReset(bytesDown: s.bytesDown), .low)
        }
        // R9.
        return settled(s)
    }

    /// R5–R6 for a ClientHello. Nil falls through to R8.
    private static func helloRules(_ s: TraceSummary, hello: ClientHelloInfo?, config: DetectionConfig) -> Result? {
        guard let prefix = s.firstDownPrefix, s.firstDownAt != nil else {
            // R5: the server never sent a byte.
            let early = s.tEnd.map { isEarly($0, s, config) } ?? false
            switch s.endReason {
            case .serverReset: return (.helloReset(early: early), early ? .high : .medium)
            case .serverFin: return (.helloSilentClose(early: early), early ? .high : .low)
            case .clientClosed, .idleTimeout:
                guard let tEnd = s.tEnd, tEnd >= config.helloBlackholeMin else {
                    return (.clientAborted, .low)  // gave up or raced another connection
                }
                let retransmits = (s.transfer.retransmittedBytes ?? 0) > 0
                return (.helloBlackhole(retransmits: retransmits), retransmits ? .high : .medium)
            default:
                return (.inconclusive, .low)
            }
        }
        // R6: what came back.
        let early = s.tFirstDown.map { isEarly($0, s, config) } ?? false
        if prefix.starts(with: Data("HTTP/".utf8)) { return (.injectedResponse(.httpOnTLS), .high) }
        if prefix.first == 0x15 {
            // A late alert is the real server rejecting us.
            return early ? (.injectedResponse(.earlyAlert), .high) : (.inconclusive, .low)
        }
        if let hello, let server = ServerHelloInfo.parse(prefix: prefix), server.negotiatedVersion == 0x0304,
           server.sessionID != hello.sessionID {
            // TLS 1.3 echoes legacy_session_id; a smart injector could too.
            return (.injectedResponse(.sessionIDMismatch), .medium)
        }
        return nil
    }

    /// R7. Nil falls through to R8.
    private static func blockPageRule(_ s: TraceSummary, requestHost: String, config: DetectionConfig) -> Result? {
        guard let prefix = s.firstDownPrefix, let status = HTTPStatusLine.status(in: prefix),
              config.blockPageStatus.contains(status) else { return nil }
        let early = s.tFirstDown.map { isEarly($0, s, config) } ?? false
        if [301, 302, 303, 307].contains(status) {
            let location = HTTPStatusLine.location(in: prefix)
            guard let location, let target = URLComponents(string: location)?.host?.lowercased() else { return nil }
            let requested = stripPort(requestHost).lowercased()
            let sameSite = (BaseDomain.of(target) ?? target) == (BaseDomain.of(requested) ?? requested)
            if !sameSite, early || config.blockPageHosts.contains(target) {
                return (.httpBlockPage(status: status, location: location), .high)
            }
            return nil
        }
        return early ? (.httpBlockPage(status: status, location: nil), .medium) : nil
    }

    private static func freezeRule(_ s: TraceSummary, config: DetectionConfig) -> TraceOutcome.Kind? {
        guard let stall = s.stall, !stall.resumed, stall.phase == .midStream,
              config.freezeWindow.contains(stall.bytesDownAtStall),
              s.endReason == .clientClosed || s.endReason == .idleTimeout else { return nil }
        return .freeze(bytesDown: stall.bytesDownAtStall)
    }

    /// R9, and the end of the VPN route.
    private static func settled(_ s: TraceSummary) -> Result {
        if s.bytesDown > 0 { return (.ok, .high) }
        if s.payloadSentAt == nil { return (.clientAborted, .low) }
        return (.inconclusive, .low)
    }

    /// §4.2: earlier than a round trip allows. Without a usable RTT nothing is early.
    static func isEarly(_ t: TimeInterval, _ s: TraceSummary, _ config: DetectionConfig) -> Bool {
        guard let rtt = s.rtt, rtt >= config.minRTTForTiming else { return false }
        return t < config.earlyRatio * rtt
    }

    /// Every address the target name was seen to resolve to.
    private static func resolvedAddresses(_ s: TraceSummary) -> [String] {
        var addresses = s.dohIPs ?? []
        addresses += s.attempts.map(\.address)
        if let connected = s.connectedAddress { addresses.append(connected) }
        if let resolved = s.establishment.resolvedIP { addresses.append(resolved) }
        return addresses
    }

    /// Addresses no public site can have (§4.4 R2).
    static func isBogon(_ address: String) -> Bool {
        if let v4 = IPv4Address(address) {
            let b = [UInt8](v4.rawValue)
            switch (b[0], b[1]) {
            case (0, _), (127, _), (10, _), (192, 168), (169, 254): return true
            case (172, 16...31), (100, 64...127): return true
            default: return false
            }
        }
        if let v6 = IPv6Address(address) {
            let b = [UInt8](v6.rawValue)
            if b.dropLast().allSatisfy({ $0 == 0 }) && (b[15] == 0 || b[15] == 1) { return true }  // :: and ::1
            if b[0] & 0xFE == 0xFC { return true }  // fc00::/7
            if b[0] == 0xFE && b[1] & 0xC0 == 0x80 { return true }  // fe80::/10
        }
        return false
    }

    private static func stripPort(_ host: String) -> String {
        if host.hasPrefix("["), let end = host.firstIndex(of: "]") {
            return String(host[host.index(after: host.startIndex)..<end])
        }
        if host.filter({ $0 == ":" }).count == 1, let colon = host.firstIndex(of: ":") {
            return String(host[..<colon])
        }
        return host
    }
}

/// The status line and `Location` of a response prefix (§4.4 R7).
enum HTTPStatusLine {
    /// `HTTP/1.x NNN`.
    static func status(in prefix: Data) -> Int? {
        let text = String(decoding: prefix.prefix(32), as: UTF8.self)
        guard text.hasPrefix("HTTP/") else { return nil }
        let parts = text.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, parts[1].count == 3 else { return nil }
        return Int(parts[1])
    }

    /// Nil when absent or cut off by the prefix.
    static func location(in prefix: Data) -> String? {
        let text = String(decoding: prefix, as: UTF8.self)
        for line in text.components(separatedBy: "\r\n").dropFirst().dropLast() {
            guard let colon = line.firstIndex(of: ":"),
                  line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "location" else { continue }
            return line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        return nil
    }
}
