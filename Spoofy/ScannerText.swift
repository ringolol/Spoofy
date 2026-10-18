import SwiftUI

/// The scanner's user-facing text (network-scanner plan §2.5.6, §6.3, §7.5, §7.6).
enum ScannerText {
    // MARK: - Verdicts

    struct VerdictCopy {
        let title: String
        let explanation: String
        let fix: String
    }

    static func copy(for verdict: HostVerdict) -> VerdictCopy? {
        switch verdict.status {
        case .unknown:
            return nil
        case .working:
            return VerdictCopy(title: "Working", explanation: "Recent connections got answers from the server.", fix: "")
        case .ruleChanged:
            return VerdictCopy(title: "Rule changed",
                               explanation: "Evidence was collected under different settings.",
                               fix: "Reload the app or page to retest.")
        case .suspicious(let kind), .blocked(let kind):
            return copy(for: kind, ech: verdict.echSeen)
        }
    }

    private static func copy(for kind: BlockKind, ech: Bool) -> VerdictCopy {
        switch kind {
        case .sni where ech:
            return VerdictCopy(title: "Blocked after TLS hello (ECH)",
                               explanation: "The connection opened, but after the browser sent the site name the reply was cut. The hello used Encrypted Client Hello, which is itself blocked in Russia.",
                               fix: "Disable ECH in the browser.")
        case .sni:
            return VerdictCopy(title: "Blocked after TLS hello",
                               explanation: "The connection opened, but after the browser sent the site name the reply was cut (reset or silence). Typical DPI SNI blocking.",
                               fix: "Add to a profile with SNI split.")
        case .injected:
            return VerdictCopy(title: "Fake response",
                               explanation: "A reply arrived faster than the server could physically answer, or wasn't valid TLS.",
                               fix: "Add to a profile with SNI split.")
        case .ip:
            return VerdictCopy(title: "Address unreachable",
                               explanation: "The TCP connection to the server's IP fails. Splitting can't fix this.",
                               fix: "Use a VPN profile.")
        case .dns:
            return VerdictCopy(title: "DNS spoofed",
                               explanation: "The name resolved to a non-public address, or didn't resolve.",
                               fix: "Enable DoH.")
        case .httpBlockPage:
            return VerdictCopy(title: "HTTP block page",
                               explanation: "A plain-HTTP request was answered by a block page.",
                               fix: "Use HTTPS, or a split or VPN profile.")
        case .freeze:
            return VerdictCopy(title: "Stalls after ~16 KB",
                               explanation: "The connection works, then stops after a few KB. Typical for foreign hosting on mobile networks.",
                               fix: "Use a VPN profile.")
        case .whitelist:
            return VerdictCopy(title: "Network whitelist",
                               explanation: "Only approved sites work on this network right now.",
                               fix: "Use a VPN through an allowed endpoint.")
        case .outline:
            return VerdictCopy(title: "Outline server unreachable",
                               explanation: "The profile's Outline server couldn't be reached.",
                               fix: "Check the Outline server.")
        }
    }

    static func color(for status: HostStatus) -> Color {
        switch status {
        case .blocked: return .red
        case .suspicious: return .orange
        case .ruleChanged, .working, .unknown: return .secondary
        }
    }

    static func confidence(_ confidence: TraceOutcome.Confidence) -> String {
        switch confidence {
        case .low: return "Low confidence"
        case .medium: return "Medium confidence"
        case .high: return "High confidence"
        }
    }

    // MARK: - Network

    static func banner(for state: NetworkState) -> String? {
        switch state {
        case .normal: return nil
        case .offline: return "No connectivity. Results paused."
        case .whitelistMode: return "Network looks like it's in whitelist mode: only approved sites work."
        case .outlineDown(let name): return "Outline server for \(name) is unreachable or blocked."
        }
    }

    // MARK: - Connections

    static func outcome(_ kind: TraceOutcome.Kind) -> String {
        switch kind {
        case .ok: return "OK"
        case .clientAborted: return "Closed by the app"
        case .interrupted: return "Interrupted"
        case .dnsFailed: return "DNS failed"
        case .dnsBogus(let ip): return "DNS answered \(ip)"
        case .connectRefused: return "Connection refused"
        case .connectTimeout: return "Connection timed out"
        case .connectUnreachable: return "Host unreachable"
        case .helloReset(let early): return early ? "Reset after hello (early)" : "Reset after hello"
        case .helloSilentClose(let early): return early ? "Closed after hello (early)" : "Closed after hello"
        case .helloBlackhole(let retransmits): return retransmits ? "No reply to hello (retransmits)" : "No reply to hello"
        case .injectedResponse(.httpOnTLS): return "HTTP reply to TLS"
        case .injectedResponse(.earlyAlert): return "Alert faster than the server"
        case .injectedResponse(.sessionIDMismatch): return "Server hello doesn't match"
        case .httpBlockPage(let status, _): return "Block page (\(status))"
        case .freeze(let bytes): return "Stalled after \(byteCount(bytes))"
        case .midStreamReset(let bytes): return "Reset after \(byteCount(bytes))"
        case .outlineFailed: return "Outline server failed"
        case .inconclusive: return "Inconclusive"
        }
    }

    /// `CONNECT · TLS h2 · DNS 12 ms · RTT 48 ms · hello→RST 3 ms (early) · ↑517 B ↓0 B` (§7.5).
    static func timeline(_ summary: TraceSummary) -> String {
        var parts: [String] = []
        switch (summary.start.inbound, summary.kind) {
        case (.http, .http): parts.append("HTTP proxy")
        case (.http, _): parts.append("CONNECT")
        case (.socks5, _): parts.append("SOCKS5")
        case (.socks4, _): parts.append("SOCKS4")
        }
        switch summary.kind {
        case .tls(let hello): parts.append((["TLS"] + hello.alpn.prefix(1)).joined(separator: " "))
        case .http(let method, _): parts.append("HTTP \(method)")
        case .none: break
        default: parts.append(summary.kind.tag.rawValue)
        }
        if let dns = summary.dnsDuration { parts.append("DNS \(duration(dns))") }
        if let rtt = summary.rtt { parts.append("RTT \(duration(rtt))") }
        if let tFirstDown = summary.tFirstDown {
            parts.append("first byte \(duration(tFirstDown))")
        } else if let tEnd = summary.tEnd {
            let early = TraceClassifier.isEarly(tEnd, summary, .standard) ? " (early)" : ""
            switch summary.endReason {
            case .serverReset: parts.append("hello→RST \(duration(tEnd))\(early)")
            case .serverFin: parts.append("hello→FIN \(duration(tEnd))\(early)")
            case .clientClosed, .idleTimeout: parts.append("silent \(duration(tEnd))")
            default: break
            }
        }
        parts.append("↑\(byteCount(summary.bytesUp)) ↓\(byteCount(summary.bytesDown))")
        return parts.joined(separator: " · ")
    }

    /// `Split (SNI) configured · not applied: not TLS`, when the route's strategy didn't run (§2.5.3).
    static func strategyNote(_ summary: TraceSummary) -> String? {
        guard case .desync(let parameters) = summary.start.outbound,
              case .passthrough(let reason) = summary.applied else { return nil }
        let why: String
        switch reason {
        case .notTLS: why = "not TLS"
        case .clientSilent: why = "the server spoke first"
        case .plainHTTP: why = "plain HTTP"
        case .splitNone: return nil
        }
        return "Split (\(parameters.mode.displayName)) configured · not applied: \(why)"
    }

    static func route(_ outbound: TraceOutbound) -> String {
        switch outbound {
        case .direct: return "Direct"
        case .desync(let parameters): return "Split (\(parameters.mode.displayName))"
        case .shadowsocks(let host, let port): return "Outline \(host):\(port)"
        }
    }

    static func duration(_ seconds: TimeInterval) -> String {
        seconds < 1 ? "\(Int((seconds * 1000).rounded())) ms" : String(format: "%.1f s", seconds)
    }

    static func byteCount(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }

    static func ago(_ date: Date, now: Date = Date()) -> String {
        let seconds = max(0, now.timeIntervalSince(date))
        if seconds < 60 { return "\(Int(seconds))s ago" }
        if seconds < 3600 { return "\(Int(seconds / 60))m ago" }
        return "\(Int(seconds / 3600))h ago"
    }

    // MARK: - Refusals

    static func refusal(_ group: RefusalGroup) -> String {
        switch group.key {
        case .socks5Command(3):
            return "An app tried to send UDP (calls, games, QUIC). Spoofy only carries TCP. These apps will connect directly or fail."
        case .socks5Command(2):
            return "An app asked to accept incoming connections (e.g. FTP active mode). Not supported."
        case .socks5Command(let command):
            return "An app sent an unsupported SOCKS5 command (\(command))."
        case .socks5AddressType(let type):
            return "An app sent an unsupported SOCKS5 address type (\(type))."
        case .socks5AuthRequired:
            return "An app wants to log in to the proxy. Turn off proxy authentication in that app."
        case .socks4:
            return "An app uses SOCKS4. Switch it to SOCKS5 or HTTP proxy."
        case .httpOriginForm, .httpsAbsoluteForm, .http2Preface:
            return "An app is talking to Spoofy as if it were a website. Check that it's set to use an HTTP proxy, not a server address."
        case .headTooLarge:
            return "An app sent a request head that was too large."
        case .routeRejected(let name):
            return "Profile \(name) routes through VPN but has no Outline server."
        case .overCapacity:
            return "More than \(ProxyServer.maxConcurrentConnections) connections at once; some were refused."
        case .malformed:
            return "\(group.count) requests weren't valid proxy requests."
        }
    }

    static let notShownFooter = "Not shown: UDP from apps that don't use SOCKS5 (QUIC, voice calls), and apps that ignore the system proxy."
}
