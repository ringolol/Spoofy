import XCTest
@testable import SpoofyCore

/// One fixture per rule of network-scanner plan §4.4.
final class TraceClassifierTests: XCTestCase {
    private static let hello = ClientHelloInfo.parse(record: ClientHelloBuilder.make(sni: "example.com"))!
    private static let echHello = ClientHelloInfo.parse(
        record: ClientHelloBuilder.make(sni: "example.com", extensionsBefore: [(0xfe0d, Data([0x00]))]))!
    private static let t0: UInt64 = 10_000_000_000

    private static func at(_ seconds: Double) -> UInt64 { t0 + UInt64(seconds * 1e9) }

    /// A TLS connection that sent its hello at `t0` over a 100 ms RTT and has heard nothing yet.
    private func summary(outbound: TraceOutbound = .direct, host: String = "example.com",
                         kind: PayloadKind? = .tls(TraceClassifierTests.hello), end: EndReason,
                         rtt: TimeInterval? = 0.1, _ configure: (inout TraceFields) -> Void = { _ in }) -> TraceSummary {
        let start = TraceStart(id: 1, startedAt: Date(timeIntervalSince1970: 1_000), startedAtNanos: Self.t0 - 500_000_000,
                               inbound: .http, host: host, port: 443, isIPLiteral: ServerConnector.isIPLiteral(host),
                               profileID: UUID(), profileName: "Master", isDefaultProfile: true, outbound: outbound)
        var fields = TraceFields()
        fields.dohIPs = ["93.184.216.34"]
        fields.connectStart = Self.t0 - 200_000_000
        fields.connectEnd = Self.t0 - 100_000_000
        fields.connectedAddress = "93.184.216.34"
        fields.attempts = [DialAttemptRecord(address: "93.184.216.34", startedAt: Self.t0 - 200_000_000, outcome: .ready)]
        fields.establishment.tcpRTT = rtt
        if kind != nil { fields.payloadSentAt = Self.t0 }
        fields.payloadKind = kind
        fields.endedAt = Self.at(30)
        configure(&fields)
        return TraceSummary(start: start, reached: .payloadSent, endReason: end, fields: fields)
    }

    private func respond(_ prefix: Data, after seconds: Double, bytes: Int? = nil) -> (inout TraceFields) -> Void {
        { fields in
            fields.firstDownAt = Self.at(seconds)
            fields.firstDownPrefix = Data(prefix.prefix(ConnectionTrace.downPrefixLength))
            fields.bytesDown = bytes ?? prefix.count
        }
    }

    private func outcome(_ summary: TraceSummary, config: DetectionConfig = .standard) -> TraceOutcome {
        TraceClassifier.classify(summary, config: config)
    }

    private func assertOutcome(_ summary: TraceSummary, _ kind: TraceOutcome.Kind, _ confidence: TraceOutcome.Confidence,
                               _ message: String = "", config: DetectionConfig = .standard,
                               file: StaticString = #filePath, line: UInt = #line) {
        let result = outcome(summary, config: config)
        XCTAssertEqual(result.kind, kind, message, file: file, line: line)
        XCTAssertEqual(result.confidence, confidence, message, file: file, line: line)
    }

    // MARK: - R-1, R0

    func testRuleChangesAndStopsAreNotEvidence() {
        // Otherwise a blackhole: 30 s of silence after the hello.
        assertOutcome(summary(end: .rerouted), .interrupted, .low)
        assertOutcome(summary(end: .proxyStopped), .interrupted, .low)
    }

    func testVPNRouteJudgesOnlyTheOutlineServer() {
        let vpn = TraceOutbound.shadowsocks(host: "1.2.3.4", port: 8388)
        assertOutcome(summary(outbound: vpn, end: .outlineConnectFailed), .outlineFailed, .high)
        assertOutcome(summary(outbound: vpn, end: .connectFailed(.timeout)), .outlineFailed, .medium)
        assertOutcome(summary(outbound: vpn, end: .clientClosed), .inconclusive, .low, "no hello blackhole on VPN")
        assertOutcome(summary(outbound: vpn, end: .serverReset, respond(Data("x".utf8), after: 0.001)), .ok, .high)
    }

    // MARK: - R1–R3

    func testDNSFailure() {
        assertOutcome(summary(kind: nil, end: .dnsFailed), .dnsFailed, .medium)
    }

    func testBogusAddressIsDNSPoisoning() {
        let poisoned = summary(end: .clientClosed) { $0.dohIPs = nil; $0.connectedAddress = "example.com"
            $0.establishment.resolvedIP = "127.0.0.1" }
        assertOutcome(poisoned, .dnsBogus(ip: "127.0.0.1"), .high)
        let failedDial = summary(kind: nil, end: .connectFailed(.refused)) { $0.dohIPs = nil; $0.connectedAddress = nil
            $0.attempts = [DialAttemptRecord(address: "10.10.34.36", startedAt: 0, outcome: .failed(.posix(.ECONNREFUSED)))] }
        assertOutcome(failedDial, .dnsBogus(ip: "10.10.34.36"), .high)
    }

    func testAnIPLiteralTargetIsNeverBogus() {
        let local = summary(host: "192.168.1.1", end: .serverFin) {
            respond(Data("x".utf8), after: 0.01)(&$0)
            $0.dohIPs = nil; $0.connectedAddress = "192.168.1.1" }
        assertOutcome(local, .ok, .high)
    }

    func testBogons() {
        for bogon in ["0.0.0.0", "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1",
                      "100.64.0.1", "100.127.0.1", "169.254.1.1", "::", "::1", "fc00::1", "fd12::1", "fe80::1", "febf::1"] {
            XCTAssertTrue(TraceClassifier.isBogon(bogon), bogon)
        }
        for address in ["93.184.216.34", "172.32.0.1", "100.128.0.1", "1.1.1.1", "2606:4700::1111", "fec0::1", "example.com"] {
            XCTAssertFalse(TraceClassifier.isBogon(address), address)
        }
    }

    func testConnectFailures() {
        assertOutcome(summary(kind: nil, end: .connectFailed(.refused)), .connectRefused, .medium)
        assertOutcome(summary(kind: nil, end: .connectFailed(.timeout)), .connectTimeout, .medium)
        assertOutcome(summary(kind: nil, end: .connectFailed(.unreachable)), .connectUnreachable, .low)
        assertOutcome(summary(kind: nil, end: .connectFailed(.other(57))), .inconclusive, .low)
    }

    // MARK: - R4, R5

    func testNothingSentIsClientAborted() {
        assertOutcome(summary(kind: nil, end: .clientClosed), .clientAborted, .low)
    }

    func testResetAfterTheHello() {
        assertOutcome(summary(end: .serverReset) { $0.endedAt = Self.at(0.02) }, .helloReset(early: true), .high)
        assertOutcome(summary(end: .serverReset) { $0.endedAt = Self.at(0.2) }, .helloReset(early: false), .medium)
    }

    func testTimingNeedsAUsableRTT() {
        // No RTT, or one below 10 ms: nothing is early.
        assertOutcome(summary(end: .serverReset, rtt: nil) { $0.endedAt = Self.at(0.001) }, .helloReset(early: false), .medium)
        assertOutcome(summary(end: .serverReset, rtt: 0.009) { $0.endedAt = Self.at(0.001) }, .helloReset(early: false), .medium)
        // Exactly half the RTT is not early; the transfer report's minimum RTT stands in for the handshake's.
        assertOutcome(summary(end: .serverReset) { $0.endedAt = Self.at(0.05) }, .helloReset(early: false), .medium)
        assertOutcome(summary(end: .serverReset, rtt: nil) { $0.transfer.minimumRTT = 0.1; $0.endedAt = Self.at(0.02) },
                      .helloReset(early: true), .high)
    }

    func testSilentCloseAfterTheHello() {
        assertOutcome(summary(end: .serverFin) { $0.endedAt = Self.at(0.02) }, .helloSilentClose(early: true), .high)
        assertOutcome(summary(end: .serverFin) { $0.endedAt = Self.at(1) }, .helloSilentClose(early: false), .low)
    }

    func testSilenceAfterTheHello() {
        assertOutcome(summary(end: .clientClosed), .helloBlackhole(retransmits: false), .medium)
        assertOutcome(summary(end: .idleTimeout) { $0.transfer.retransmittedBytes = 1551 }, .helloBlackhole(retransmits: true), .high)
        // The client gave up early or raced another connection.
        assertOutcome(summary(end: .clientClosed) { $0.endedAt = Self.at(2.9) }, .clientAborted, .low)
        var quick = DetectionConfig.standard
        quick.helloBlackholeMin = 2
        assertOutcome(summary(end: .clientClosed) { $0.endedAt = Self.at(2.9) }, .helloBlackhole(retransmits: false), .medium,
                      config: quick)
    }

    func testServerErrorWithNothingBackIsInconclusive() {
        assertOutcome(summary(end: .serverError(57)), .inconclusive, .low)
    }

    // MARK: - R6

    func testHTTPOnATLSConnectionIsInjected() {
        let page = Data("HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/\r\n\r\n".utf8)
        assertOutcome(summary(end: .serverFin, respond(page, after: 0.3)), .injectedResponse(.httpOnTLS), .high)
    }

    func testAlerts() {
        let alert = Data([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
        assertOutcome(summary(end: .serverFin, respond(alert, after: 0.01)), .injectedResponse(.earlyAlert), .high)
        assertOutcome(summary(end: .serverFin, respond(alert, after: 0.1)), .inconclusive, .low,
                      "a late alert is the real server rejecting us")
    }

    private static func serverHello(sessionID: Data, tls13: Bool) -> Data {
        var body = Data([0x03, 0x03]) + Data(repeating: 0x11, count: 32)
        body += [UInt8(sessionID.count)] + sessionID + Data([0x13, 0x01, 0x00])
        let ext = tls13 ? Data([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]) : Data()
        body += ClientHelloBuilder.u16(ext.count) + ext
        let handshake = Data([0x02]) + ClientHelloBuilder.u24(body.count) + body
        return Data([0x16, 0x03, 0x03]) + ClientHelloBuilder.u16(handshake.count) + handshake
    }

    func testTLS13ServerHelloMustEchoTheSessionID() {
        let forged = Self.serverHello(sessionID: Data(repeating: 0xCC, count: 32), tls13: true)
        assertOutcome(summary(end: .clientClosed, respond(forged, after: 0.1, bytes: 4000)),
                      .injectedResponse(.sessionIDMismatch), .medium)
        let echoed = Self.serverHello(sessionID: Self.hello.sessionID, tls13: true)
        assertOutcome(summary(end: .clientClosed, respond(echoed, after: 0.1, bytes: 4000)), .ok, .high)
        let tls12 = Self.serverHello(sessionID: Data(repeating: 0xCC, count: 32), tls13: false)
        assertOutcome(summary(end: .clientClosed, respond(tls12, after: 0.1, bytes: 4000)), .ok, .high,
                      "a TLS 1.2 server picks its own")
    }

    // MARK: - R7

    private func http(_ response: String, after seconds: Double, config: DetectionConfig = .standard) -> TraceOutcome {
        outcome(summary(kind: .http(method: "GET", host: "www.example.com"), end: .serverFin,
                        respond(Data(response.utf8), after: seconds)), config: config)
    }

    func testEarlyRedirectElsewhereIsABlockPage() {
        let redirect = "HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/?id=1\r\nContent-Length: 0\r\n\r\n"
        XCTAssertEqual(http(redirect, after: 0.01).kind, .httpBlockPage(status: 302, location: "http://warning.rt.ru/?id=1"))
        XCTAssertEqual(http(redirect, after: 0.01).confidence, .high)
        XCTAssertEqual(http(redirect, after: 0.2).kind, .ok, "a late redirect is the site's")
        var listed = DetectionConfig.standard
        listed.blockPageHosts = ["warning.rt.ru"]
        XCTAssertEqual(http(redirect, after: 0.2, config: listed).kind,
                       .httpBlockPage(status: 302, location: "http://warning.rt.ru/?id=1"))
    }

    func testRedirectWithinTheSiteIsNotABlockPage() {
        XCTAssertEqual(http("HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n\r\n", after: 0.01).kind, .ok)
        XCTAssertEqual(http("HTTP/1.1 301 Moved\r\nLocation: /login\r\n\r\n", after: 0.01).kind, .ok)
        XCTAssertEqual(http("HTTP/1.1 302 Found\r\nLocation: http://warning.r", after: 0.01).kind, .ok,
                       "a Location cut off by the prefix is unknown")
    }

    func testEarlyForbiddenIsABlockPage() {
        XCTAssertEqual(http("HTTP/1.1 451 Unavailable For Legal Reasons\r\n\r\n", after: 0.01).kind,
                       .httpBlockPage(status: 451, location: nil))
        XCTAssertEqual(http("HTTP/1.1 403 Forbidden\r\n\r\n", after: 0.01).confidence, .medium)
        XCTAssertEqual(http("HTTP/1.1 403 Forbidden\r\n\r\n", after: 0.2).kind, .ok)
    }

    func testHTTPWithoutAnAnswerIsInconclusive() {
        assertOutcome(summary(kind: .http(method: "GET", host: "example.com"), end: .serverReset) { $0.endedAt = Self.at(0.01) },
                      .inconclusive, .low)
    }

    func testHTTPStatusLineParsing() {
        XCTAssertEqual(HTTPStatusLine.status(in: Data("HTTP/1.0 307 Temporary Redirect\r\n".utf8)), 307)
        XCTAssertNil(HTTPStatusLine.status(in: Data("SSH-2.0".utf8)))
        XCTAssertEqual(HTTPStatusLine.location(in: Data("HTTP/1.1 302 x\r\nlocation:  http://a.b/ \r\n".utf8)), "http://a.b/")
        XCTAssertNil(HTTPStatusLine.location(in: Data("HTTP/1.1 302 x\r\nLocation: http://a.b/".utf8)))
    }

    // MARK: - R8, R9

    private func stalled(at bytes: Int, resumed: Bool = false) -> (inout TraceFields) -> Void {
        { fields in
            fields.firstDownAt = Self.at(0.2)
            fields.firstDownPrefix = Self.serverHello(sessionID: Self.hello.sessionID, tls13: true)
            fields.bytesDown = resumed ? bytes + 5000 : bytes
            fields.stall = StallInfo(at: Self.at(9), bytesDownAtStall: bytes, phase: .midStream, resumed: resumed)
        }
    }

    func testStallInsideTheWindowIsAFreeze() {
        assertOutcome(summary(end: .clientClosed, stalled(at: 16_000)), .freeze(bytesDown: 16_000), .medium)
        assertOutcome(summary(end: .idleTimeout, stalled(at: 16_000)), .freeze(bytesDown: 16_000), .medium)
    }

    func testStallsThatAreNotFreezes() {
        assertOutcome(summary(end: .clientClosed, stalled(at: 16_000, resumed: true)), .ok, .high)
        assertOutcome(summary(end: .clientClosed, stalled(at: 100_000)), .ok, .high)
        assertOutcome(summary(end: .serverFin, stalled(at: 16_000)), .ok, .high)
    }

    func testMidStreamReset() {
        assertOutcome(summary(end: .serverReset, respond(Self.serverHello(sessionID: Self.hello.sessionID, tls13: true),
                                                        after: 0.2, bytes: 20_000)), .midStreamReset(bytesDown: 20_000), .low)
        assertOutcome(summary(end: .serverReset, respond(Data([0x17]), after: 0.2, bytes: 200_000)), .ok, .high)
    }

    // MARK: - The kind gate (§2.5.5)

    func testOtherProtocolsGetOnlyConnectRulesAndFreeze() {
        assertOutcome(summary(kind: .ssh, end: .clientClosed), .inconclusive, .low, "many protocols wait legitimately")
        assertOutcome(summary(kind: .ssh, end: .serverReset) { $0.endedAt = Self.at(0.01) }, .inconclusive, .low)
        assertOutcome(summary(kind: .ssh, end: .clientClosed, stalled(at: 16_000)), .freeze(bytesDown: 16_000), .low)
        assertOutcome(summary(kind: .tlsOther, end: .serverFin, respond(Data("HTTP/1.1 200".utf8), after: 0.01)),
                      .inconclusive, .low)
        assertOutcome(summary(kind: .ssh, end: .connectFailed(.refused)), .connectRefused, .medium)
    }

    func testServerFirstIsInconclusive() {
        let banner = Data("220 smtp ESMTP\r\n".utf8)
        assertOutcome(summary(kind: .serverFirst(.smtpOrFTP), end: .serverFin) {
            respond(banner, after: 0.1)(&$0)
            $0.payloadSentAt = nil }, .inconclusive, .low)
    }

    func testECHIsCarried() {
        XCTAssertTrue(outcome(summary(kind: .tls(Self.echHello), end: .serverReset)).echPresent)
        XCTAssertFalse(outcome(summary(end: .serverReset)).echPresent)
    }
}
