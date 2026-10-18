import Network
import XCTest
@testable import SpoofyCore

/// Plan §5.3: test client → real `ProxyServer` on 127.0.0.1:0 → `LoopbackOrigin`.
/// This is the contract the step-4d handler rewrite must keep. DoH is off and every target
/// is a loopback literal or `localhost`, so nothing leaves the machine.
final class LoopbackHarnessTests: XCTestCase {
    private var proxy: ProxyServer?
    private var origins: [LoopbackOrigin] = []
    private var shadowsocksServers: [LoopbackShadowsocksServer] = []

    override func tearDown() {
        proxy?.stop()
        origins.forEach { $0.stop() }
        shadowsocksServers.forEach { $0.stop() }
        super.tearDown()
    }

    // MARK: - Fixture

    /// With a `resolver`, DoH is on and every lookup goes to it instead of the network.
    private static func config(splitMode: SplitMode, chunkSize: Int = 5, recordFragmentation: Bool = false,
                               dohEnabled: Bool = false, rules: [SpoofProfile] = []) -> ProxyConfig {
        var master = SpoofProfile.makeDefault()
        master.splitMode = splitMode
        master.chunkSize = chunkSize
        master.tlsRecordFragmentation = recordFragmentation
        master.dohEnabled = dohEnabled
        return ProxyConfig(profiles: rules + [master], port: 0, allowLANAccess: false)
    }

    private func startProxy(splitMode: SplitMode, chunkSize: Int = 5, recordFragmentation: Bool = false,
                            resolver: FakeResolver? = nil, handshakeTimeout: TimeInterval = 10,
                            observer: ConnectionObserver? = nil) throws -> UInt16 {
        try startProxy(Self.config(splitMode: splitMode, chunkSize: chunkSize, recordFragmentation: recordFragmentation,
                                   dohEnabled: resolver != nil),
                       resolver: resolver, handshakeTimeout: handshakeTimeout, observer: observer)
    }

    private func startProxy(_ config: ProxyConfig, resolver: FakeResolver? = nil,
                            handshakeTimeout: TimeInterval = 10, observer: ConnectionObserver? = nil) throws -> UInt16 {

        let resolverCache = DoHResolverCache { url in
            guard let resolver else { preconditionFailure("DoH is off, but a resolver was requested for \(url)") }
            return resolver
        }
        // Short first-byte timer so the server-first tests (U7) don't wait the production 2 s.
        let server = ProxyServer(config: config, resolverCache: resolverCache,
                                 limits: Session.Limits(handshakeTimeout: handshakeTimeout, firstByteTimeout: 0.3),
                                 observer: observer)
        let started = expectation(description: "proxy ready")
        let failure = LockedBox<Error?>(nil)
        server.start { error in
            failure.value = error
            started.fulfill()
        }
        wait(for: [started], timeout: 5)
        if let error = failure.value { throw error }
        proxy = server
        return try XCTUnwrap(server.port)
    }

    private func startOrigin(_ behaviour: LoopbackOrigin.Behaviour, host: NWEndpoint.Host? = nil) throws -> LoopbackOrigin {
        let origin = try LoopbackOrigin(behaviour, host: host)
        origins.append(origin)
        return origin
    }

    /// Polls until the origin has received `count` bytes or the deadline passes.
    private func waitForOrigin(_ origin: LoopbackOrigin, count: Int, timeout: TimeInterval = 5) -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        while origin.received.count < count && Date() < deadline {
            usleep(10_000)
        }
        return origin.received
    }

    private func connectTunnel(proxyPort: UInt16, originPort: UInt16, host: String = "127.0.0.1") throws -> TestClient {
        let client = try TestClient(port: proxyPort)
        try client.send("CONNECT \(host):\(originPort) HTTP/1.1\r\nHost: \(host):\(originPort)\r\n\r\n")
        let reply = try client.read(through: Data("\r\n\r\n".utf8))
        XCTAssertEqual(String(decoding: reply, as: UTF8.self), "HTTP/1.1 200 Connection Established\r\n\r\n")
        return client
    }

    private static let crlf2 = Data("\r\n\r\n".utf8)

    // MARK: - Scenario 0: the harness itself

    func testProxyReportsEphemeralPort() throws {
        let port = try startProxy(splitMode: .none)
        XCTAssertNotEqual(port, 0)
    }

    func testGarbageGets400() throws {
        let port = try startProxy(splitMode: .none)
        let client = try TestClient(port: port)
        try client.send("NOT-HTTP\r\n\r\n")
        let reply = try client.read(through: Self.crlf2)
        XCTAssertTrue(String(decoding: reply, as: UTF8.self).hasPrefix("HTTP/1.1 400 Bad Request\r\n"))
        XCTAssertTrue(client.waitForClose())
    }

    // MARK: - Scenario 1: CONNECT + ClientHello in each split mode

    /// With record fragmentation off, every mode only changes TCP segmentation, which loopback
    /// coalesces, so the origin must see the original bytes exactly. Segment boundaries are
    /// covered by `TLSDesyncerTests`.
    func testConnectDeliversClientHelloUnchangedInEveryMode() throws {
        let hello = Fixtures.tls13ClientHello
        let tail = Data("application data after the hello".utf8)
        for mode in SplitMode.allCases {
            try XCTContext.runActivity(named: "mode \(mode.rawValue)") { _ in
                proxy?.stop()
                let origin = try startOrigin(.recordAll)
                let port = try startProxy(splitMode: mode, chunkSize: 7)
                let client = try connectTunnel(proxyPort: port, originPort: origin.port)
                try client.send(hello)
                try client.send(tail)
                let got = waitForOrigin(origin, count: hello.count + tail.count)
                XCTAssertEqual(got.count, hello.count + tail.count, "mode \(mode.rawValue)")
                XCTAssertEqual(got, hello + tail, "mode \(mode.rawValue)")
                client.close()
            }
        }
    }

    func testConnectWithRecordFragmentationPreservesHandshakePayload() throws {
        for mode in [SplitMode.chunk, .firstByte, .random] {
            try XCTContext.runActivity(named: "mode \(mode.rawValue)") { _ in
                let records = try fragmentedRecords(mode: mode)
                XCTAssertGreaterThan(records.count, 1, "mode \(mode.rawValue): the hello should arrive as several records")
                XCTAssertTrue(records.allSatisfy { $0.type == 0x16 })
                XCTAssertEqual(records.reduce(Data()) { $0 + $1.payload }, Fixtures.tls13ClientHello.dropFirst(5))
            }
        }
    }

    func testSNIModeWithRecordFragmentationSendsSeveralRecords() throws {
        let records = try fragmentedRecords(mode: .sni)
        XCTAssertEqual(records.reduce(Data()) { $0 + $1.payload }, Fixtures.tls13ClientHello.dropFirst(5))
        XCTAssertGreaterThan(records.count, 1)
        XCTAssertTrue(records.allSatisfy { $0.type == 0x16 })
    }

    /// Sends the TLS 1.3 hello through a fragmenting proxy and returns the records the origin got.
    private func fragmentedRecords(mode: SplitMode) throws -> [(type: UInt8, payload: Data)] {
        proxy?.stop()
        let hello = Fixtures.tls13ClientHello
        let origin = try startOrigin(.recordAll)
        let port = try startProxy(splitMode: mode, chunkSize: 100, recordFragmentation: true)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        defer { client.close() }
        try client.send(hello)

        // Each extra record adds a 5-byte header, so wait on the re-assembled payload, not the byte count.
        let deadline = Date().addingTimeInterval(5)
        var records: [(type: UInt8, payload: Data)] = []
        while Date() < deadline {
            records = Self.parseRecords(origin.received)
            if records.reduce(0, { $0 + $1.payload.count }) >= hello.count - 5 { break }
            usleep(10_000)
        }
        return records
    }

    /// Splits a stream of complete TLS records; stops at the first incomplete one.
    private static func parseRecords(_ data: Data) -> [(type: UInt8, payload: Data)] {
        let bytes = [UInt8](data)
        var records: [(UInt8, Data)] = []
        var i = 0
        while i + 5 <= bytes.count {
            let length = Int(bytes[i + 3]) << 8 | Int(bytes[i + 4])
            guard i + 5 + length <= bytes.count else { break }
            records.append((bytes[i], Data(bytes[(i + 5)..<(i + 5 + length)])))
            i += 5 + length
        }
        return records
    }

    func testConnectEchoRoundTrip() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .sni)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        try client.send(Fixtures.tls12ClientHello)
        XCTAssertEqual(try client.read(count: Fixtures.tls12ClientHello.count), Fixtures.tls12ClientHello)
        try client.send("ping")
        XCTAssertEqual(try client.read(count: 4), Data("ping".utf8))
    }

    /// N15: the reader decides on the first byte, so a first message shorter than a TLS header
    /// (and a client that then waits for a reply) is forwarded at once.
    func testShortFirstClientWriteIsForwarded() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .sni)
        for route in ["CONNECT", "SOCKS5"] {
            try XCTContext.runActivity(named: route) { _ in
                let client = route == "CONNECT"
                    ? try connectTunnel(proxyPort: port, originPort: origin.port)
                    : try socksTunnel(proxyPort: port, target: .ipv4, originPort: origin.port)
                try client.send("ping")
                let got = try? client.read(count: 4, timeout: 1)
                XCTAssertEqual(got, Data("ping".utf8), route)
                client.close()
            }
        }
    }

    func testConnectToClosedPortClosesClient() throws {
        // Grab a free port, then close its listener so nothing is listening there.
        let probe = try LoopbackOrigin(.recordAll)
        let deadPort = probe.port
        probe.stop()

        let port = try startProxy(splitMode: .none)
        let client = try TestClient(port: port)
        try client.send("CONNECT 127.0.0.1:\(deadPort) HTTP/1.1\r\n\r\n")
        // The tunnel dials before replying, so the refusal is a 502, not 200 and a reset.
        // A refused dial puts NWConnection in .waiting, which the dialer treats as a failure (N11).
        let reply = try client.read(through: Self.crlf2, timeout: 2)
        XCTAssertTrue(String(decoding: reply, as: UTF8.self).hasPrefix("HTTP/1.1 502 Bad Gateway\r\n"))
        XCTAssertTrue(client.waitForClose(timeout: 2))
    }

    // MARK: - Scenario 1b: the DoH path, through FakeResolver (step 4b)

    func testConnectThroughDoHUsesResolvedAddress() throws {
        let origin = try startOrigin(.echo)
        let resolver = FakeResolver(["origin.test": ["127.0.0.1"]])
        let port = try startProxy(splitMode: .none, resolver: resolver)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port, host: "origin.test")
        try client.send("hello origin")
        XCTAssertEqual(try client.read(count: 12), Data("hello origin".utf8))
        XCTAssertEqual(resolver.queries, ["origin.test"])
    }

    func testDoHWithIPv6OnlyAnswerConnects() throws {
        // N10: AAAA answers are dialed too.
        let origin = try startOrigin(.echo, host: "::1")
        let resolver = FakeResolver(["v6.test": ["::1"]])
        let port = try startProxy(splitMode: .none, resolver: resolver)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port, host: "v6.test")
        try client.send("hello origin")
        XCTAssertEqual(try client.read(count: 12), Data("hello origin".utf8))
    }

    func testDeadFirstAddressFallsBackToTheNext() throws {
        // N10/N11: the IPv4 address is refused (the origin only listens on ::1); the dialer moves on.
        let origin = try startOrigin(.echo, host: "::1")
        let resolver = FakeResolver(["both.test": ["127.0.0.1", "::1"]])
        let port = try startProxy(splitMode: .none, resolver: resolver)
        let started = Date()
        let client = try connectTunnel(proxyPort: port, originPort: origin.port, host: "both.test")
        try client.send("hello origin")
        XCTAssertEqual(try client.read(count: 12), Data("hello origin".utf8))
        XCTAssertLessThan(Date().timeIntervalSince(started), 2, "fallback must not wait for a timeout")
    }

    // MARK: - Observer (network-scanner step 5d)

    func testObserverSeesTheDialRace() throws {
        let origin = try startOrigin(.echo, host: "::1")
        let resolver = FakeResolver(["both.test": ["127.0.0.1", "::1"]])
        let observer = RecordingObserver()
        let port = try startProxy(splitMode: .none, resolver: resolver, observer: observer)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port, host: "both.test")
        try client.send("hello origin")
        XCTAssertEqual(try client.read(count: 12), Data("hello origin".utf8))
        client.close()

        XCTAssertTrue(eventually { observer.summaries.count == 1 })
        let summary = try XCTUnwrap(observer.summaries.first)
        XCTAssertEqual(summary.start.host, "both.test")
        XCTAssertEqual(summary.start.outbound, .direct)
        XCTAssertEqual(summary.reached, .responding, "the echo came back")
        XCTAssertEqual(summary.bytesUp, 12)
        XCTAssertEqual(summary.bytesDown, 12)
        XCTAssertEqual(summary.applied, .passthrough(.splitNone))
        XCTAssertNotNil(summary.payloadSentAt)
        XCTAssertNotNil(summary.tFirstDown)
        XCTAssertEqual(summary.dohIPs, ["127.0.0.1", "::1"])
        XCTAssertEqual(summary.connectedAddress, "::1")
        XCTAssertEqual(summary.attempts.map(\.address), ["127.0.0.1", "::1"])
        XCTAssertEqual(summary.attempts.last?.outcome, .ready)
        if case .failed = summary.attempts.first?.outcome {} else {
            XCTFail("the IPv4 attempt should have failed: \(String(describing: summary.attempts.first))")
        }
        XCTAssertEqual(summary.endReason, .clientClosed)
        XCTAssertEqual(observer.refusals.count, 0)
    }

    func testObserverSeesARefusedDial() throws {
        let probe = try LoopbackOrigin(.recordAll)
        let deadPort = probe.port
        probe.stop()

        let observer = RecordingObserver()
        let port = try startProxy(splitMode: .none, observer: observer)
        let client = try TestClient(port: port)
        try client.send("CONNECT 127.0.0.1:\(deadPort) HTTP/1.1\r\n\r\n")
        XCTAssertTrue(client.waitForClose(timeout: 2))
        XCTAssertTrue(eventually { observer.summaries.count == 1 })
        let summary = try XCTUnwrap(observer.summaries.first)
        XCTAssertTrue(summary.start.isIPLiteral)
        XCTAssertNil(summary.dnsStart, "an IP literal skips DNS")
        XCTAssertEqual(summary.reached, .connecting)
        XCTAssertEqual(summary.endReason, .connectFailed(.refused))
    }

    func testIPLiteralSkipsDoH() throws {
        // N10: the resolver is never asked about an address.
        let origin = try startOrigin(.echo)
        let resolver = FakeResolver([:])
        let port = try startProxy(splitMode: .none, resolver: resolver)
        for host in ["127.0.0.1", "[::1]"] {
            let client = try connectTunnel(proxyPort: port, originPort: origin.port, host: host)
            try client.send("hello origin")
            XCTAssertEqual(try client.read(count: 12), Data("hello origin".utf8), host)
            client.close()
        }
        let socks = try socksTunnel(proxyPort: port, target: .ipv6, originPort: origin.port)
        try socks.send("hello origin")
        XCTAssertEqual(try socks.read(count: 12), Data("hello origin".utf8))
        XCTAssertEqual(resolver.queries, [])
    }

    func testUnresolvedNameFallsBackToSystemResolver() throws {
        let origin = try startOrigin(.echo)
        let resolver = FakeResolver([:])
        let port = try startProxy(splitMode: .none, resolver: resolver)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port, host: "localhost")
        try client.send("hello origin")
        XCTAssertEqual(try client.read(count: 12), Data("hello origin".utf8))
        XCTAssertEqual(resolver.queries, ["localhost"])
    }

    // MARK: - Scenario 2: SOCKS5 with domain, IPv4 and IPv6 targets

    private enum SOCKSTarget {
        case domain(String), ipv4, ipv6

        func request(port: UInt16) -> Data {
            var data = Data([0x05, 0x01, 0x00])
            switch self {
            case .domain(let name):
                data.append(0x03)
                data.append(UInt8(name.utf8.count))
                data.append(contentsOf: name.utf8)
            case .ipv4:
                data.append(contentsOf: [0x01, 127, 0, 0, 1])
            case .ipv6:
                data.append(0x04)
                data.append(contentsOf: [UInt8](repeating: 0, count: 15) + [1])
            }
            data.append(UInt8(port >> 8))
            data.append(UInt8(port & 0xFF))
            return data
        }
    }

    private func socksTunnel(proxyPort: UInt16, target: SOCKSTarget, originPort: UInt16) throws -> TestClient {
        let client = try TestClient(port: proxyPort)
        // One step at a time, as most clients do; the pipelined form is in `SessionTests` (N6).
        try client.send(Data([0x05, 0x01, 0x00]))
        XCTAssertEqual(try client.read(count: 2), Data([0x05, 0x00]))
        try client.send(target.request(port: originPort))
        let reply = try client.read(count: 10)
        XCTAssertEqual(reply, Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), "SOCKS5 success reply")
        return client
    }

    func testSOCKS5EchoForEachAddressType() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .sni)
        for target in [SOCKSTarget.domain("localhost"), .ipv4, .ipv6] {
            try XCTContext.runActivity(named: "\(target)") { _ in
                let client = try socksTunnel(proxyPort: port, target: target, originPort: origin.port)
                try client.send("hello origin")
                XCTAssertEqual(try client.read(count: 12), Data("hello origin".utf8), "\(target)")
                client.close()
            }
        }
    }

    func testSOCKS5ClientHelloIsDeliveredUnchanged() throws {
        let origin = try startOrigin(.recordAll)
        let port = try startProxy(splitMode: .sni)
        let client = try socksTunnel(proxyPort: port, target: .ipv4, originPort: origin.port)
        try client.send(Fixtures.tls13ClientHello)
        XCTAssertEqual(waitForOrigin(origin, count: Fixtures.tls13ClientHello.count), Fixtures.tls13ClientHello)
    }

    func testSOCKS5UnsupportedCommandGets0x07() throws {
        let port = try startProxy(splitMode: .sni)
        let client = try TestClient(port: port)
        try client.send(Data([0x05, 0x01, 0x00]))
        XCTAssertEqual(try client.read(count: 2), Data([0x05, 0x00]))
        try client.send(Data([0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])) // BIND
        XCTAssertEqual(try client.read(count: 2), Data([0x05, 0x07]))
        XCTAssertTrue(client.waitForClose())
    }

    func testSOCKS5NoAcceptableMethodGets0xFF() throws {
        let port = try startProxy(splitMode: .sni)
        let client = try TestClient(port: port)
        try client.send(Data([0x05, 0x01, 0x02])) // username/password only
        XCTAssertEqual(try client.read(count: 2), Data([0x05, 0xFF]))
        XCTAssertTrue(client.waitForClose())
    }

    func testSOCKS4ClientGetsRequestRejected() throws {
        let port = try startProxy(splitMode: .sni)
        let client = try TestClient(port: port)
        try client.send(Data([0x04, 0x01, 0x01, 0xBB, 127, 0, 0, 1, 0]))
        XCTAssertEqual(try client.read(count: 8), Data([0x00, 0x5B, 0, 0, 0, 0, 0, 0]))
        XCTAssertTrue(client.waitForClose())
    }

    // MARK: - Scenario 3: plain HTTP absolute-form

    private func plainHTTPRequest(originPort: UInt16) -> String {
        "GET http://127.0.0.1:\(originPort)/path?q=1 HTTP/1.1\r\n"
            + "Host: 127.0.0.1:\(originPort)\r\n"
            + "Proxy-Connection: keep-alive\r\n"
            + "Accept: */*\r\n\r\n"
    }

    func testPlainHTTPReachesOriginAndResponseReturns() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .sni)
        let client = try TestClient(port: port)
        try client.send(plainHTTPRequest(originPort: origin.port))
        // The echo origin returns whatever it was sent, so this is also the upstream request.
        let upstream = try client.read(through: Self.crlf2)
        XCTAssertTrue(String(decoding: upstream, as: UTF8.self).hasPrefix("GET "))
        XCTAssertTrue(String(decoding: upstream, as: UTF8.self).contains("Host: 127.0.0.1:\(origin.port)\r\n"))
    }

    func testPlainHTTPIsRewrittenToOriginForm() throws {
        let origin = try startOrigin(.recordAll)
        let port = try startProxy(splitMode: .sni)
        let client = try TestClient(port: port)
        try client.send(plainHTTPRequest(originPort: origin.port))
        let head = String(decoding: waitForOrigin(origin, count: 1), as: UTF8.self)
        XCTAssertFalse(head.isEmpty, "the origin got nothing")

        XCTAssertTrue(head.hasPrefix("GET /path?q=1 HTTP/1.1\r\n"), head)
        XCTAssertFalse(head.lowercased().contains("proxy-connection"), head)
        XCTAssertTrue(head.contains("\r\nConnection: close\r\n"), head)
    }

    /// N9: a head longer than one read, and sent in pieces, still parses.
    func testLongPlainHTTPHeadSplitAcrossWrites() throws {
        let origin = try startOrigin(.recordAll)
        let port = try startProxy(splitMode: .none)
        let client = try TestClient(port: port)
        let request = "GET http://127.0.0.1:\(origin.port)/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            + "Cookie: \(String(repeating: "c", count: 20_000))\r\n\r\n"
        let bytes = Data(request.utf8)
        try client.send(bytes.prefix(10_000))
        usleep(50_000)
        try client.send(bytes.dropFirst(10_000))
        let head = String(decoding: waitForOrigin(origin, count: bytes.count - 4), as: UTF8.self)
        XCTAssertTrue(head.hasPrefix("GET / HTTP/1.1\r\n"), String(head.prefix(40)))
        XCTAssertTrue(head.hasSuffix("Connection: close\r\n\r\n"))
    }

    // MARK: - Handshake deadline (N8) and pipelining (N6)

    func testSilentClientIsClosedByTheHandshakeDeadline() throws {
        let port = try startProxy(splitMode: .sni, handshakeTimeout: 0.3)
        let client = try TestClient(port: port)
        XCTAssertTrue(client.waitForClose(timeout: 2))
        XCTAssertTrue(eventually(timeout: 2) { self.proxy?.activeSessionCount == 0 })
    }

    func testPartialClientHelloIsClosedByTheDeadline() throws {
        let origin = try startOrigin(.recordAll)
        let port = try startProxy(splitMode: .sni, handshakeTimeout: 0.3)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        // A TLS header announcing a record that never completes.
        try client.send(Fixtures.tls13ClientHello.prefix(8))
        XCTAssertTrue(client.waitForClose(timeout: 2))
        XCTAssertEqual(origin.received, Data(), "nothing is forwarded from a half ClientHello")
    }

    func testSOCKS5PipelinedGreetingRequestAndHello() throws {
        let origin = try startOrigin(.recordAll)
        let port = try startProxy(splitMode: .sni)
        let client = try TestClient(port: port)
        try client.send(Data([0x05, 0x01, 0x00]) + SOCKSTarget.ipv4.request(port: origin.port) + Fixtures.tls13ClientHello)
        XCTAssertEqual(try client.read(count: 12), Data([0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        XCTAssertEqual(waitForOrigin(origin, count: Fixtures.tls13ClientHello.count), Fixtures.tls13ClientHello)
    }

    // MARK: - Scenario 4: server-first origin over CONNECT

    func testServerFirstBannerReachesClientInModeNone() throws {
        let banner = Data("SSH-2.0-OpenSSH_9.6\r\n".utf8)
        let origin = try startOrigin(.serverFirst(banner))
        let port = try startProxy(splitMode: .none)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        XCTAssertEqual(try client.read(count: banner.count), banner)
    }

    func testServerFirstBannerReachesClientInSplitMode() throws {
        let banner = Data("SSH-2.0-OpenSSH_9.6\r\n".utf8)
        let origin = try startOrigin(.serverFirst(banner))
        let port = try startProxy(splitMode: .sni)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        // The client says nothing; after the first-byte timer the tunnel dials and relays as-is.
        XCTAssertEqual(try client.read(count: banner.count, timeout: 2), banner)
        // The client read left in flight by the timer carries on into the relay.
        try client.send("hello")
        XCTAssertTrue(eventually { origin.received.suffix(5) == Data("hello".utf8) })
    }

    func testNonTLSClientFirstBytesPassThroughInSplitMode() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .sni)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        // 0x53 'S' isn't a TLS record type, so the bytes go through unmodified.
        let line = Data("SSH-2.0-client\r\n".utf8)
        try client.send(line)
        XCTAssertEqual(try client.read(count: line.count, timeout: 1), line)
    }

    // MARK: - Scenario 5: connection cap and stop()

    /// Each idle client costs two descriptors in this process (client side and proxy side).
    /// GUI-launched test runners can start with a soft limit of 256.
    private func raiseFileDescriptorLimit(to wanted: rlim_t) {
        var limit = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limit) == 0, limit.rlim_cur < wanted else { return }
        limit.rlim_cur = min(wanted, limit.rlim_max)
        setrlimit(RLIMIT_NOFILE, &limit)
    }

    func testConnectionCapAdmitsExactly200() throws {
        raiseFileDescriptorLimit(to: 4096)
        let observer = RecordingObserver()
        let port = try startProxy(splitMode: .sni, observer: observer)
        let cap = ProxyServer.maxConcurrentConnections
        let clients = try (0..<(cap + 50)).map { _ in try TestClient(port: port) }

        XCTAssertTrue(eventually { clients.filter(\.isClosedByPeer).count == 50 },
                      "closed: \(clients.filter(\.isClosedByPeer).count)")
        XCTAssertEqual(observer.refusals.map(\.reason), Array(repeating: .overCapacity, count: 50))
        XCTAssertTrue(observer.refusals.allSatisfy { $0.inbound == nil && $0.target == nil })
        XCTAssertEqual(proxy?.activeSessionCount, cap)
        // No late admissions or extra rejections after things settle.
        usleep(200_000)
        XCTAssertEqual(clients.filter(\.isClosedByPeer).count, 50)
        XCTAssertEqual(proxy?.activeSessionCount, cap)

        // Closing admitted clients frees their slots.
        clients.filter { !$0.isClosedByPeer }.prefix(10).forEach { $0.close() }
        XCTAssertTrue(eventually { self.proxy?.activeSessionCount == cap - 10 })
        let late = try TestClient(port: port)
        XCTAssertFalse(late.waitForClose(timeout: 0.3), "a freed slot should admit a new client")

        proxy?.stop()
        // The 10 closed locally see their own cancel as EOF too, so every client ends up closed.
        XCTAssertTrue(eventually { clients.allSatisfy(\.isClosedByPeer) },
                      "stop() should close every admitted client")
        XCTAssertTrue(late.waitForClose())
    }

    func testStopClosesSessionsInEveryPhase() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .sni)

        // Relaying: a CONNECT tunnel with an upstream connection.
        let relaying = try connectTunnel(proxyPort: port, originPort: origin.port)
        try relaying.send(Fixtures.tls12ClientHello)
        _ = try relaying.read(count: Fixtures.tls12ClientHello.count)
        // Idle: connected, never sent a byte.
        let idle = try TestClient(port: port)
        // Mid-handshake: SOCKS5 greeting answered, no request yet.
        let handshaking = try TestClient(port: port)
        try handshaking.send(Data([0x05, 0x01, 0x00]))
        XCTAssertEqual(try handshaking.read(count: 2), Data([0x05, 0x00]))

        XCTAssertTrue(eventually { self.proxy?.activeSessionCount == 3 })
        proxy?.stop()

        XCTAssertTrue(relaying.waitForClose(), "relaying client")
        XCTAssertTrue(idle.waitForClose(), "idle client")
        XCTAssertTrue(handshaking.waitForClose(), "handshaking client")
        XCTAssertTrue(eventually { origin.closedCount == 1 }, "the upstream connection should be closed too")
        XCTAssertEqual(proxy?.activeSessionCount, 0)
        XCTAssertNil(proxy?.port, "the listener should be gone")
    }

    func testSessionSlotIsReleasedWhenClientCloses() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .none)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        try client.send("hello origin")
        _ = try client.read(count: 12)
        XCTAssertEqual(proxy?.activeSessionCount, 1)
        client.close()
        XCTAssertTrue(eventually { self.proxy?.activeSessionCount == 0 })
        XCTAssertTrue(eventually { origin.closedCount == 1 })
    }

    // MARK: - Scenario 6: the VPN route

    /// Master on the VPN route through `server`.
    private static func vpnConfig(_ server: OutlineServerConfig) -> ProxyConfig {
        var master = SpoofProfile.makeDefault()
        master.routeMode = .vpn
        master.outlineConfig = server
        return ProxyConfig(profiles: [master], port: 0, allowLANAccess: false)
    }

    private func startShadowsocksServer() throws -> LoopbackShadowsocksServer {
        let server = try LoopbackShadowsocksServer()
        shadowsocksServers.append(server)
        return server
    }

    func testVPNRouteEchoRoundTrip() throws {
        let origin = try startOrigin(.echo)
        let server = try startShadowsocksServer()
        let port = try startProxy(Self.vpnConfig(server.config))
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        try client.send(Fixtures.tls13ClientHello)
        XCTAssertEqual(try client.read(count: Fixtures.tls13ClientHello.count), Fixtures.tls13ClientHello,
                       "the VPN route doesn't desync, so the hello arrives in one piece")
        // Several AEAD chunks each way.
        let big = Data((0..<100_000).map { UInt8(truncatingIfNeeded: $0) })
        try client.send(big)
        XCTAssertEqual(try client.read(count: big.count), big)
        XCTAssertEqual(server.targets, ["127.0.0.1:\(origin.port)"])
    }

    /// Without DoH the domain goes to the server in the address header, unresolved.
    func testVPNRouteSendsTheDomainInTheHeader() throws {
        let origin = try startOrigin(.echo)
        let server = try startShadowsocksServer()
        let port = try startProxy(Self.vpnConfig(server.config))
        let client = try socksTunnel(proxyPort: port, target: .domain("localhost"), originPort: origin.port)
        try client.send("hello")
        XCTAssertEqual(try client.read(count: 5), Data("hello".utf8))
        XCTAssertEqual(server.targets, ["localhost:\(origin.port)"])
    }

    /// N4: the server learns the target without client data, so a server-first protocol works.
    func testVPNRouteServerFirstBannerReachesClient() throws {
        let banner = Data("220 smtp.example ESMTP\r\n".utf8)
        let origin = try startOrigin(.serverFirst(banner))
        let server = try startShadowsocksServer()
        let port = try startProxy(Self.vpnConfig(server.config))
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        XCTAssertEqual(try client.read(count: banner.count, timeout: 2), banner)
        try client.send("EHLO me\r\n")
        XCTAssertTrue(eventually { origin.received == Data("EHLO me\r\n".utf8) })
    }

    /// Plain HTTP writes the request as soon as the server is connected, so it rides with the
    /// header in one write instead of after it.
    func testVPNRouteCoalescesTheHeaderWithTheFirstClientData() throws {
        let origin = try startOrigin(.echo)
        let server = try startShadowsocksServer()
        let port = try startProxy(Self.vpnConfig(server.config))
        let client = try TestClient(port: port)
        let request = plainHTTPRequest(originPort: origin.port)
        try client.send(request)
        _ = try client.read(through: Self.crlf2)
        // Salt, then the length frame and the payload frame of a 7-byte IPv4 header.
        let headerOnly = 32 + (2 + ShadowsocksCrypto.tagLength) + (7 + ShadowsocksCrypto.tagLength)
        XCTAssertGreaterThan(try XCTUnwrap(server.firstReadSizes.first), headerOnly)
    }

    /// Opt-in interop with a real server (plan §5.3 scenario 6), for example
    /// `docker run --rm -p 8388:8388 ghcr.io/shadowsocks/ssserver-rust ssserver -s 0.0.0.0:8388 -m chacha20-ietf-poly1305 -k pw`
    /// with `SPOOFY_SS_TEST_KEY=ss://…@127.0.0.1:8388`. The server reaches the local origin as
    /// `SPOOFY_SS_TEST_ORIGIN_HOST` (default `host.docker.internal`).
    func testInteropWithARealShadowsocksServer() throws {
        let env = ProcessInfo.processInfo.environment
        guard let key = env["SPOOFY_SS_TEST_KEY"] else { throw XCTSkip("set SPOOFY_SS_TEST_KEY to run") }
        let originHost = env["SPOOFY_SS_TEST_ORIGIN_HOST"] ?? "host.docker.internal"
        let config = try OutlineAccessKey.decode(key)

        let echo = try startOrigin(.echo)
        let banner = Data("220 interop ESMTP\r\n".utf8)
        let serverFirst = try startOrigin(.serverFirst(banner))
        let port = try startProxy(Self.vpnConfig(config))

        let client = try connectTunnel(proxyPort: port, originPort: echo.port, host: originHost)
        let big = Data((0..<100_000).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        try client.send(big)
        XCTAssertEqual(try client.read(count: big.count, timeout: 10), big)

        let quiet = try connectTunnel(proxyPort: port, originPort: serverFirst.port, host: originHost)
        XCTAssertEqual(try quiet.read(count: banner.count, timeout: 5), banner, "N4")
    }

    // MARK: - U13: a settings change reaches open connections

    /// Disabling or enabling a rule must not leave open tunnels on their old route: the ones
    /// whose route changed are closed so the client reconnects. The others stay open, including
    /// a relaying tunnel whose only change is the desync mode.
    func testConfigUpdateClosesSessionsWhoseRouteChanged() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .none)
        let kept = try connectTunnel(proxyPort: port, originPort: origin.port, host: "127.0.0.1")
        let moved = try connectTunnel(proxyPort: port, originPort: origin.port, host: "localhost")
        for client in [kept, moved] {
            try client.send("hello origin")
            XCTAssertEqual(try client.read(count: 12), Data("hello origin".utf8))
        }

        // localhost now goes to a VPN route with no server, so it would be rejected.
        var rule = SpoofProfile.makeDefault()
        rule.id = UUID()
        rule.isDefault = false
        rule.domainPatterns = ["localhost"]
        rule.routeMode = .vpn
        proxy?.update(Self.config(splitMode: .sni, rules: [rule]))

        XCTAssertTrue(moved.waitForClose(), "the re-routed tunnel should be closed")
        XCTAssertFalse(kept.waitForClose(timeout: 0.3), "an unchanged route stays open")
        try kept.send("still here")
        XCTAssertEqual(try kept.read(count: 10), Data("still here".utf8))
        XCTAssertTrue(eventually { self.proxy?.activeSessionCount == 1 })

        // New connections use the new snapshot.
        let rejected = try TestClient(port: port)
        try rejected.send("CONNECT localhost:\(origin.port) HTTP/1.1\r\nHost: localhost\r\n\r\n")
        let reply = try rejected.read(through: Data("\r\n\r\n".utf8))
        XCTAssertTrue(String(decoding: reply, as: UTF8.self).hasPrefix("HTTP/1.1 502"))
    }

    // MARK: - Payload and end reasons (network-scanner step 5e)

    func testObserverSeesTheHelloAndTheServersFinish() throws {
        let origin = try startOrigin(.replyAndFinish(Data([0x16, 0x03, 0x03, 0x00, 0x01, 0x02])))
        let observer = RecordingObserver()
        let port = try startProxy(splitMode: .firstByte, observer: observer)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port, host: "127.0.0.1")
        let hello = ClientHelloBuilder.make(sni: "www.example.com")
        try client.send(hello)
        XCTAssertEqual(try client.read(count: 6).count, 6)
        XCTAssertTrue(client.waitForClose(timeout: 2), "the server's FIN is forwarded")
        client.close()

        XCTAssertTrue(eventually { observer.summaries.count == 1 })
        let summary = try XCTUnwrap(observer.summaries.first)
        if case .tls(let info) = summary.kind { XCTAssertEqual(info.sni, "www.example.com") } else {
            XCTFail("kind \(summary.kind)")
        }
        if case .desync = summary.applied {} else { XCTFail("applied \(String(describing: summary.applied))") }
        XCTAssertEqual(summary.reached, .responding)
        XCTAssertEqual(summary.bytesDown, 6)
        XCTAssertEqual(summary.endReason, .serverFin)
        XCTAssertNotNil(summary.establishment.tcpRTT, "the establishment report is read on loopback too")
    }

    func testObserverSeesTheServersReset() throws {
        let origin = try startOrigin(.resetOnData)
        let observer = RecordingObserver()
        let port = try startProxy(splitMode: .none, observer: observer)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port, host: "127.0.0.1")
        try client.send("hello origin")
        XCTAssertTrue(client.waitForClose(timeout: 2))

        XCTAssertTrue(eventually { observer.summaries.count == 1 })
        let summary = try XCTUnwrap(observer.summaries.first)
        XCTAssertEqual(summary.reached, .payloadSent)
        XCTAssertEqual(summary.endReason, .serverReset)
    }

    // MARK: - Outcomes (network-scanner step 5f)

    /// Short waits so a blackhole doesn't take 3 s; loopback RTT is under 10 ms, so nothing is
    /// ever "early" here (the timing rules are covered by `TraceClassifierTests`).
    private static let quickDetection: DetectionConfig = {
        var config = DetectionConfig.standard
        config.helloBlackholeMin = 0.3
        return config
    }()

    private static let hello = ClientHelloBuilder.make(sni: "www.example.com")

    /// Sends a ClientHello to an origin with `behaviour` through a desync route and returns the
    /// host's latest outcome. `then` runs after the hello is sent; the client is closed after it.
    private func outcome(for behaviour: LoopbackOrigin.Behaviour, socks: Bool = false,
                         then: (TestClient) throws -> Void = { _ in }) throws -> TraceOutcome? {
        let origin = try startOrigin(behaviour)
        let log = ConnectionLog(config: Self.quickDetection, reportWait: 0.2)
        let port = try startProxy(splitMode: .firstByte, observer: log)
        let client = socks ? try socksTunnel(proxyPort: port, target: .ipv4, originPort: origin.port)
                           : try connectTunnel(proxyPort: port, originPort: origin.port)
        try client.send(Self.hello)
        try then(client)
        client.close()
        XCTAssertTrue(eventually { log.snapshot().hosts["127.0.0.1"] != nil })
        XCTAssertTrue(log.snapshot().active.isEmpty)
        return log.snapshot().hosts["127.0.0.1"]?.recent.elements.last?.outcome
    }

    func testResetAfterTheHelloIsHelloReset() throws {
        let result = try outcome(for: .resetOnData) { XCTAssertTrue($0.waitForClose(timeout: 2)) }
        XCTAssertEqual(result?.kind, .helloReset(early: false))
    }

    func testFINAfterTheHelloIsHelloSilentClose() throws {
        let result = try outcome(for: .finishOnData, socks: true) { XCTAssertTrue($0.waitForClose(timeout: 2)) }
        XCTAssertEqual(result?.kind, .helloSilentClose(early: false))
    }

    func testSilenceAfterTheHelloIsHelloBlackhole() throws {
        let result = try outcome(for: .recordAll) { _ in Thread.sleep(forTimeInterval: 0.5) }
        XCTAssertEqual(result?.kind, .helloBlackhole(retransmits: false))
    }

    func testClientLeavingQuicklyIsNotABlackhole() throws {
        XCTAssertEqual(try outcome(for: .recordAll)?.kind, .clientAborted)
    }

    func testHTTPOnTheTLSTunnelIsInjected() throws {
        let page = Data("HTTP/1.1 302 Found\r\nLocation: http://warning.example/\r\n\r\n".utf8)
        let result = try outcome(for: .replyOnData(page)) { XCTAssertEqual(try $0.read(count: page.count), page) }
        XCTAssertEqual(result?.kind, .injectedResponse(.httpOnTLS))
    }

    func testAnsweredHelloIsOK() throws {
        let result = try outcome(for: .echo, socks: true) { XCTAssertEqual(try $0.read(count: Self.hello.count).count, Self.hello.count) }
        XCTAssertEqual(result?.kind, .ok)
    }

    func testRefusedDialIsConnectRefused() throws {
        let probe = try LoopbackOrigin(.recordAll)
        let deadPort = probe.port
        probe.stop()
        let log = ConnectionLog(config: Self.quickDetection, reportWait: 0.2)
        let port = try startProxy(splitMode: .firstByte, observer: log)
        let client = try TestClient(port: port)
        try client.send("CONNECT 127.0.0.1:\(deadPort) HTTP/1.1\r\n\r\n")
        XCTAssertTrue(client.waitForClose(timeout: 2))
        XCTAssertTrue(eventually { log.snapshot().hosts["127.0.0.1"] != nil })
        XCTAssertEqual(log.snapshot().hosts["127.0.0.1"]?.recent.elements.last?.outcome.kind, .connectRefused)
    }

    func testRefusalsReachTheLog() throws {
        let log = ConnectionLog()
        let port = try startProxy(splitMode: .none, observer: log)
        let client = try TestClient(port: port)
        try client.send(Data([0x04, 0x01, 0x00, 0x50, 1, 2, 3, 4, 0x00]))
        XCTAssertEqual(try client.read(count: 8).prefix(2), Data([0x00, 0x5B]))
        XCTAssertTrue(eventually { log.snapshot().refusals[.socks4]?.count == 1 })
        XCTAssertEqual(log.snapshot().refusals[.socks4]?.targets, [DialTarget(host: "1.2.3.4", port: 80)])
        XCTAssertTrue(log.snapshot().hosts.isEmpty)
    }
}
