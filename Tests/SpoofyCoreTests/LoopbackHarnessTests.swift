import Network
import XCTest
@testable import SpoofyCore

/// Plan §5.3: test client → real `ProxyServer` on 127.0.0.1:0 → `LoopbackOrigin`.
/// This is the contract the step-4d handler rewrite must keep. DoH is off and every target
/// is a loopback literal or `localhost`, so nothing leaves the machine.
final class LoopbackHarnessTests: XCTestCase {
    private var suiteName: String!
    private var settings: AppSettings!
    private var proxy: ProxyServer?
    private var origins: [LoopbackOrigin] = []

    override func setUp() {
        super.setUp()
        suiteName = "SpoofyLoopbackTests.\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suiteName)!)
    }

    override func tearDown() {
        proxy?.stop()
        origins.forEach { $0.stop() }
        UserDefaults().removePersistentDomain(forName: suiteName)
        super.tearDown()
    }

    // MARK: - Fixture

    private func startProxy(splitMode: SplitMode, chunkSize: Int = 5, recordFragmentation: Bool = false) throws -> UInt16 {
        var master = SpoofProfile.makeDefault()
        master.splitMode = splitMode
        master.chunkSize = chunkSize
        master.tlsRecordFragmentation = recordFragmentation
        master.dohEnabled = false
        settings.profiles = [master]
        settings.allowLANAccess = false

        let server = ProxyServer(port: 0, settings: settings)
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

    private func startOrigin(_ behaviour: LoopbackOrigin.Behaviour) throws -> LoopbackOrigin {
        let origin = try LoopbackOrigin(behaviour)
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
        XCTAssertEqual(String(decoding: reply, as: UTF8.self), "HTTP/1.1 400 Bad Request\r\n\r\n")
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
        XCTExpectFailure("U8: SNI mode ignores record fragmentation") {
            XCTAssertGreaterThan(records.count, 1)
        }
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

    /// The first client read asks for at least 5 bytes (a TLS header), so a protocol whose first
    /// message is shorter, and that waits for a reply, stalls until the idle timeout.
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
                XCTExpectFailure("N15: the first read waits for 5 bytes") {
                    XCTAssertEqual(got, Data("ping".utf8), route)
                }
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
        // mode=none: the 200 goes out before the dial, then the client is dropped.
        _ = try client.read(through: Self.crlf2)
        // A refused dial leaves NWConnection in .waiting, which the handler ignores until its 10 s timeout.
        let closed = client.waitForClose(timeout: 2)
        XCTExpectFailure("N11: a refused connection waits out the 10 s dial timeout") {
            XCTAssertTrue(closed)
        }
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
        // Wait for the method reply before the request: the current handler can't take them pipelined (N6).
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

        XCTExpectFailure("N9: the absolute-form request is forwarded as-is") {
            XCTAssertTrue(head.hasPrefix("GET /path?q=1 HTTP/1.1\r\n"), head)
            XCTAssertFalse(head.lowercased().contains("proxy-connection"), head)
            XCTAssertTrue(head.contains("\r\nConnection: close\r\n"), head)
        }
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
        // The split path waits for a ClientHello before it even dials, so the banner never comes.
        let got = try? client.read(count: banner.count, timeout: 1)
        XCTExpectFailure("U7: CONNECT in a split mode has no passthrough for server-first protocols") {
            XCTAssertEqual(got, banner)
        }
    }

    func testNonTLSClientFirstBytesPassThroughInSplitMode() throws {
        let origin = try startOrigin(.echo)
        let port = try startProxy(splitMode: .sni)
        let client = try connectTunnel(proxyPort: port, originPort: origin.port)
        // 0x53 'S' isn't a TLS record type, but the handler parses bytes 3..4 as a record length.
        let line = Data("SSH-2.0-client\r\n".utf8)
        try client.send(line)
        let got = try? client.read(count: line.count, timeout: 1)
        XCTExpectFailure("U7: CONNECT in a split mode treats non-TLS first bytes as a TLS header") {
            XCTAssertEqual(got, line)
        }
    }

    // MARK: - Scenario 5: connection cap and stop()

    /// Polls `condition` every 10 ms until it holds or the deadline passes; returns its final value.
    private func eventually(timeout: TimeInterval = 5, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            usleep(10_000)
        }
        return condition()
    }

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
        let port = try startProxy(splitMode: .sni)
        let cap = ProxyServer.maxConcurrentConnections
        let clients = try (0..<(cap + 50)).map { _ in try TestClient(port: port) }

        XCTAssertTrue(eventually { clients.filter(\.isClosedByPeer).count == 50 },
                      "closed: \(clients.filter(\.isClosedByPeer).count)")
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
}
