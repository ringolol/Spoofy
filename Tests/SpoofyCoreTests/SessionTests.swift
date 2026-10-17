import Network
import XCTest
@testable import SpoofyCore

/// Plan §5.2: the session pipeline over fake connections. The fakes work at the `send` level,
/// so segmentation is exact.
final class SessionTests: XCTestCase {
    private let root = DispatchQueue(label: "SessionTests.root", attributes: .concurrent)
    private var scope: SessionScope!
    private var client: FakeConnection!
    private var upstream: FakeConnection!
    private var outbound: FakeOutbound!
    private var session: Session!
    /// Set on the session queue by `onClose`.
    private var didClose = false

    private static let hello = Fixtures.tls13ClientHello
    private static let greeting = Data([0x05, 0x01, 0x00])
    private static let methodAccepted = Data([0x05, 0x00])
    private static let socksIPv4Request = Data([0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB])
    private static let connectHead = Data("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".utf8)
    private static let outline = OutlineServerConfig(host: "h", port: 1, password: "p", cipher: .aes256Gcm, prefix: nil)

    /// Upstream connect result, scripted per test.
    private final class FakeOutbound: Outbound {
        let result: Result<FakeConnection, OutboundError>
        private(set) var targets: [DialTarget] = []

        init(_ result: Result<FakeConnection, OutboundError>) { self.result = result }

        func connect(_ target: DialTarget, session: SessionScope,
                     completion: @escaping (Result<any ConnectionProtocol, OutboundError>) -> Void) {
            targets.append(target)
            if case .success(let conn) = result { session.adopt(conn) }
            session.queue.async { completion(self.result.map { $0 }) }
        }
    }

    /// Tests may end with the session still relaying; close it so nothing outlives the test.
    override func tearDown() {
        if let session, let scope {
            scope.queue.sync { session.close("test over") }
        }
        super.tearDown()
    }

    /// Builds and starts a session. `script` is the client's input; more can be pushed later.
    private func start(_ script: [FakeConnection.Event], route: RouteMode = .split, split: SplitMode = .firstByte,
                       outline: OutlineServerConfig? = nil, connect: Result<Void, OutboundError> = .success(()),
                       limits: Session.Limits = Session.Limits(handshakeTimeout: 5, firstByteTimeout: 5)) {
        scope = SessionScope(id: 1, target: root)
        client = FakeConnection(queue: scope.queue, script: script)
        upstream = FakeConnection(queue: scope.queue)
        outbound = FakeOutbound(connect.map { upstream! })
        var profile = SpoofProfile.makeDefault()
        profile.routeMode = route
        profile.splitMode = split
        profile.tlsRecordFragmentation = false
        profile.outlineConfig = outline
        let router = Router { _ in profile }
        let outbound = self.outbound!
        let deps = Session.Dependencies(router: router, limits: limits) { _ in outbound }
        session = Session(scope: scope, client: client, deps: deps)
        didClose = false
        session.onClose = { [unowned self] in didClose = true }
        scope.queue.async { self.session.start() }
    }

    private func waitForClose(timeout: TimeInterval = 2, file: StaticString = #filePath, line: UInt = #line) {
        waitFor({ self.scope.queue.sync { self.didClose } }, timeout: timeout, file: file, line: line)
    }

    /// Lets the session queue drain a few rounds of async callbacks.
    private func settle() {
        for _ in 0..<20 { scope.queue.sync {} }
        usleep(5_000)
        for _ in 0..<20 { scope.queue.sync {} }
    }

    private func phase() -> Session.Phase { scope.queue.sync { session.phase } }

    private func waitFor(_ condition: () -> Bool, timeout: TimeInterval = 2, file: StaticString = #filePath, line: UInt = #line) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline { usleep(2_000) }
        XCTAssertTrue(condition(), "condition not met in \(timeout)s", file: file, line: line)
    }

    // MARK: - SOCKS5 (N6)

    func testSOCKS5PipelinedGreetingRequestAndHelloInOneRead() {
        start([.data(Self.greeting + Self.socksIPv4Request + Self.hello)])
        waitFor { self.upstream.sent.count == 2 }
        XCTAssertEqual(client.sent, [Self.methodAccepted, SOCKS5Parser.reply(0x00)])
        XCTAssertEqual(outbound.targets, [DialTarget(host: "10.0.0.1", port: 443)])
        // firstByte mode: the pipelined hello is still desynced.
        XCTAssertEqual(upstream.sent, [Self.hello.prefix(1), Self.hello.dropFirst()])
        XCTAssertEqual(phase(), .relaying)

        client.push(.eof)
        waitForClose()
        XCTAssertTrue(upstream.cancelled)
    }

    func testSOCKS5ByteByByte() {
        let stream = Self.greeting + Self.socksIPv4Request
        start(stream.map { .data(Data([$0])) })
        waitFor { self.client.sent.count == 2 }
        XCTAssertEqual(client.sent, [Self.methodAccepted, SOCKS5Parser.reply(0x00)])
        XCTAssertEqual(phase(), .readingFirstFlight)
    }

    func testSOCKS5UnsupportedCommandIs0x07() {
        start([.data(Self.greeting + Data([0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80]))])
        waitForClose()
        XCTAssertEqual(client.sent, [Self.methodAccepted, SOCKS5Parser.reply(0x07)])
        XCTAssertEqual(outbound.targets, [])
    }

    func testSOCKS5DialFailureGetsItsReplyCode() {
        start([.data(Self.greeting + Self.socksIPv4Request)], connect: .failure(.dial(.allFailed([.posix(.ECONNREFUSED)]))))
        waitForClose()
        XCTAssertEqual(client.sent, [Self.methodAccepted, SOCKS5Parser.reply(0x05)])
        XCTAssertTrue(client.cancelled)
    }

    // MARK: - CONNECT

    func testConnectDialsBeforeTheReply() {
        start([.data(Self.connectHead)], connect: .failure(.dial(.timeout)))
        waitForClose()
        XCTAssertEqual(client.sent.map { String(decoding: $0, as: UTF8.self).components(separatedBy: "\r\n")[0] },
                       ["HTTP/1.1 504 Gateway Timeout"], "no 200 before a failed dial")
    }

    func testConnectRefusedIs502() {
        start([.data(Self.connectHead)], connect: .failure(.dial(.allFailed([.posix(.ECONNREFUSED)]))))
        waitForClose()
        XCTAssertEqual(client.sent, [HTTPHeadParser.response(502, "Bad Gateway")])
    }

    /// U7: non-TLS first bytes go upstream unchanged.
    func testConnectNonTLSFirstBytesPassThrough() {
        let ssh = Data("SSH-2.0-client\r\n".utf8)
        start([.data(Self.connectHead), .data(ssh)])
        waitFor { self.upstream.sent.count == 1 }
        XCTAssertEqual(client.sent, [HTTPHeadParser.connectEstablished])
        XCTAssertEqual(upstream.sent, [ssh])
        XCTAssertEqual(phase(), .relaying)
    }

    func testConnectHeadAndHelloInOneReadIsDesynced() {
        start([.data(Self.connectHead + Self.hello)])
        waitFor { self.upstream.sent.count == 2 }
        XCTAssertEqual(upstream.sent, [Self.hello.prefix(1), Self.hello.dropFirst()])
    }

    func testModeNoneForwardsPipelinedBytesBeforeRelaying() {
        start([.data(Self.connectHead + Data("early".utf8)), .data(Data("late".utf8))], split: .none)
        waitFor { self.upstream.sent.count == 2 }
        XCTAssertEqual(upstream.sent, [Data("early".utf8), Data("late".utf8)])
    }

    /// N7: a failed segment write closes both sides; nothing is relayed after it.
    func testSegmentWriteErrorClosesWithoutRelaying() {
        start([.data(Self.connectHead)])
        waitFor { self.client.sent.count == 1 }
        upstream.sendError = .posix(.EPIPE)
        client.push(.data(Self.hello))
        waitForClose()
        XCTAssertTrue(client.cancelled)
        XCTAssertTrue(upstream.cancelled)
        XCTAssertEqual(upstream.sent, [])
    }

    // MARK: - Plain HTTP (N9)

    func testPlainHTTPSendsTheRewrittenHeadAndBodyStartTogether() {
        let request = "GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\nBODY"
        start([.data(Data(request.utf8))])
        waitFor { self.upstream.sent.count == 1 }
        XCTAssertEqual(client.sent, [], "the origin's response is the reply")
        XCTAssertEqual(outbound.targets, [DialTarget(host: "example.com", port: 80)])
        XCTAssertEqual(String(decoding: upstream.sent[0], as: UTF8.self),
                       "GET /a HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\nBODY")
    }

    func testGarbageIs400() {
        start([.data(Data("NOT-HTTP\r\n\r\n".utf8))])
        waitForClose()
        XCTAssertEqual(client.sent, [HTTPHeadParser.response(400, "Bad Request")])
        XCTAssertEqual(outbound.targets, [])
    }

    // MARK: - U6: VPN route without a server

    func testVPNWithoutConfigIsRejectedWithoutDialing() {
        for (input, reply) in [(Self.connectHead, HTTPHeadParser.response(502, "Bad Gateway")),
                               (Self.greeting + Self.socksIPv4Request, SOCKS5Parser.reply(0x02))] {
            start([.data(input)], route: .vpn)
            waitForClose()
            XCTAssertEqual(client.sent.last, reply)
            XCTAssertEqual(outbound.targets, [], "no dial attempted")
        }
    }

    func testVPNTunnelRelaysWithoutDesync() {
        start([.data(Self.connectHead + Self.hello)], route: .vpn, outline: Self.outline)
        waitFor { self.upstream.sent.count == 1 }
        XCTAssertEqual(upstream.sent, [Self.hello], "the Shadowsocks stream gets the hello whole")
    }

    // MARK: - N8: handshake deadline

    func testSilentClientIsClosedByTheDeadline() {
        start([], limits: Session.Limits(handshakeTimeout: 0.1, firstByteTimeout: 5))
        waitForClose()
        XCTAssertTrue(client.cancelled)
        XCTAssertEqual(outbound.targets, [])
    }

    func testHalfAHeadIsClosedByTheDeadline() {
        start([.data(Self.connectHead.prefix(10))], limits: Session.Limits(handshakeTimeout: 0.1, firstByteTimeout: 5))
        waitForClose()
        XCTAssertEqual(client.sent, [])
    }

    func testPartialClientHelloIsClosedByTheDeadline() {
        start([.data(Self.connectHead), .data(Self.hello.prefix(20))],
              limits: Session.Limits(handshakeTimeout: 0.2, firstByteTimeout: 5))
        waitForClose()
        XCTAssertTrue(upstream.cancelled)
        XCTAssertEqual(upstream.sent, [], "nothing forwarded from half a ClientHello")
    }

    func testDeadlineDoesNotFireOnceRelaying() {
        start([.data(Self.connectHead), .data(Data("x".utf8))], split: .none,
              limits: Session.Limits(handshakeTimeout: 0.1, firstByteTimeout: 5))
        waitFor { self.upstream.sent.count == 1 }
        usleep(300_000)
        XCTAssertEqual(phase(), .relaying)
        client.push(.eof)
        waitForClose()
    }

    // MARK: - Close

    func testCloseIsIdempotentAndLateCallbacksAreIgnored() {
        start([.data(Self.connectHead)])
        waitFor { self.client.sent.count == 1 }
        scope.queue.sync {
            session.close("test")
            session.close("again")
        }
        waitForClose()
        client.push(.data(Self.hello))
        settle()
        XCTAssertEqual(phase(), .closed)
        XCTAssertEqual(upstream.sent, [])
    }

    func testClientEOFDuringHandshakeCloses() {
        start([.data(Self.greeting.prefix(1)), .eof])
        waitForClose()
        XCTAssertEqual(client.sent, [])
    }
}
