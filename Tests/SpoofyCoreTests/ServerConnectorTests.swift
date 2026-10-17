import Network
import XCTest
@testable import SpoofyCore

/// Plan §6.2. Dials stay on loopback: live origins, and ports nothing listens on.
final class ServerConnectorTests: XCTestCase {
    private let root = DispatchQueue(label: "ServerConnectorTests", attributes: .concurrent)
    private var origins: [LoopbackOrigin] = []

    override func tearDown() {
        origins.forEach { $0.stop() }
        super.tearDown()
    }

    private func deadPort() throws -> UInt16 {
        let probe = try LoopbackOrigin(.recordAll)
        defer { probe.stop() }
        return probe.port
    }

    private func dial(_ host: String, _ port: UInt16, resolver: Resolver? = nil,
                      connector: ServerConnector = ServerConnector(),
                      session: SessionScope? = nil,
                      beforeDial: ((SessionScope) -> Void)? = nil) -> (Result<NWConnection, DialError>, calls: Int) {
        let session = session ?? SessionScope(id: 1, target: root)
        let done = expectation(description: "dial completes")
        let results = LockedBox<[Result<NWConnection, DialError>]>([])
        session.queue.async {
            beforeDial?(session)
            connector.dial(DialTarget(host: host, port: port), resolver: resolver, session: session) { result in
                dispatchPrecondition(condition: .onQueue(session.queue))
                results.value.append(result)
                done.fulfill()
            }
        }
        wait(for: [done], timeout: 5)
        // Give a duplicate completion a chance to show up.
        usleep(300_000)
        session.queue.sync { session.close() }
        return (results.value[0], results.value.count)
    }

    func testInterleaveAlternatesFamiliesStartingWithIPv4() {
        XCTAssertEqual(ServerConnector.interleave(["::1", "::2", "1.1.1.1", "2.2.2.2", "3.3.3.3"]),
                       ["1.1.1.1", "::1", "2.2.2.2", "::2", "3.3.3.3"])
        XCTAssertEqual(ServerConnector.interleave(["::1"]), ["::1"])
        XCTAssertEqual(ServerConnector.interleave([]), [])
    }

    func testIPLiteralDetection() {
        XCTAssertTrue(ServerConnector.isIPLiteral("127.0.0.1"))
        XCTAssertTrue(ServerConnector.isIPLiteral("::1"))
        XCTAssertTrue(ServerConnector.isIPLiteral("2001:db8::1"))
        XCTAssertFalse(ServerConnector.isIPLiteral("example.com"))
        XCTAssertFalse(ServerConnector.isIPLiteral("[::1]"))
    }

    func testParametersAlwaysDisableNagle() throws {
        let tcp = try XCTUnwrap(ServerConnector.makeParameters().defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options)
        XCTAssertTrue(tcp.noDelay)
    }

    func testDialsLiveOriginOnce() throws {
        let origin = try LoopbackOrigin(.echo)
        origins.append(origin)
        let (result, calls) = dial("127.0.0.1", origin.port)
        XCTAssertNoThrow(try result.get())
        XCTAssertEqual(calls, 1)
    }

    func testRefusedPortFailsFastWithAllFailed() throws {
        let port = try deadPort()
        let started = Date()
        let (result, calls) = dial("127.0.0.1", port)
        XCTAssertLessThan(Date().timeIntervalSince(started), 2)
        XCTAssertEqual(calls, 1)
        guard case .failure(.allFailed(let errors)) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(errors.count, 1)
    }

    func testEveryAddressIsTriedBeforeGivingUp() throws {
        let port = try deadPort()
        let resolver = FakeResolver(["dead.test": ["127.0.0.1", "::1"]])
        let (result, _) = dial("dead.test", port, resolver: resolver)
        guard case .failure(.allFailed(let errors)) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(errors.count, 2)
    }

    func testFallsBackPastARefusedAddress() throws {
        let origin = try LoopbackOrigin(.echo, host: "::1")
        origins.append(origin)
        let resolver = FakeResolver(["both.test": ["127.0.0.1", "::1"]])
        let (result, calls) = dial("both.test", origin.port, resolver: resolver)
        let conn = try result.get()
        XCTAssertEqual(calls, 1)
        guard case .hostPort(let host, _) = conn.endpoint else { return XCTFail("\(conn.endpoint)") }
        XCTAssertEqual("\(host)", "::1")
    }

    func testIPLiteralIsNotSentToTheResolver() throws {
        let origin = try LoopbackOrigin(.echo)
        origins.append(origin)
        let resolver = FakeResolver([:])
        XCTAssertNoThrow(try dial("::1", origin.port, resolver: resolver).0.get())
        XCTAssertEqual(resolver.queries, [])
    }

    func testClosedSessionCompletesWithCancelled() throws {
        let origin = try LoopbackOrigin(.echo)
        origins.append(origin)
        // The resolver answers after the session has closed (e.g. ProxyServer.stop() during a lookup).
        let resolver = FakeResolver(["slow.test": ["127.0.0.1"]], delay: 0.2)
        let session = SessionScope(id: 2, target: root)
        session.queue.asyncAfter(deadline: .now() + 0.05) { session.close() }
        let (result, calls) = dial("slow.test", origin.port, resolver: resolver, session: session)
        XCTAssertEqual(calls, 1)
        guard case .failure(.cancelled) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(origin.acceptCount, 0)
    }

    func testSessionClosedMidDialCompletesWithCancelled() throws {
        // A listener that never accepts would need a non-loopback blackhole; instead close
        // the session right after the attempt starts, before .ready can arrive.
        let origin = try LoopbackOrigin(.echo)
        origins.append(origin)
        let session = SessionScope(id: 3, target: root)
        let (result, calls) = dial("127.0.0.1", origin.port, session: session) { session in
            session.queue.async { session.close() }
        }
        XCTAssertEqual(calls, 1)
        guard case .failure(.cancelled) = result else { return XCTFail("\(result)") }
    }
}
