import XCTest
@testable import SpoofyCore

final class ConnectionLogTests: XCTestCase {
    private let queue = DispatchQueue(label: "ConnectionLogTests")
    private var log: ConnectionLog!
    private var nextID: UInt64 = 1

    override func setUp() {
        log = ConnectionLog()
    }

    private func start(_ host: String, port: UInt16 = 443, at seconds: TimeInterval = 1_000,
                       outbound: TraceOutbound = .direct) -> TraceStart {
        defer { nextID += 1 }
        return TraceStart(id: nextID, startedAt: Date(timeIntervalSince1970: seconds),
                          startedAtNanos: DispatchTime.now().uptimeNanoseconds, inbound: .socks5, host: host, port: port,
                          isIPLiteral: ServerConnector.isIPLiteral(host), profileID: UUID(), profileName: "Master",
                          isDefaultProfile: true, outbound: outbound)
    }

    /// A connection that answered `bytesDown` bytes and ended with a server FIN.
    @discardableResult
    private func connection(_ host: String, port: UInt16 = 443, at seconds: TimeInterval = 1_000, address: String = "93.184.216.34",
                            payload: Data = ClientHelloBuilder.make(sni: "example.com"), bytesDown: Int = 10,
                            end: RelayEndEvent = .eof(fromLeft: false)) -> ConnectionTrace {
        let trace = log.begin(start(host, port: port, at: seconds), queue: queue)!
        trace.attemptStarted(address)
        trace.attemptReady(address)
        trace.payloadSent(kind: PayloadSniffer.sniff(client: payload))
        if bytesDown > 0 { trace.relayed(bytesDown, fromLeft: false, prefix: Data(repeating: 0x17, count: min(bytesDown, 16))) }
        trace.relayEnded(end)
        trace.finish(fallback: .clientClosed)
        return trace
    }

    // MARK: - Active

    func testActiveEntriesFollowThePhaseUntilTheEnd() throws {
        let trace = try XCTUnwrap(log.begin(start("example.com"), queue: queue))
        XCTAssertEqual(log.snapshot().active.first?.value.phase, .created)
        trace.attemptStarted("1.2.3.4")
        trace.attemptReady("1.2.3.4")
        XCTAssertEqual(log.snapshot().active.first?.value.phase, .connected)
        XCTAssertEqual(log.snapshot().active.first?.value.host, "example.com")
        trace.finish(fallback: .clientClosed)
        XCTAssertTrue(log.snapshot().active.isEmpty)
        XCTAssertEqual(log.snapshot().hosts["example.com"]?.connectionCount, 1)
    }

    // MARK: - Hosts

    func testHostRecordAggregatesItsConnections() throws {
        connection("example.com", port: 443, at: 1_000, address: "1.1.1.1", bytesDown: 10)
        connection("example.com", port: 5222, at: 1_010, address: "1.1.1.1", bytesDown: 20)
        connection("example.com", at: 1_020, address: "2.2.2.2", bytesDown: 0, end: .readError(fromLeft: false, .posix(.ECONNRESET)))
        let record = try XCTUnwrap(log.snapshot().hosts["example.com"])
        XCTAssertEqual(record.connectionCount, 3)
        XCTAssertEqual(record.ports, [443, 5222])
        XCTAssertEqual(record.ips, ["1.1.1.1", "2.2.2.2"])
        XCTAssertEqual(record.bytesDown, 30)
        XCTAssertEqual(record.firstSeen, Date(timeIntervalSince1970: 1_000))
        XCTAssertEqual(record.lastSeen.timeIntervalSince1970, 1_020, accuracy: 1)
        XCTAssertEqual(record.recent.elements.map(\.outcome.kind), [.ok, .ok, .helloReset(early: false)],
                       "classified once, on completion")
    }

    func testIPsAreCappedAndSNIsKeptOnlyForIPTargets() throws {
        for i in 1...6 { connection("example.com", address: "10.0.0.\(i)") }
        XCTAssertEqual(log.snapshot().hosts["example.com"]?.ips.count, ConnectionLog.ipsPerHost)
        XCTAssertEqual(log.snapshot().hosts["example.com"]?.snis, [])

        connection("1.2.3.4", address: "1.2.3.4", payload: ClientHelloBuilder.make(sni: "Blocked.example"))
        connection("1.2.3.4", address: "1.2.3.4", payload: ClientHelloBuilder.make(sni: "other.example"))
        XCTAssertEqual(log.snapshot().hosts["1.2.3.4"]?.snis, ["blocked.example", "other.example"])
    }

    func testRecentKeepsTheNewestEight() throws {
        for i in 0..<10 { connection("example.com", at: 1_000 + Double(i), bytesDown: i + 1) }
        let recent = try XCTUnwrap(log.snapshot().hosts["example.com"]).recent.elements
        XCTAssertEqual(recent.count, ConnectionLog.recentPerHost)
        XCTAssertEqual(recent.map(\.summary.bytesDown), Array(3...10))
    }

    func testTheLeastRecentlySeenHostIsEvicted() {
        for i in 0..<ConnectionLog.hostCap { connection("h\(i).example", at: 10_000 + Double(i)) }
        connection("h0.example", at: 20_000)  // seen again: now the newest
        connection("new.example", at: 30_000)
        let hosts = log.snapshot().hosts
        XCTAssertEqual(hosts.count, ConnectionLog.hostCap)
        XCTAssertNotNil(hosts["h0.example"])
        XCTAssertNil(hosts["h1.example"], "the stalest goes")
        XCTAssertNotNil(hosts["new.example"])
    }

    func testRecentGlobalIsARing() {
        for i in 0..<(ConnectionLog.recentGlobalCap + 5) { connection("h\(i % 7).example", at: 1_000 + Double(i)) }
        let global = log.snapshot().recentGlobal.elements
        XCTAssertEqual(global.count, ConnectionLog.recentGlobalCap)
        XCTAssertEqual(global.last?.host, "h\((ConnectionLog.recentGlobalCap + 4) % 7).example")
        XCTAssertEqual(global.last?.outcome.kind, .ok)
        XCTAssertEqual(global.last?.profileName, "Master")
    }

    // MARK: - Refusals

    func testRefusalsAreGroupedByCause() throws {
        let at = Date(timeIntervalSince1970: 1_000)
        for i in 0..<7 {
            let target = DialTarget(host: "10.0.0.\(i % 6)", port: 80)
            log.refused(RefusalRecord(at: at.addingTimeInterval(Double(i)), inbound: .socks4,
                                      reason: .handshake(.socks4(target: target)), target: target))
        }
        log.refused(RefusalRecord(at: at, inbound: .socks5, reason: .handshake(.socks5Command(3)), target: nil))
        log.refused(RefusalRecord(at: at, inbound: nil, reason: .overCapacity, target: nil))
        log.refused(RefusalRecord(at: at, inbound: .http, reason: .routeRejected(profileName: "VPN"), target: nil))
        log.refused(RefusalRecord(at: at, inbound: .http, reason: .routeRejected(profileName: "Other"), target: nil))

        let refusals = log.snapshot().refusals
        XCTAssertEqual(refusals.count, 5)
        let socks4 = try XCTUnwrap(refusals[.socks4])
        XCTAssertEqual(socks4.count, 7)
        XCTAssertEqual(socks4.lastInbound, .socks4)
        XCTAssertEqual(socks4.targets.map(\.host), ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.0"],
                       "the last five distinct, newest last")
        XCTAssertEqual(socks4.lastSeen, at.addingTimeInterval(6))
        XCTAssertEqual(refusals[.socks5Command(3)]?.count, 1)
        XCTAssertEqual(refusals[.routeRejected(profileName: "VPN")]?.count, 1)
    }

    func testRefusalGroupsAreCapped() {
        for i in 0..<(ConnectionLog.refusalGroupCap + 1) {
            log.refused(RefusalRecord(at: Date(timeIntervalSince1970: Double(i)), inbound: .socks5,
                                      reason: .handshake(.socks5AddressType(UInt8(i))), target: nil))
        }
        let refusals = log.snapshot().refusals
        XCTAssertEqual(refusals.count, ConnectionLog.refusalGroupCap)
        XCTAssertNil(refusals[.socks5AddressType(0)])
    }

    func testRefusalsNeverTouchHosts() {
        log.refused(RefusalRecord(at: Date(), inbound: .http, reason: .routeRejected(profileName: "VPN"),
                                  target: DialTarget(host: "example.com", port: 443)))
        XCTAssertTrue(log.snapshot().hosts.isEmpty)
        XCTAssertEqual(log.snapshot().recentGlobal.count, 0)
    }

    // MARK: - Clear

    func testClearKeepsLiveSessions() throws {
        connection("old.example")
        log.refused(RefusalRecord(at: Date(), inbound: nil, reason: .overCapacity, target: nil))
        let live = try XCTUnwrap(log.begin(start("live.example"), queue: queue))
        log.clear()
        let snapshot = log.snapshot()
        XCTAssertTrue(snapshot.hosts.isEmpty)
        XCTAssertTrue(snapshot.refusals.isEmpty)
        XCTAssertEqual(snapshot.recentGlobal.count, 0)
        XCTAssertEqual(snapshot.active.count, 1)
        live.finish(fallback: .clientClosed)
        XCTAssertNotNil(log.snapshot().hosts["live.example"], "lands as a host when it ends")
    }

    func testRing() {
        var ring = Ring<Int>(capacity: 3)
        XCTAssertEqual(ring.elements, [])
        for i in 1...5 { ring.append(i) }
        XCTAssertEqual(ring.elements, [3, 4, 5])
        XCTAssertEqual(ring.count, 3)
    }
}
