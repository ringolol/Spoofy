import XCTest
@testable import SpoofyCore

final class ScannerSnapshotTests: XCTestCase {
    private typealias F = VerdictFixture

    private func log(_ traces: [ClassifiedTrace]) -> LogSnapshot {
        var snapshot = LogSnapshot()
        for trace in traces {
            snapshot.hosts[trace.summary.start.host, default: HostRecord(host: trace.summary.start.host,
                                                                          firstSeen: trace.summary.start.startedAt)].add(trace)
            snapshot.recentGlobal.append(F.global(trace))
        }
        return snapshot
    }

    private func config(_ custom: [SpoofProfile] = []) -> ProxyConfig {
        ProxyConfig(profiles: custom + [.makeDefault()], port: 8090, allowLANAccess: false)
    }

    func testRowsAreSortedByVerdictThenRecency() {
        let snapshot = ScannerSnapshot.build(log: log([
            F.trace("old-ok.com", .ok, ago: 50), F.trace("new-ok.com", .ok, ago: 5),
            F.trace("odd.com", .helloSilentClose(early: false), .low, ago: 40),
            F.trace("blocked.com", .helloReset(early: true), ago: 30),
            F.trace("moved.com", .helloReset(early: true), ago: 20, fingerprint: "old"),
        ]), config: config(), now: F.now)
        XCTAssertEqual(snapshot.rows.map(\.host), ["blocked.com", "odd.com", "moved.com", "new-ok.com", "old-ok.com"])
        XCTAssertEqual(snapshot.summary, LogSummary(hostCount: 5, blockedCount: 1, network: .normal))
    }

    func testTheVerdictUsesTheCurrentRule() {
        var youtube = SpoofProfile.makeCustom(name: "YouTube", domainPatterns: ["*.youtube.com"], splitMode: .sni)
        youtube.dohEnabled = false
        let master = SpoofProfile.makeDefault()
        let resolved = ProxyConfig.resolve(youtube, master: master)
        let traces = [F.trace("www.youtube.com", .helloReset(early: true), ago: 30, fingerprint: master.routingFingerprint),
                      F.trace("ok.com", .ok, ago: 30)]

        let before = ScannerSnapshot.build(log: log(traces), config: config(), now: F.now)
        let row = try! XCTUnwrap(before.rows.first { $0.host == "www.youtube.com" })
        XCTAssertEqual(row.verdict.status, .blocked(.sni))
        XCTAssertTrue(row.isDefaultProfile)

        let after = ScannerSnapshot.build(log: log(traces), config: config([youtube]), now: F.now)
        let moved = try! XCTUnwrap(after.rows.first { $0.host == "www.youtube.com" })
        XCTAssertEqual(moved.profileName, "YouTube")
        XCTAssertEqual(moved.profileID, youtube.id)
        XCTAssertFalse(moved.isDefaultProfile)
        XCTAssertEqual(moved.verdict.status, .ruleChanged)

        let retested = ScannerSnapshot.build(log: log(traces + [F.trace("www.youtube.com", .ok, ago: 5, fingerprint: resolved.routingFingerprint)]),
                                             config: config([youtube]), now: F.now)
        XCTAssertEqual(retested.rows.first { $0.host == "www.youtube.com" }?.verdict.status, .working)
    }

    /// A browser keeps its connection open for minutes; the host shows before the first one closes.
    func testHostsWithOnlyOpenConnectionsAreListed() {
        var snapshot = log([F.trace("done.com", .ok, ago: 30)])
        snapshot.active[1] = ActiveEntry(id: 1, host: "open.com", port: 443, phase: .responding, startedAt: F.now.addingTimeInterval(-5))
        snapshot.active[2] = ActiveEntry(id: 2, host: "open.com", port: 443, phase: .responding, startedAt: F.now.addingTimeInterval(-2))
        snapshot.active[3] = ActiveEntry(id: 3, host: "done.com", port: 443, phase: .responding, startedAt: F.now.addingTimeInterval(-1))
        snapshot.active[4] = ActiveEntry(id: 4, host: "hidden.com", port: 443, phase: .responding, startedAt: F.now)

        let built = ScannerSnapshot.build(log: snapshot, config: config(), hiddenHosts: ["hidden.com"], now: F.now)
        XCTAssertEqual(Set(built.rows.map(\.host)), ["done.com", "open.com"])
        XCTAssertEqual(built.hiddenCount, 1)

        let open = built.rows.first { $0.host == "open.com" }!
        XCTAssertEqual(open.openCount, 2)
        XCTAssertEqual(open.connectionCount, 0)
        XCTAssertEqual(open.ports, [443])
        XCTAssertEqual(open.lastSeen, F.now.addingTimeInterval(-2))
        XCTAssertEqual(open.verdict.status, .unknown)
        XCTAssertTrue(open.isDefaultProfile)
        XCTAssertEqual(built.rows.first { $0.host == "done.com" }?.openCount, 1)
        XCTAssertEqual(built.summary.hostCount, 2)
    }

    func testRowFields() throws {
        let hello = PayloadKind.tls(ClientHelloInfo.parse(record: ClientHelloBuilder.make(sni: "blocked.example"))!)
        var start = log([F.trace("1.2.3.4", .ok, payload: hello), F.trace("1.2.3.4", .ok, payload: .ssh),
                         F.trace("1.2.3.4", .clientAborted, .low, payload: PayloadKind.none)])
        start.active[7] = ActiveEntry(id: 7, host: "x.com", port: 443, phase: .connected, startedAt: F.now)
        let snapshot = ScannerSnapshot.build(log: start, config: config(), now: F.now)
        let row = try XCTUnwrap(snapshot.rows.first { $0.id == "1.2.3.4" })
        XCTAssertEqual(row.ports, [443])
        XCTAssertEqual(row.kinds, [.tls, .ssh])
        XCTAssertEqual(row.connectionCount, 3)
        XCTAssertEqual(row.sni, "blocked.example")
        XCTAssertEqual(row.snis, ["blocked.example"])
        XCTAssertEqual(row.recent.count, 3)
        XCTAssertEqual(snapshot.activeCount, 1)
    }

    func testHiddenHostsAreLeftOut() {
        let snapshot = ScannerSnapshot.build(log: log([F.trace("a.apple.com", .ok), F.trace("apple.com", .ok),
                                                       F.trace("telemetry.b.com", .ok), F.trace("b.com", .ok)]),
                                             config: config(), hiddenHosts: ["*.apple.com", "telemetry.b.com"], now: F.now)
        XCTAssertEqual(snapshot.rows.map(\.host), ["b.com"])
        XCTAssertEqual(snapshot.hiddenCount, 3)
        XCTAssertEqual(snapshot.summary.hostCount, 1)
    }

    func testRefusalsNewestFirstAndNetworkState() {
        var snapshot = log((1...3).map { F.trace("h\($0).com", .connectTimeout) })
        snapshot.refusals[.socks4] = RefusalGroup(key: .socks4, firstSeen: F.now.addingTimeInterval(-50))
        snapshot.refusals[.overCapacity] = RefusalGroup(key: .overCapacity, firstSeen: F.now.addingTimeInterval(-5))
        let built = ScannerSnapshot.build(log: snapshot, config: config(), now: F.now)
        XCTAssertEqual(built.refusals.map(\.key), [.overCapacity, .socks4])
        XCTAssertEqual(built.network, .offline)
        XCTAssertEqual(built.summary.network, .offline)
    }
}
