import XCTest
@testable import SpoofyCore

final class NetworkStateTests: XCTestCase {
    private typealias F = VerdictFixture

    private func state(_ traces: [ClassifiedTrace]) -> NetworkState {
        NetworkState.evaluate(traces.map(F.global), now: F.now)
    }

    func testNormalByDefault() {
        XCTAssertEqual(state([]), .normal)
        XCTAssertEqual(state([F.trace("a.com", .ok), F.trace("b.com", .helloReset(early: true))]), .normal)
    }

    func testOfflineNeedsThreeHostsAllFailingToConnect() {
        let failing = [F.trace("a.com", .connectTimeout), F.trace("b.com", .dnsFailed), F.trace("c.com", .connectUnreachable)]
        XCTAssertEqual(state(failing), .offline)
        XCTAssertEqual(state(Array(failing.prefix(2))), .normal)
        XCTAssertEqual(state(failing + [F.trace("d.com", .ok)]), .normal)
        XCTAssertEqual(state(failing + [F.trace("d.com", .helloReset(early: true))]), .normal)
        XCTAssertEqual(state(failing.map { F.trace($0.summary.start.host, .connectTimeout, ago: 200) }), .normal, "outside 90 s")
    }

    func testEachHostCountsByItsLatestOutcome() {
        let traces = [F.trace("a.com", .connectTimeout, ago: 30), F.trace("b.com", .connectTimeout, ago: 30),
                      F.trace("c.com", .connectTimeout, ago: 30), F.trace("a.com", .ok, ago: 5)]
        XCTAssertEqual(state(traces), .normal)
        let aborted = [F.trace("a.com", .connectTimeout, ago: 30), F.trace("b.com", .connectTimeout), F.trace("c.com", .connectTimeout),
                       F.trace("a.com", .clientAborted, .low, ago: 5)]
        XCTAssertEqual(state(aborted), .offline, "an abort says nothing")
    }

    func testWhitelistMode() {
        var traces = (1...6).map { F.trace("h\($0).com", $0.isMultiple(of: 2) ? .connectTimeout : .helloBlackhole(retransmits: true)) }
        traces.append(F.trace("allowed.ru", .ok))
        XCTAssertEqual(state(traces), .whitelistMode)
        XCTAssertEqual(state(Array(traces.suffix(6))), .normal, "five failing")
        XCTAssertEqual(state(traces + (1...3).map { F.trace("ok\($0).ru", .ok) }), .normal, "fail ratio 0.6")
    }

    func testShadowsocksDoesntCountForOfflineOrWhitelist() {
        let ss = TraceOutbound.shadowsocks(host: "1.2.3.4", port: 8388)
        let traces = [F.trace("a.com", .connectTimeout), F.trace("b.com", .connectTimeout), F.trace("c.com", .connectTimeout),
                      F.trace("d.com", .ok, outbound: ss)]
        XCTAssertEqual(state(traces), .offline)
    }

    func testOutlineDown() {
        let ss = TraceOutbound.shadowsocks(host: "1.2.3.4", port: 8388)
        let vpn = UUID()
        let failed = (1...3).map { F.trace("h\($0).com", .outlineFailed, outbound: ss, profileName: "VPN", profileID: vpn) }
        XCTAssertEqual(state(failed), .outlineDown(profileName: "VPN"))
        XCTAssertEqual(state(Array(failed.prefix(2))), .normal)
        XCTAssertEqual(state(failed + [F.trace("x.com", .ok, outbound: ss, profileName: "VPN", profileID: vpn)]), .normal)
        let other = F.trace("x.com", .ok, outbound: ss, profileName: "Other", profileID: UUID())
        XCTAssertEqual(state(failed + [other]), .outlineDown(profileName: "VPN"), "another profile's server is fine")
    }
}
