import XCTest
@testable import SpoofyCore

/// Builds classified traces with a chosen outcome, so the verdict rules can be tested apart from
/// the classifier.
enum VerdictFixture {
    static let now = Date(timeIntervalSince1970: 100_000)
    static let fingerprint = SpoofProfile.makeDefault().routingFingerprint

    static func trace(_ kind: TraceOutcome.Kind, _ confidence: TraceOutcome.Confidence = .high, ago: TimeInterval = 10,
                      fingerprint: String = fingerprint, payload: PayloadKind? = nil, ech: Bool = false) -> ClassifiedTrace {
        trace("example.com", kind, confidence, ago: ago, fingerprint: fingerprint, payload: payload, ech: ech)
    }

    static func trace(_ host: String, _ kind: TraceOutcome.Kind, _ confidence: TraceOutcome.Confidence = .high,
                      ago: TimeInterval = 10, fingerprint: String = fingerprint, payload: PayloadKind? = nil,
                      ech: Bool = false, outbound: TraceOutbound = .direct, profileName: String = "Master",
                      profileID: UUID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!) -> ClassifiedTrace {
        let start = TraceStart(id: 1, startedAt: now.addingTimeInterval(-ago), startedAtNanos: 0, inbound: .socks5,
                               host: host, port: 443, isIPLiteral: ServerConnector.isIPLiteral(host), profileID: profileID,
                               profileName: profileName, isDefaultProfile: true, outbound: outbound, fingerprint: fingerprint)
        var fields = TraceFields()
        fields.payloadKind = payload ?? .tls(ClientHelloInfo.parse(record: ClientHelloBuilder.make(sni: host))!)
        return ClassifiedTrace(summary: TraceSummary(start: start, reached: .payloadSent, endReason: .clientClosed, fields: fields),
                               outcome: TraceOutcome(kind: kind, confidence: confidence, echPresent: ech))
    }

    static func record(_ traces: [ClassifiedTrace]) -> HostRecord {
        var record = HostRecord(host: traces.first?.summary.start.host ?? "example.com",
                                firstSeen: traces.first?.summary.start.startedAt ?? now)
        traces.forEach { record.add($0) }
        return record
    }

    static func global(_ trace: ClassifiedTrace) -> GlobalOutcome {
        let start = trace.summary.start
        return GlobalOutcome(host: start.host, outcome: trace.outcome, endedAt: trace.summary.endedDate,
                             outbound: start.outbound, profileID: start.profileID, profileName: start.profileName)
    }

    /// Another host that worked at the same moments, so the network counts as healthy.
    static func healthy(at agos: [TimeInterval] = [10, 20, 30, 40, 50]) -> [GlobalOutcome] {
        agos.map { global(trace("ok.example", .ok, ago: $0)) }
    }
}

final class HostVerdictTests: XCTestCase {
    private typealias F = VerdictFixture

    private func verdict(_ traces: [ClassifiedTrace], network: NetworkState = .normal,
                         global: [GlobalOutcome] = F.healthy(), fingerprint: String = F.fingerprint) -> HostVerdict {
        HostVerdict.verdict(for: F.record(traces), currentFingerprint: fingerprint, network: network,
                            recentGlobal: global, now: F.now)
    }

    func testOutcomeKindsMapToBlockKinds() {
        XCTAssertEqual(BlockKind(.helloReset(early: true)), .sni)
        XCTAssertEqual(BlockKind(.helloBlackhole(retransmits: false)), .sni)
        XCTAssertEqual(BlockKind(.connectTimeout), .ip)
        XCTAssertEqual(BlockKind(.dnsBogus(ip: "10.0.0.1")), .dns)
        XCTAssertEqual(BlockKind(.httpBlockPage(status: 302, location: nil)), .httpBlockPage)
        XCTAssertEqual(BlockKind(.injectedResponse(.earlyAlert)), .injected)
        XCTAssertEqual(BlockKind(.freeze(bytesDown: 16_000)), .freeze)
        XCTAssertEqual(BlockKind(.outlineFailed), .outline)
        XCTAssertNil(BlockKind(.midStreamReset(bytesDown: 10)))
        XCTAssertNil(BlockKind(.ok))
    }

    func testNoEvidenceIsUnknown() {
        XCTAssertEqual(verdict([]).status, .unknown)
        XCTAssertEqual(verdict([F.trace(.clientAborted, .low), F.trace(.inconclusive, .low), F.trace(.interrupted, .low)]).status, .unknown)
        XCTAssertEqual(verdict([F.trace(.helloReset(early: true), ago: 16 * 60)]).status, .unknown, "older than 15 min")
    }

    func testEvidenceUnderAnotherFingerprintIsRuleChanged() {
        let v = verdict([F.trace(.helloReset(early: true), fingerprint: "split|none|5|-|-")], fingerprint: "split|sni|5|-|-")
        XCTAssertEqual(v.status, .ruleChanged)
        XCTAssertNil(v.confidence)
        let fresh = verdict([F.trace(.helloReset(early: true), ago: 30, fingerprint: "old"), F.trace(.ok, ago: 5), F.trace(.ok, ago: 1)])
        XCTAssertEqual(fresh.status, .working, "only the current rule's evidence counts")
    }

    func testTwoRecentOKsAreWorking() {
        let v = verdict([F.trace(.helloReset(early: true), ago: 30), F.trace(.ok, ago: 20), F.trace(.ok, ago: 10)])
        XCTAssertEqual(v.status, .working)
        XCTAssertEqual(verdict([F.trace(.ok)]).status, .working, "one ok and nothing against it")
    }

    func testScoreDecidesBlockedOrSuspicious() {
        XCTAssertEqual(verdict([F.trace(.helloReset(early: true), .high)]).status, .blocked(.sni))
        XCTAssertEqual(verdict([F.trace(.helloReset(early: true), .high)]).confidence, .high)
        let medium = verdict([F.trace(.helloReset(early: false), .medium, ago: 20), F.trace(.helloReset(early: false), .medium)])
        XCTAssertEqual(medium.status, .blocked(.sni))
        XCTAssertEqual(medium.confidence, .medium)
        let low = verdict([F.trace(.helloSilentClose(early: false), .low)])
        XCTAssertEqual(low.status, .suspicious(.sni))
        XCTAssertEqual(low.confidence, .low)
        XCTAssertEqual(verdict([F.trace(.ok, ago: 20), F.trace(.helloReset(early: true))]).status, .blocked(.sni),
                       "the latest failure beats an older success")
    }

    func testBlockedNeedsAHealthyNetwork() {
        XCTAssertEqual(verdict([F.trace(.helloReset(early: true))], global: []).status, .suspicious(.sni))
        let far = F.healthy(at: [200])
        XCTAssertEqual(verdict([F.trace(.helloReset(early: true), ago: 10)], global: far).status, .suspicious(.sni),
                       "an ok more than 60 s away doesn't count")
        let selfOnly = [F.global(F.trace("example.com", .ok, ago: 10))]
        XCTAssertEqual(verdict([F.trace(.helloReset(early: true))], global: selfOnly).status, .suspicious(.sni),
                       "the host's own success doesn't make the network healthy")
    }

    func testFreezeWinsOverSuccesses() {
        let v = verdict([F.trace(.freeze(bytesDown: 16_000), .medium, ago: 40), F.trace(.freeze(bytesDown: 16_000), .medium, ago: 30),
                         F.trace(.ok, ago: 20), F.trace(.ok, ago: 10)])
        XCTAssertEqual(v.status, .blocked(.freeze))
        XCTAssertEqual(v.evidence.count, 2)
    }

    func testTopKindWins() {
        let v = verdict([F.trace(.connectTimeout, .medium, ago: 30),
                         F.trace(.helloReset(early: true), .high, ago: 20), F.trace(.helloBlackhole(retransmits: true), .high)])
        XCTAssertEqual(v.status, .blocked(.sni))
        XCTAssertEqual(v.evidence.count, 2)
    }

    func testWhitelistModeRelabelsSNIAndIP() {
        XCTAssertEqual(verdict([F.trace(.helloBlackhole(retransmits: false), .medium)], network: .whitelistMode).status, .blocked(.whitelist))
        XCTAssertEqual(verdict([F.trace(.dnsBogus(ip: "10.1.1.1"))], network: .whitelistMode).status, .blocked(.dns))
    }

    func testOfflineIgnoresTheLastNinetySeconds() {
        let v = verdict([F.trace(.ok, ago: 300), F.trace(.connectTimeout, .medium, ago: 30), F.trace(.connectTimeout, .medium, ago: 10)],
                        network: .offline)
        XCTAssertEqual(v.status, .working)
    }

    func testOtherProtocolsDontDiluteTLS() {
        let ssh = PayloadKind.ssh
        let v = verdict([F.trace(.helloReset(early: true), ago: 30),
                         F.trace(.ok, ago: 20, payload: ssh), F.trace(.ok, ago: 10, payload: ssh)])
        XCTAssertEqual(v.status, .blocked(.sni))
        XCTAssertEqual(verdict([F.trace(.ok, ago: 20, payload: ssh), F.trace(.ok, ago: 10, payload: ssh)]).status, .working)
    }

    func testOutlineFailuresDontJudgeTheHost() {
        let v = verdict([F.trace(.outlineFailed, .high, ago: 20), F.trace(.outlineFailed, .high)])
        XCTAssertEqual(v.status, .unknown)
    }

    func testECHIsReported() {
        XCTAssertTrue(verdict([F.trace(.helloReset(early: true), ech: true)]).echSeen)
        XCTAssertFalse(verdict([F.trace(.helloReset(early: true))]).echSeen)
    }
}
