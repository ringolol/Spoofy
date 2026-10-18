import Network
import XCTest
@testable import SpoofyCore

/// Network-scanner plan §2.1: the trace's lifecycle and the end-reason mapping.
final class ConnectionTraceTests: XCTestCase {
    private var summaries: [TraceSummary] = []
    private let queue = DispatchQueue(label: "ConnectionTraceTests")
    /// The trace's clock, in nanoseconds; tests move it by hand.
    private var clock: UInt64 = 1_000_000_000

    private static let start = TraceStart(
        id: 7, startedAt: Date(), startedAtNanos: DispatchTime.now().uptimeNanoseconds, inbound: .http,
        host: "example.com", port: 443, isIPLiteral: false, profileID: UUID(), profileName: "Master",
        isDefaultProfile: true, outbound: .direct)

    private func makeTrace() -> ConnectionTrace {
        ConnectionTrace(Self.start, queue: queue, clock: { [unowned self] in clock }, reportWait: 0.1) { [unowned self] in
            summaries.append($0)
        }
    }

    // MARK: - Lifecycle

    func testPhasesOnlyMoveForward() {
        let trace = makeTrace()
        XCTAssertEqual(trace.phase, .created)
        trace.dnsStarted()
        XCTAssertEqual(trace.phase, .resolving)
        trace.dnsFinished(ips: ["10.0.0.1", "10.0.0.2"])
        trace.attemptStarted("10.0.0.1")
        XCTAssertEqual(trace.phase, .connecting)
        trace.attemptFailed("10.0.0.1", .posix(.ECONNREFUSED))
        trace.attemptStarted("10.0.0.2")
        trace.attemptReady("10.0.0.2")
        XCTAssertEqual(trace.phase, .connected)
        trace.attemptStarted("10.0.0.3")
        trace.dnsStarted()
        XCTAssertEqual(trace.phase, .connected, "a late event is recorded but doesn't move the phase back")
    }

    func testFinishRecordsTheDialAndDeliversOnce() throws {
        let trace = makeTrace()
        trace.dnsStarted()
        trace.dnsFinished(ips: ["10.0.0.1", "::1"])
        trace.attemptStarted("10.0.0.1")
        trace.attemptFailed("10.0.0.1", .posix(.ECONNREFUSED))
        trace.attemptStarted("::1")
        trace.attemptReady("::1")
        trace.finish(fallback: .clientClosed)
        trace.finish(fallback: .proxyStopped)
        trace.attemptStarted("10.0.0.9")

        XCTAssertEqual(summaries.count, 1)
        let summary = try XCTUnwrap(summaries.first)
        XCTAssertEqual(summary.start.host, "example.com")
        XCTAssertEqual(summary.reached, .connected)
        XCTAssertEqual(summary.endReason, .clientClosed)
        XCTAssertEqual(summary.dohIPs, ["10.0.0.1", "::1"])
        XCTAssertEqual(summary.connectedAddress, "::1")
        XCTAssertEqual(summary.attempts.map(\.address), ["10.0.0.1", "::1"])
        XCTAssertEqual(summary.attempts.map(\.outcome), [.failed(.posix(.ECONNREFUSED)), .ready])
        let dnsStart = try XCTUnwrap(summary.dnsStart), dnsEnd = try XCTUnwrap(summary.dnsEnd)
        let connectStart = try XCTUnwrap(summary.connectStart), connectEnd = try XCTUnwrap(summary.connectEnd)
        XCTAssertLessThanOrEqual(dnsStart, dnsEnd)
        XCTAssertLessThanOrEqual(dnsEnd, connectStart)
        XCTAssertLessThanOrEqual(connectStart, connectEnd)
        XCTAssertLessThanOrEqual(connectEnd, summary.endedAt)
        XCTAssertEqual(trace.phase, .ended)
    }

    func testAttemptsAreCappedAtFour() {
        let trace = makeTrace()
        for i in 1...6 {
            trace.attemptStarted("10.0.0.\(i)")
            trace.attemptFailed("10.0.0.\(i)", .posix(.ETIMEDOUT))
        }
        trace.finish(fallback: .clientClosed)
        XCTAssertEqual(summaries.first?.attempts.map(\.address), ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
    }

    func testAttemptsStillOpenAtFinishAreCancelled() {
        let trace = makeTrace()
        trace.attemptStarted("10.0.0.1")
        trace.finish(fallback: .proxyStopped)
        XCTAssertEqual(summaries.first?.attempts.map(\.outcome), [.cancelled])
    }

    func testEmptyDoHAnswerIsNil() {
        let trace = makeTrace()
        trace.dnsStarted()
        trace.dnsFinished(ips: [])
        trace.finish(fallback: .clientClosed)
        XCTAssertNil(summaries.first?.dohIPs)
        XCTAssertNotNil(summaries.first?.dnsEnd)
    }

    // MARK: - Terminal events

    /// One side ending cancels the other, whose ECANCELED must not overwrite the real cause.
    func testTheFirstEndEventWins() {
        let trace = makeTrace()
        trace.end(.serverReset)
        trace.end(.clientClosed)
        trace.finish(fallback: .clientClosed)
        XCTAssertEqual(summaries.map(\.endReason), [.serverReset])
    }

    func testDNSOnlyFailureWithoutDoHAnswerIsDNSFailed() {
        let trace = makeTrace()
        trace.finish(fallback: .connectFailed(.dns))
        XCTAssertEqual(summaries.map(\.endReason), [.dnsFailed])
    }

    /// DoH gave addresses, yet the dial reported DNS errors: keep what the dial said.
    func testDNSOnlyFailureAfterADoHAnswerStaysConnectFailed() {
        let trace = makeTrace()
        trace.dnsStarted()
        trace.dnsFinished(ips: ["10.0.0.1"])
        trace.finish(fallback: .connectFailed(.dns))
        XCTAssertEqual(summaries.map(\.endReason), [.connectFailed(.dns)])
    }

    // MARK: - Mapping

    func testConnectErrorFromDialErrors() {
        let cases: [([NWError], ConnectError)] = [
            ([.posix(.ECONNREFUSED)], .refused),
            ([.posix(.EHOSTUNREACH), .posix(.ECONNREFUSED)], .refused),
            ([.posix(.EHOSTUNREACH)], .unreachable),
            ([.dns(-65554), .posix(.ENETUNREACH)], .unreachable),
            ([.dns(-65554), .dns(-65554)], .dns),
            ([.posix(.ECONNRESET), .posix(.ETIMEDOUT)], .other(ETIMEDOUT)),
            ([], .other(0)),
        ]
        for (errors, expected) in cases {
            XCTAssertEqual(ConnectError(errors), expected, "\(errors)")
        }
    }

    func testEndReasonForEveryCloseReason() {
        let error = NWError.posix(.EPIPE)
        let cases: [(CloseReason, EndReason)] = [
            (.connectFailed(.dial(.allFailed([.posix(.ECONNREFUSED)]))), .connectFailed(.refused)),
            (.connectFailed(.dial(.allFailed([.dns(-65554)]))), .connectFailed(.dns)),
            (.connectFailed(.dial(.timeout)), .connectFailed(.timeout)),
            (.connectFailed(.dial(.cancelled)), .clientClosed),
            (.connectFailed(.shadowsocks), .outlineConnectFailed),
            (.routeChanged(.direct), .rerouted),
            (.proxyStopped, .proxyStopped),
            (.idleTimeout, .idleTimeout),
            (.relayFinished, .clientClosed),
            (.deadline("first flight", seconds: 10), .clientClosed),
            (.clientClosedBeforeFirstFlight, .clientClosed),
            (.clientWriteFailed(error), .clientClosed),
            (.upstreamWriteFailed(error), .serverError(EPIPE)),
            (.firstFlightWriteFailed(error), .serverError(EPIPE)),
            (.clientConnectionCancelled, .clientClosed),
        ]
        for (reason, expected) in cases {
            XCTAssertEqual(reason.endReason, expected, "\(reason)")
        }
    }

    func testRefusalTargetComesFromTheFailure() {
        let target = DialTarget(host: "1.2.3.4", port: 443)
        XCTAssertEqual(RefusalReason.handshake(.socks4(target: target)).target, target)
        XCTAssertNil(RefusalReason.handshake(.http2Preface).target)
        XCTAssertNil(RefusalReason.overCapacity.target)
    }

    // MARK: - First payload and relay (step 5e)

    private func advance(_ seconds: Double) { clock += UInt64(seconds * 1e9) }

    func testPhaseChangesAreReportedUntilTheEnd() {
        var phases: [TracePhase] = []
        let trace = ConnectionTrace(Self.start, queue: queue, clock: { [unowned self] in clock },
                                    onPhase: { phases.append($0) }) { [unowned self] in summaries.append($0) }
        trace.dnsStarted()
        trace.attemptStarted("1.2.3.4")
        trace.attemptStarted("::1")
        trace.attemptReady("1.2.3.4")
        trace.payloadSent(kind: .ssh)
        trace.finish(fallback: .clientClosed)
        XCTAssertEqual(phases, [.resolving, .connecting, .connected, .payloadSent], "ended comes as the summary")
    }

    func testEndedDateIsOnTheWallClock() {
        let start = TraceStart(id: 1, startedAt: Date(timeIntervalSince1970: 1_000), startedAtNanos: clock, inbound: .http,
                               host: "example.com", port: 443, isIPLiteral: false, profileID: UUID(), profileName: "Master",
                               isDefaultProfile: true, outbound: .direct)
        let trace = ConnectionTrace(start, queue: queue, clock: { [unowned self] in clock }) { [unowned self] in summaries.append($0) }
        advance(2.5)
        trace.finish(fallback: .clientClosed)
        XCTAssertEqual(summaries.first?.endedDate, Date(timeIntervalSince1970: 1_002.5))
    }

    func testPayloadSentRecordsTheKindOnce() {
        let trace = makeTrace()
        trace.setApplied(.passthrough(.notTLS))
        trace.payloadSent(kind: .ssh)
        advance(1)
        trace.payloadSent(kind: .tlsOther)
        trace.relayed(10, fromLeft: true, prefix: Data("GET / HTTP/1.1\r\n".utf8))
        XCTAssertEqual(trace.phase, .payloadSent)
        trace.finish(fallback: .clientClosed)
        XCTAssertEqual(summaries.first?.kind, .ssh)
        XCTAssertEqual(summaries.first?.applied, .passthrough(.notTLS))
        XCTAssertEqual(summaries.first?.payloadSentAt, 1_000_000_000, "the first payload's time")
        XCTAssertEqual(summaries.first?.bytesUp, 10)
    }

    /// A relay that carries the first payload sniffs it.
    func testFirstRelayedClientChunkIsThePayload() {
        let trace = makeTrace()
        trace.setApplied(.passthrough(.splitNone))
        trace.relayed(5, fromLeft: true, prefix: Data("SSH-2.0-x\r\n".utf8))
        trace.finish(fallback: .clientClosed)
        XCTAssertEqual(summaries.first?.kind, .ssh)
        XCTAssertNotNil(summaries.first?.payloadSentAt)
    }

    func testServerFirstSetsTheKindAndResponding() throws {
        let trace = makeTrace()
        trace.setApplied(.passthrough(.clientSilent))
        let banner = Data("220 mail.example ESMTP\r\n".utf8) + Data(repeating: 0x41, count: 200)
        trace.relayed(banner.count, fromLeft: false, prefix: banner)
        XCTAssertEqual(trace.phase, .responding)
        advance(0.5)
        trace.relayed(4, fromLeft: true, prefix: Data("EHLO".utf8))
        trace.finish(fallback: .clientClosed)
        let summary = try XCTUnwrap(summaries.first)
        XCTAssertEqual(summary.kind, .serverFirst(.smtpOrFTP))
        XCTAssertEqual(summary.firstDownPrefix?.count, ConnectionTrace.downPrefixLength)
        XCTAssertNil(summary.tFirstDown, "the server spoke before the client")
    }

    func testTimingsAreRelativeToThePayload() throws {
        let trace = makeTrace()
        trace.payloadSent(kind: .tlsOther)
        advance(0.25)
        trace.relayed(100, fromLeft: false, prefix: Data([0x16, 0x03, 0x03]))
        advance(0.75)
        trace.finish(fallback: .clientClosed)
        let summary = try XCTUnwrap(summaries.first)
        XCTAssertEqual(try XCTUnwrap(summary.tFirstDown), 0.25, accuracy: 1e-9)
        XCTAssertEqual(try XCTUnwrap(summary.tEnd), 1.0, accuracy: 1e-9)
        XCTAssertEqual(summary.reached, .responding)
        XCTAssertEqual(summary.bytesDown, 100)
    }

    func testNothingSentIsKindNone() {
        let trace = makeTrace()
        trace.setApplied(.passthrough(.clientSilent))
        trace.finish(fallback: .clientClosed)
        XCTAssertEqual(summaries.first?.kind, PayloadKind.none)
    }

    func testRelayEndEventsMapToEndReasons() {
        let cases: [(RelayEndEvent, EndReason)] = [
            (.readError(fromLeft: false, .posix(.ECONNRESET)), .serverReset),
            (.readError(fromLeft: false, .posix(.ETIMEDOUT)), .serverError(ETIMEDOUT)),
            (.eof(fromLeft: false), .serverFin),
            (.readError(fromLeft: true, .posix(.ECONNRESET)), .clientClosed),
            (.eof(fromLeft: true), .clientClosed),
            (.writeError(toLeft: true, .posix(.EPIPE)), .clientClosed),
            (.writeError(toLeft: false, .posix(.EPIPE)), .serverError(EPIPE)),
            (.idleTimeout, .idleTimeout),
        ]
        for (event, expected) in cases {
            XCTAssertEqual(event.endReason, expected, "\(event)")
        }
    }

    /// The server's reset arrives first; the client side's ECANCELED afterwards doesn't count.
    func testTheRelaysFirstEndEventWins() {
        let trace = makeTrace()
        trace.relayEnded(.readError(fromLeft: false, .posix(.ECONNRESET)))
        trace.relayEnded(.readError(fromLeft: true, .posix(.ECANCELED)))
        trace.finish(fallback: .clientClosed)
        XCTAssertEqual(summaries.map(\.endReason), [.serverReset])
    }

    // MARK: - Stall check (§3)

    func testSilenceAfterThePayloadIsAStallBeforeResponse() throws {
        let trace = makeTrace()
        trace.payloadSent(kind: .tlsOther)
        advance(DetectionConfig.standard.stallSeconds - 0.1)
        trace.relayTick(now: clock)
        trace.finish(fallback: .proxyStopped)
        XCTAssertNil(summaries.first?.stall)

        summaries = []
        let second = makeTrace()
        second.payloadSent(kind: .tlsOther)
        advance(DetectionConfig.standard.stallSeconds)
        second.relayTick(now: clock)
        second.finish(fallback: .clientClosed)
        let stall = try XCTUnwrap(summaries.first?.stall)
        XCTAssertEqual(stall.phase, .beforeResponse)
        XCTAssertEqual(stall.bytesDownAtStall, 0)
        XCTAssertFalse(stall.resumed)
    }

    func testMidStreamStallThatResumes() throws {
        let trace = makeTrace()
        trace.payloadSent(kind: .tlsOther)
        trace.relayed(20_000, fromLeft: false, prefix: Data([0x16]))
        advance(1)
        trace.relayed(50, fromLeft: true, prefix: Data([0x17]))
        advance(DetectionConfig.standard.stallSeconds)
        trace.relayTick(now: clock)
        trace.relayed(1_000, fromLeft: false, prefix: Data([0x17]))
        trace.relayTick(now: clock)
        trace.finish(fallback: .clientClosed)
        let stall = try XCTUnwrap(summaries.first?.stall)
        XCTAssertEqual(stall.phase, .midStream)
        XCTAssertEqual(stall.bytesDownAtStall, 20_000)
        XCTAssertTrue(stall.resumed)
    }

    /// The server answered last: the client is the one being quiet, which is no stall.
    func testWaitingOnTheClientIsNotAStall() {
        let trace = makeTrace()
        trace.payloadSent(kind: .tlsOther)
        advance(0.1)
        trace.relayed(500, fromLeft: false, prefix: Data([0x16]))
        advance(60)
        trace.relayTick(now: clock)
        trace.finish(fallback: .clientClosed)
        XCTAssertNil(summaries.first?.stall)
    }

    // MARK: - Transport reports (§2.3)

    private final class FakeReports: TransportReports {
        var establishment: EstablishmentInfo?
        var transfers: [TransferInfo?]
        private(set) var started = 0
        private(set) var collected = 0

        init(establishment: EstablishmentInfo?, transfers: [TransferInfo?]) {
            self.establishment = establishment
            self.transfers = transfers
        }

        func establishment(queue: DispatchQueue, completion: @escaping (EstablishmentInfo?) -> Void) {
            let info = establishment
            queue.async { completion(info) }
        }

        func startTransfer() -> PendingTransfer {
            started += 1
            return Pending(owner: self, info: transfers.isEmpty ? nil : transfers.removeFirst())
        }

        /// Nil `info`: the report never comes back.
        struct Pending: PendingTransfer {
            let owner: FakeReports
            let info: TransferInfo?
            func collect(queue: DispatchQueue, completion: @escaping (TransferInfo) -> Void) {
                owner.collected += 1
                guard let info else { return }
                queue.async { completion(info) }
            }
        }
    }

    private func drain() { for _ in 0..<5 { queue.sync {} } }

    func testReportsFillTheSummaryAtFinish() throws {
        let reports = FakeReports(establishment: EstablishmentInfo(tcpRTT: 0.040, resolvedIP: "10.0.0.1"),
                                  transfers: [TransferInfo(retransmittedBytes: 517, minimumRTT: 0.035, smoothedRTT: 0.050)])
        let trace = makeTrace()
        queue.sync { trace.attemptStarted("10.0.0.1"); trace.attemptReady("10.0.0.1", reports: reports) }
        drain()
        queue.sync { trace.finish(fallback: .clientClosed) }
        drain()
        let summary = try XCTUnwrap(queue.sync { summaries.first })
        XCTAssertEqual(reports.collected, 1)
        XCTAssertEqual(summary.establishment.tcpRTT, 0.040)
        XCTAssertEqual(summary.establishment.resolvedIP, "10.0.0.1")
        XCTAssertEqual(summary.transfer.retransmittedBytes, 517)
        XCTAssertEqual(summary.rtt, 0.040, "the handshake RTT beats the transport's")
    }

    func testAReportThatNeverComesBackDelaysTheSummaryByReportWaitOnly() {
        let reports = FakeReports(establishment: nil, transfers: [nil])
        let trace = makeTrace()
        queue.sync { trace.attemptReady("10.0.0.1", reports: reports) }
        queue.sync { trace.finish(fallback: .clientClosed) }
        XCTAssertEqual(queue.sync { summaries.count }, 0, "waiting for the report")
        XCTAssertTrue(eventually(timeout: 1) { self.queue.sync { self.summaries.count == 1 } })
        XCTAssertNil(queue.sync { summaries.first?.rtt })
    }

    /// §2.3 #1: silence after the payload past helloBlackholeMin collects a report early and
    /// starts another, which the finish collects. Retransmits add up.
    func testSuspectedBlackholeCollectsEarly() throws {
        let reports = FakeReports(establishment: nil, transfers: [
            TransferInfo(retransmittedBytes: 1_034, minimumRTT: 0.030, smoothedRTT: 0.031),
            TransferInfo(retransmittedBytes: 517, minimumRTT: 0, smoothedRTT: 0.045),
        ])
        let trace = makeTrace()
        queue.sync {
            trace.attemptReady("10.0.0.1", reports: reports)
            trace.payloadSent(kind: .tlsOther)
        }
        advance(DetectionConfig.standard.helloBlackholeMin)
        queue.sync { trace.relayTick(now: clock) }
        queue.sync { trace.relayTick(now: clock) }
        drain()
        XCTAssertEqual(reports.collected, 1)
        XCTAssertEqual(reports.started, 2)
        queue.sync { trace.finish(fallback: .clientClosed) }
        drain()
        let summary = try XCTUnwrap(queue.sync { summaries.first })
        XCTAssertEqual(summary.transfer.retransmittedBytes, 1_551)
        XCTAssertEqual(summary.transfer.minimumRTT, 0.030, "zero means not measured")
        XCTAssertEqual(summary.transfer.smoothedRTT, 0.045)
        XCTAssertEqual(summary.rtt, 0.030)
    }

    /// A crash on macOS 26: the system's count plus an earlier one overflowed UInt64 and trapped.
    func testRetransmitsSaturateInsteadOfOverflowing() {
        var info = TransferInfo(retransmittedBytes: 517)
        info.add(TransferInfo(retransmittedBytes: .max))
        XCTAssertEqual(info.retransmittedBytes, .max)
    }
}
