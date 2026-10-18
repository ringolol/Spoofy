import Network
import XCTest
@testable import SpoofyCore

/// Network-scanner plan §2.1: the trace's lifecycle and the end-reason mapping.
final class ConnectionTraceTests: XCTestCase {
    private var summaries: [TraceSummary] = []

    private static let start = TraceStart(
        id: 7, startedAt: Date(), startedAtNanos: DispatchTime.now().uptimeNanoseconds, inbound: .http,
        host: "example.com", port: 443, isIPLiteral: false, profileID: UUID(), profileName: "Master",
        isDefaultProfile: true, outbound: .direct)

    private func makeTrace() -> ConnectionTrace {
        ConnectionTrace(Self.start) { [unowned self] in summaries.append($0) }
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
}
