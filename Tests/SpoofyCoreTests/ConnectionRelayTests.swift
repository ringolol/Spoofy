import Network
import XCTest
@testable import SpoofyCore

final class ConnectionRelayTests: XCTestCase {
    private let queue = DispatchQueue(label: "ConnectionRelayTests")

    private func relay(_ left: FakeConnection, _ right: FakeConnection,
                       idleTimeout: Double = 120, idleCheckInterval: DispatchTimeInterval = .seconds(15)) -> XCTestExpectation {
        let done = expectation(description: "relay completion")
        done.assertForOverFulfill = true
        ConnectionRelay.relay(left: left, right: right, queue: queue,
                              idleTimeout: idleTimeout, idleCheckInterval: idleCheckInterval) {
            done.fulfill()
        }
        return done
    }

    private func data(_ text: String) -> FakeConnection.Event { .data(Data(text.utf8)) }

    func testClientToServerPreservesChunksAndEOFCancelsBoth() {
        let left = FakeConnection(queue: queue, script: [data("GET "), data("/ HTTP/1.1\r\n"), .eof])
        let right = FakeConnection(queue: queue)
        wait(for: [relay(left, right)], timeout: 2)
        XCTAssertEqual(right.sent, [Data("GET ".utf8), Data("/ HTTP/1.1\r\n".utf8)])
        XCTAssertTrue(left.cancelled)
        XCTAssertTrue(right.cancelled)
    }

    func testServerToClient() {
        let left = FakeConnection(queue: queue)
        let right = FakeConnection(queue: queue, script: [data("HTTP/1.1 200 OK\r\n"), .eof])
        wait(for: [relay(left, right)], timeout: 2)
        XCTAssertEqual(left.sent, [Data("HTTP/1.1 200 OK\r\n".utf8)])
    }

    func testBothDirectionsInterleaved() {
        let left = FakeConnection(queue: queue)
        let right = FakeConnection(queue: queue)
        let done = relay(left, right)
        left.push(data("ping"))
        right.push(data("pong"))
        queue.asyncAfter(deadline: .now() + 0.1) {
            left.push(.data(Data("bye".utf8)))
            left.push(.eof)
        }
        wait(for: [done], timeout: 2)
        XCTAssertEqual(right.sent, [Data("ping".utf8), Data("bye".utf8)])
        XCTAssertEqual(left.sent, [Data("pong".utf8)])
    }

    func testReadErrorCancelsTheOtherSide() {
        let left = FakeConnection(queue: queue, script: [.error(.posix(.ECONNRESET))])
        let right = FakeConnection(queue: queue)
        wait(for: [relay(left, right)], timeout: 2)
        XCTAssertTrue(right.cancelled)
    }

    // N14: a write error cancels only the source, so the opposite pipe stays parked in
    // receive() until the idle timeout. (A failed NWConnection usually errors its pending
    // receive too, which hides this; a ShadowsocksStream doesn't.)
    func testWriteErrorStopsTheRelay() {
        let left = FakeConnection(queue: queue, script: [data("hello")])
        let right = FakeConnection(queue: queue)
        right.sendError = .posix(.EPIPE)
        let finished = LockedFlag()
        ConnectionRelay.relay(left: left, right: right, queue: queue) { _ = finished.setIfFalse() }

        let settled = expectation(description: "settled")
        queue.asyncAfter(deadline: .now() + 0.2) { settled.fulfill() }
        wait(for: [settled], timeout: 2)

        XCTAssertTrue(left.cancelled)
        XCTAssertEqual(right.sent, [])
        XCTExpectFailure("N14: write error leaves the other direction running") {
            XCTAssertTrue(right.cancelled)
            XCTAssertFalse(finished.setIfFalse(), "relay should have completed")
        }
        right.cancel()
    }

    func testIdleTimeoutCancelsBoth() {
        let left = FakeConnection(queue: queue)
        let right = FakeConnection(queue: queue)
        wait(for: [relay(left, right, idleTimeout: 0.05, idleCheckInterval: .milliseconds(20))], timeout: 2)
        XCTAssertTrue(left.cancelled)
        XCTAssertTrue(right.cancelled)
    }

    func testTrafficKeepsTheRelayAlive() {
        let left = FakeConnection(queue: queue)
        let right = FakeConnection(queue: queue)
        let done = relay(left, right, idleTimeout: 0.15, idleCheckInterval: .milliseconds(20))
        done.isInverted = true
        // Keep sending for 0.4 s, well past the idle timeout.
        for i in 0..<8 {
            queue.asyncAfter(deadline: .now() + .milliseconds(50 * i)) { left.push(.data(Data([UInt8(i)]))) }
        }
        wait(for: [done], timeout: 0.4)
        XCTAssertFalse(right.cancelled)
        XCTAssertEqual(right.sent.count, 8)
        left.cancel()
    }
}
