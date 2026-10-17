import Network
import XCTest
@testable import SpoofyCore

final class SegmentWriterTests: XCTestCase {
    private let queue = DispatchQueue(label: "SegmentWriterTests")

    private func write(_ segments: [Data], to conn: FakeConnection) -> NWError? {
        let done = expectation(description: "write")
        var result: NWError?
        SegmentWriter.write(segments, to: conn) { error in
            result = error
            done.fulfill()
        }
        wait(for: [done], timeout: 2)
        return result
    }

    func testSendsEverySegmentInOrder() {
        let conn = FakeConnection(queue: queue)
        let segments = [Data([1]), Data([2, 3]), Data([4])]
        XCTAssertNil(write(segments, to: conn))
        XCTAssertEqual(conn.sent, segments)
    }

    func testNoSegmentsCompletesAtOnce() {
        let conn = FakeConnection(queue: queue)
        XCTAssertNil(write([], to: conn))
        XCTAssertEqual(conn.sent, [])
    }

    // N7: the error reaches the caller, so it can close instead of relaying.
    func testFirstErrorStopsAndIsReported() {
        let conn = FakeConnection(queue: queue)
        conn.sendError = .posix(.ECONNRESET)
        XCTAssertEqual(write([Data([1]), Data([2])], to: conn), .posix(.ECONNRESET))
    }

    func testClientHelloIsSplitThenLeftoverFollows() {
        var profile = SpoofProfile.makeDefault()
        profile.splitMode = .firstByte
        profile.tlsRecordFragmentation = false
        let hello = Fixtures.tls12ClientHello
        let leftover = Data("after".utf8)
        let conn = FakeConnection(queue: queue)
        let done = expectation(description: "first flight")
        SegmentWriter.writeFirstFlight(.clientHello(record: hello, sniOffset: nil, leftover: leftover),
                                       profile: profile, to: conn, label: "test") { error in
            XCTAssertNil(error)
            done.fulfill()
        }
        wait(for: [done], timeout: 2)
        XCTAssertEqual(conn.sent, [hello.prefix(1), hello.dropFirst(), leftover])
    }

    func testRawAndNoneAreSentUnchanged() {
        let profile = SpoofProfile.makeDefault()
        let conn = FakeConnection(queue: queue)
        let done = expectation(description: "first flight")
        done.expectedFulfillmentCount = 2
        SegmentWriter.writeFirstFlight(.raw(Data("SSH-2.0".utf8)), profile: profile, to: conn, label: "test") { _ in
            SegmentWriter.writeFirstFlight(.empty, profile: profile, to: conn, label: "test") { _ in done.fulfill() }
            done.fulfill()
        }
        wait(for: [done], timeout: 2)
        XCTAssertEqual(conn.sent, [Data("SSH-2.0".utf8)])
    }
}
