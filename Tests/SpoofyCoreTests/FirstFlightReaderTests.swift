import Network
import XCTest
@testable import SpoofyCore

final class FirstFlightReaderTests: XCTestCase {
    private let queue = DispatchQueue(label: "FirstFlightReaderTests")

    private func read(_ reader: FirstFlightReader) -> FirstFlight?? {
        let done = expectation(description: "first flight")
        var result: FirstFlight??
        queue.async {
            reader.read { flight in
                result = .some(flight)
                done.fulfill()
            }
        }
        wait(for: [done], timeout: 2)
        return result
    }

    private func makeReader(_ client: FakeConnection, timeout: TimeInterval = 5) -> FirstFlightReader {
        FirstFlightReader(client: client, queue: queue, firstByteTimeout: timeout, label: "test")
    }

    func testHelloAcrossReadsWithLeftover() throws {
        let hello = Fixtures.tls13ClientHello
        let client = FakeConnection(queue: queue, script: [.data(hello.prefix(3)), .data(hello.dropFirst(3) + Data("x".utf8))])
        let reader = makeReader(client)
        guard case .clientHello(let record, let sni, let leftover) = try XCTUnwrap(read(reader)) else {
            return XCTFail("expected a ClientHello")
        }
        XCTAssertEqual(record, hello)
        XCTAssertNotNil(sni)
        XCTAssertEqual(leftover, Data("x".utf8))
        XCTAssertNil(reader.inFlightRead)
    }

    func testNonTLSIsRaw() throws {
        let client = FakeConnection(queue: queue, script: [.data(Data("ping".utf8))])
        guard case .raw(let bytes) = try XCTUnwrap(read(makeReader(client))) else { return XCTFail("expected raw") }
        XCTAssertEqual(bytes, Data("ping".utf8))
    }

    func testEOFOrErrorBeforeDecisionIsNil() throws {
        for event in [FakeConnection.Event.eof, .error(.posix(.ECONNRESET))] {
            let client = FakeConnection(queue: queue, script: [.data(Data([0x16, 0x03])), event])
            XCTAssertNil(try XCTUnwrap(read(makeReader(client))))
        }
    }

    /// U7: silence → `.empty`, and the read the timer left behind feeds the relay, whether its
    /// data arrives before or after the relay asks for it.
    func testTimeoutHandsTheInFlightReadToTheRelay() throws {
        for dataFirst in [true, false] {
            let client = FakeConnection(queue: queue)
            let reader = makeReader(client, timeout: 0.05)
            guard case .empty = try XCTUnwrap(read(reader)) else { return XCTFail("expected .empty") }
            let inFlight = try XCTUnwrap(reader.inFlightRead)

            let got = expectation(description: "in-flight read")
            let take = {
                inFlight { data, _, _, _ in
                    XCTAssertEqual(data, Data("late".utf8))
                    got.fulfill()
                }
            }
            if dataFirst {
                client.push(.data(Data("late".utf8)))
                queue.sync {}  // let the pending receive complete first
                queue.async(execute: take)
            } else {
                queue.async(execute: take)
                queue.sync {}
                client.push(.data(Data("late".utf8)))
            }
            wait(for: [got], timeout: 2)
        }
    }

    func testTimerIgnoredOnceBytesArrived() throws {
        let client = FakeConnection(queue: queue, script: [.data(Data([0x16]))])
        let reader = makeReader(client, timeout: 0.05)
        let done = expectation(description: "decision")
        var result: FirstFlight?
        queue.async { reader.read { result = $0; done.fulfill() } }
        // Partial header, then a pause longer than the timer: no `.empty`. Version 7 completes the
        // 5-byte header and makes it a passthrough.
        queue.asyncAfter(deadline: .now() + 0.2) {
            client.push(.data(Data([0x07, 0, 0, 0])))
        }
        wait(for: [done], timeout: 2)
        guard case .raw(let bytes) = result else { return XCTFail("expected raw, got \(String(describing: result))") }
        XCTAssertEqual(bytes, Data([0x16, 0x07, 0, 0, 0]))
        XCTAssertNil(reader.inFlightRead)
    }
}
