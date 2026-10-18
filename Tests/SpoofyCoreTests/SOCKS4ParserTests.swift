import XCTest
@testable import SpoofyCore

/// Step 5b (network-scanner plan §2.5.4): SOCKS4 is recognised and refused with its own reply.
final class SOCKS4ParserTests: XCTestCase {
    private static let rejected = Data([0x00, 0x5B, 0, 0, 0, 0, 0, 0])

    private static func socks4(port: UInt16 = 443, ip: [UInt8], user: String = "", host: String? = nil) -> Data {
        var bytes: [UInt8] = [0x04, 0x01, UInt8(port >> 8), UInt8(port & 0xFF)] + ip + Array(user.utf8) + [0]
        if let host { bytes += Array(host.utf8) + [0] }
        return Data(bytes)
    }

    /// Feeds `stream` split at `cut` (nil = one chunk) and returns the final step.
    private func run(_ stream: Data, cut: Int? = nil) -> InboundStep {
        var parser = InboundProtocol(firstByte: stream[stream.startIndex]).makeParser()
        guard let cut else { return parser.feed(stream) }
        let first = parser.feed(stream.prefix(cut))
        guard case .needMore = first else { return first }
        return parser.feed(stream.dropFirst(cut))
    }

    private func assertRefused(_ step: InboundStep, target: DialTarget?, file: StaticString = #filePath, line: UInt = #line) {
        guard case .fail(let reply, let failure) = step else {
            return XCTFail("expected a failure, got \(step)", file: file, line: line)
        }
        XCTAssertEqual(reply, Self.rejected, file: file, line: line)
        XCTAssertEqual(failure, .socks4(target: target), file: file, line: line)
    }

    func testFirstByte4PicksSOCKS4() {
        XCTAssertEqual(InboundProtocol(firstByte: 0x04), .socks4)
    }

    func testSOCKS4IsRefusedWithItsTarget() {
        assertRefused(run(Self.socks4(ip: [10, 0, 0, 1], user: "bob")), target: DialTarget(host: "10.0.0.1", port: 443))
    }

    func testSOCKS4aNamesTheHost() {
        assertRefused(run(Self.socks4(port: 80, ip: [0, 0, 0, 7], host: "example.com")),
                      target: DialTarget(host: "example.com", port: 80))
    }

    func testEveryByteBoundary() {
        let cases = [(Self.socks4(ip: [10, 0, 0, 1], user: "bob"), DialTarget(host: "10.0.0.1", port: 443)),
                     (Self.socks4(ip: [0, 0, 0, 1], host: "a.b"), DialTarget(host: "a.b", port: 443))]
        for (stream, expected) in cases {
            for cut in 1..<stream.count {
                assertRefused(run(stream, cut: cut), target: expected)
            }
        }
    }

    func testOverlongUserIDIsMalformed() {
        let step = run(Self.socks4(ip: [10, 0, 0, 1], user: String(repeating: "u", count: 300)))
        guard case .fail(_, .malformed) = step else { return XCTFail("\(step)") }
    }

    func testDescriptionNamesSOCKS4() {
        XCTAssertEqual(InboundFailure.socks4(target: nil).description, "SOCKS4 is not supported")
    }

    // MARK: - HTTP refusals

    private func httpFailure(_ text: String) -> InboundFailure? {
        var parser = HTTPHeadParser()
        guard case .fail(_, let failure) = parser.feed(Data(text.utf8)) else { return nil }
        return failure
    }

    func testHTTPRefusalsAreNamed() {
        XCTAssertEqual(httpFailure("GET /path HTTP/1.1\r\nHost: a.b\r\n\r\n"), .httpOriginForm)
        XCTAssertEqual(httpFailure("GET https://a.b/ HTTP/1.1\r\n\r\n"), .httpsAbsoluteForm)
        XCTAssertEqual(httpFailure("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), .http2Preface)
        XCTAssertEqual(httpFailure("NOT-HTTP\r\n\r\n"), .malformed("malformed request line"))
    }

    func testHTTPRefusalsKeepTheirLogText() {
        XCTAssertEqual(InboundFailure.httpOriginForm.description, "not an absolute http:// target (origin-form)")
        XCTAssertEqual(InboundFailure.httpsAbsoluteForm.description, "not an absolute http:// target (https://)")
        XCTAssertEqual(InboundFailure.http2Preface.description, "HTTP/2 connection preface")
    }
}
