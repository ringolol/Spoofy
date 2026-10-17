import Network
import XCTest
@testable import SpoofyCore

final class SOCKS5ParserTests: XCTestCase {
    private static let greeting = Data([0x05, 0x01, 0x00])
    private static let methodAccepted = Data([0x05, 0x00])

    private static func connect(_ address: [UInt8], port: UInt16 = 443) -> Data {
        Data([0x05, 0x01, 0x00] + address + [UInt8(port >> 8), UInt8(port & 0xFF)])
    }

    private static let ipv4Request = connect([0x01, 10, 0, 0, 1])

    /// Feeds `chunks` in order and flattens the steps: replies collected, final step returned.
    private func run(_ chunks: [Data]) -> (replies: [Data], last: InboundStep?) {
        var parser = SOCKS5Parser()
        var replies: [Data] = []
        var last: InboundStep?
        for chunk in chunks {
            var step = parser.feed(chunk)
            while case .reply(let bytes, let then) = step {
                replies.append(bytes)
                step = then
            }
            last = step
            if case .needMore = step { continue }
            break
        }
        return (replies, last)
    }

    private func request(_ step: InboundStep?, file: StaticString = #filePath, line: UInt = #line) -> InboundRequest? {
        guard case .request(let req)? = step else {
            XCTFail("expected a request, got \(String(describing: step))", file: file, line: line)
            return nil
        }
        return req
    }

    private func failure(_ step: InboundStep?) -> Data?? {
        guard case .fail(let reply, _)? = step else { return nil }
        return .some(reply)
    }

    // MARK: - Address types

    func testAddressTypes() throws {
        let cases: [([UInt8], String)] = [
            ([0x01, 192, 168, 1, 20], "192.168.1.20"),
            ([0x04] + [UInt8](repeating: 0, count: 15) + [1], "::1"),
            ([0x04, 0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [0x42], "2001:db8::42"),
            ([0x03, 11] + Array("example.com".utf8), "example.com"),
        ]
        for (address, host) in cases {
            let (replies, last) = run([Self.greeting, Self.connect(address, port: 8443)])
            XCTAssertEqual(replies, [Self.methodAccepted])
            let req = try XCTUnwrap(request(last))
            XCTAssertEqual(req.target, DialTarget(host: host, port: 8443))
            XCTAssertEqual(req.kind, .tunnel)
        }
    }

    // MARK: - N6: pipelining and short reads

    func testGreetingRequestAndHelloInOneChunk() throws {
        let hello = Fixtures.tls13ClientHello
        let (replies, last) = run([Self.greeting + Self.ipv4Request + hello])
        XCTAssertEqual(replies, [Self.methodAccepted])
        let req = try XCTUnwrap(request(last))
        XCTAssertEqual(req.target, DialTarget(host: "10.0.0.1", port: 443))
        XCTAssertEqual(req.leftover, hello, "bytes after the request reach the outbound unmodified")
    }

    func testByteByByte() throws {
        let stream = Self.greeting + Self.connect([0x03, 3] + Array("a.b".utf8)) + Data("tail".utf8)
        var parser = SOCKS5Parser()
        var replies: [Data] = []
        var result: InboundRequest?
        for (i, byte) in stream.enumerated() {
            var step = parser.feed(Data([byte]))
            while case .reply(let bytes, let then) = step {
                replies.append(bytes)
                step = then
            }
            switch step {
            case .needMore: continue
            case .request(let req): result = req
            default: return XCTFail("byte \(i): \(step)")
            }
            break
        }
        XCTAssertEqual(replies, [Self.methodAccepted])
        let req = try XCTUnwrap(result)
        XCTAssertEqual(req.target, DialTarget(host: "a.b", port: 443))
        XCTAssertEqual(req.leftover, Data(), "decided on the last port byte")
        XCTAssertEqual(parser.state, .done)
    }

    func testGreetingWithSeveralMethods() throws {
        let (replies, last) = run([Data([0x05, 0x03, 0x02, 0x01, 0x00]), Self.ipv4Request])
        XCTAssertEqual(replies, [Self.methodAccepted])
        XCTAssertNotNil(request(last))
    }

    // MARK: - Failures

    func testBadVersionInGreetingClosesWithoutReply() {
        XCTAssertEqual(failure(run([Data([0x04, 0x01, 0x00])]).last), .some(nil))
    }

    func testNoAcceptableMethodIs0xFF() {
        XCTAssertEqual(failure(run([Data([0x05, 0x01, 0x02])]).last), Data([0x05, 0xFF]))
        XCTAssertEqual(failure(run([Data([0x05, 0x00])]).last), Data([0x05, 0xFF]), "no methods at all")
    }

    func testRequestFailureCodes() {
        let cases: [(Data, UInt8)] = [
            (Data([0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]), 0x01),            // version
            (Data([0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80]), 0x07),            // BIND
            (Data([0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0, 80]), 0x07),            // UDP ASSOCIATE
            (Data([0x05, 0x01, 0x00, 0x09]), 0x08),                               // address type
            (Data([0x05, 0x01, 0x00, 0x03, 0x00, 0, 80]), 0x01),                  // empty domain
            (Data([0x05, 0x01, 0x00, 0x03, 0x02, 0xC3, 0xA9, 0, 80]), 0x01),      // non-ASCII domain
            (Data([0x05, 0x01, 0x00, 0x03, 0x02, 0x61, 0x20, 0, 80]), 0x01),      // space in domain
            (Self.connect([0x01, 1, 2, 3, 4], port: 0), 0x01),                    // port 0
        ]
        for (request, code) in cases {
            XCTAssertEqual(failure(run([Self.greeting, request]).last), SOCKS5Parser.reply(code), request.hex)
        }
    }

    func testReplyLayout() {
        // M7: BND.ADDR is always 0.0.0.0:0.
        XCTAssertEqual(SOCKS5Parser.reply(0x00), Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    }

    func testReplyCodeForOutboundErrors() {
        let cases: [(OutboundError, UInt8)] = [
            (.dial(.timeout), 0x06),
            (.dial(.allFailed([.posix(.ECONNREFUSED)])), 0x05),
            (.dial(.allFailed([.posix(.ECONNREFUSED), .posix(.EHOSTUNREACH)])), 0x04),
            (.dial(.allFailed([.posix(.ENETUNREACH)])), 0x03),
            (.dial(.allFailed([.dns(-65554)])), 0x04),
            (.dial(.allFailed([.posix(.ECONNRESET)])), 0x01),
            (.dial(.cancelled), 0x01),
            (.shadowsocks, 0x01),
        ]
        for (error, code) in cases {
            XCTAssertEqual(SOCKS5Parser.replyCode(for: error), code, "\(error)")
        }
    }
}
