import XCTest
@testable import SpoofyCore

final class HTTPHeadParserTests: XCTestCase {
    private func parse(_ text: String) -> InboundStep {
        var parser = HTTPHeadParser()
        return parser.feed(Data(text.utf8))
    }

    private func request(_ step: InboundStep, file: StaticString = #filePath, line: UInt = #line) -> InboundRequest? {
        guard case .request(let request) = step else {
            XCTFail("expected a request, got \(step)", file: file, line: line)
            return nil
        }
        return request
    }

    private func status(_ step: InboundStep) -> String? {
        guard case .fail(let reply?, _) = step else { return nil }
        return String(decoding: reply, as: UTF8.self).components(separatedBy: "\r\n").first
    }

    // MARK: - CONNECT

    func testConnectForms() throws {
        let cases: [(String, DialTarget)] = [
            ("example.com:443", DialTarget(host: "example.com", port: 443)),
            ("[2001:db8::1]:8443", DialTarget(host: "2001:db8::1", port: 8443)),
            ("127.0.0.1:1", DialTarget(host: "127.0.0.1", port: 1)),
        ]
        for (authority, target) in cases {
            let req = try XCTUnwrap(request(parse("CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\n\r\n")))
            XCTAssertEqual(req.target, target, authority)
            XCTAssertEqual(req.kind, .tunnel)
            XCTAssertEqual(req.leftover, Data())
        }
    }

    func testConnectMethodIsCaseInsensitiveLikeBefore() throws {
        XCTAssertNotNil(request(parse("connect example.com:443 HTTP/1.1\r\n\r\n")))
    }

    func testBadConnectAuthoritiesAre400() {
        let host256 = String(repeating: "a", count: 256)
        for authority in ["example.com", "example.com:", "example.com:0", "example.com:65536", "example.com:44x",
                          "[::1", "[::1]443", "[nothex]:443", "2001:db8::1:443", ":443", "\(host256):443",
                          "a/b:443", "user@host:443"] {
            XCTAssertEqual(status(parse("CONNECT \(authority) HTTP/1.1\r\n\r\n")), "HTTP/1.1 400 Bad Request", authority)
        }
    }

    func testHost255BytesIsAccepted() throws {
        let host = String(repeating: "a", count: 255)
        XCTAssertEqual(try XCTUnwrap(request(parse("CONNECT \(host):443 HTTP/1.1\r\n\r\n"))).target.host, host)
    }

    func testBytesAfterTheHeadAreLeftover() throws {
        let req = try XCTUnwrap(request(parse("CONNECT a.b:443 HTTP/1.1\r\n\r\n\u{16}\u{03}\u{01}")))
        XCTAssertEqual(req.leftover, Data([0x16, 0x03, 0x01]))
    }

    // MARK: - Incremental input (N9)

    func testHeadSplitAtEveryByteGivesTheSameResult() throws {
        let text = "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nCookie: abc\r\n\r\nBODY"
        let whole = try XCTUnwrap(request(parse(text)))
        var parser = HTTPHeadParser()
        var result: InboundRequest?
        for (i, byte) in Data(text.utf8).enumerated() {
            let step = parser.feed(Data([byte]))
            if case .request(let req) = step {
                result = req
                XCTAssertEqual(i, text.utf8.count - 5, "decided on the last byte of the head")
                break
            }
            guard case .needMore = step else { return XCTFail("byte \(i): \(step)") }
        }
        let split = try XCTUnwrap(result)
        XCTAssertEqual(split.target, whole.target)
        XCTAssertEqual(split.kind, whole.kind)
        XCTAssertEqual(split.leftover, Data(), "nothing after the head had arrived yet")
    }

    func testHeadOver64KBIs431() {
        var parser = HTTPHeadParser()
        XCTAssertNotNil({ if case .needMore = parser.feed(Data("GET http://a/ HTTP/1.1\r\n".utf8)) { return () } else { return nil } }())
        let step = parser.feed(Data(repeating: UInt8(ascii: "x"), count: HTTPHeadParser.maxHead))
        XCTAssertEqual(status(step), "HTTP/1.1 431 Request Header Fields Too Large")
    }

    func testLongHeadUnderTheLimitIsAccepted() throws {
        let cookie = String(repeating: "c", count: 60_000)
        XCTAssertNotNil(request(parse("GET http://a/ HTTP/1.1\r\nCookie: \(cookie)\r\n\r\n")))
    }

    // MARK: - Malformed

    func testMalformedRequestLinesAre400() {
        for line in ["NOT-HTTP", "GET http://a/", "GET  http://a/ HTTP/1.1", "GET http://a/ HTTP/2.0",
                     "G(T http://a/ HTTP/1.1", "GET /relative HTTP/1.1", "GET https://a/ HTTP/1.1", "GET * HTTP/1.1"] {
            XCTAssertEqual(status(parse("\(line)\r\n\r\n")), "HTTP/1.1 400 Bad Request", line)
        }
    }

    func testNonASCIIRequestLineIs400() {
        var parser = HTTPHeadParser()
        let step = parser.feed(Data("GET http://a/ HTTP/1.1".utf8) + Data([0xFF]) + Data("\r\n\r\n".utf8))
        XCTAssertEqual(status(step), "HTTP/1.1 400 Bad Request")
    }

    // MARK: - Absolute-form rewrite (N9)

    private func rewritten(_ text: String) throws -> (InboundRequest, String) {
        let req = try XCTUnwrap(request(parse(text)))
        guard case .http(let head) = req.kind else {
            XCTFail("expected plain HTTP")
            return (req, "")
        }
        return (req, String(decoding: head, as: UTF8.self))
    }

    func testAbsoluteFormBecomesOriginForm() throws {
        let (req, head) = try rewritten(
            "POST http://Example.com:8080/a/b?q=1#frag HTTP/1.1\r\n"
            + "Host: Example.com:8080\r\n"
            + "Proxy-Connection: keep-alive\r\n"
            + "Proxy-Authorization: Basic eA==\r\n"
            + "Connection: keep-alive\r\n"
            + "Keep-Alive: timeout=5\r\n"
            + "Content-Length: 4\r\n\r\nBODY")
        XCTAssertEqual(req.target, DialTarget(host: "Example.com", port: 8080))
        XCTAssertEqual(head, "POST /a/b?q=1 HTTP/1.1\r\n"
                       + "Host: Example.com:8080\r\n"
                       + "Content-Length: 4\r\n"
                       + "Connection: close\r\n\r\n")
        XCTAssertEqual(req.leftover, Data("BODY".utf8), "the body start is forwarded as-is")
    }

    func testDefaultsForPortAndPath() throws {
        for (target, path) in [("http://a.b", "/"), ("http://a.b?x=1", "/?x=1"), ("HTTP://a.b/", "/")] {
            let (req, head) = try rewritten("GET \(target) HTTP/1.1\r\nHost: a.b\r\n\r\n")
            XCTAssertEqual(req.target, DialTarget(host: "a.b", port: 80), target)
            XCTAssertTrue(head.hasPrefix("GET \(path) HTTP/1.1\r\n"), head)
        }
    }

    func testIPv6AndUserinfoAuthorities() throws {
        let (v6, _) = try rewritten("GET http://[::1]:81/ HTTP/1.1\r\nHost: [::1]:81\r\n\r\n")
        XCTAssertEqual(v6.target, DialTarget(host: "::1", port: 81))
        let (user, head) = try rewritten("GET http://u:p@a.b/ HTTP/1.1\r\n\r\n")
        XCTAssertEqual(user.target, DialTarget(host: "a.b", port: 80))
        XCTAssertTrue(head.contains("\r\nHost: a.b\r\n"), head)
    }

    func testMissingHostIsAddedAndVersionIsKept() throws {
        let (_, head) = try rewritten("GET http://a.b:81/x HTTP/1.0\r\nAccept: */*\r\n\r\n")
        XCTAssertEqual(head, "GET /x HTTP/1.0\r\nAccept: */*\r\nHost: a.b:81\r\nConnection: close\r\n\r\n")
    }

    func testHeaderNamesAreMatchedCaseInsensitivelyAndFoldsFollowTheirHeader() throws {
        let (_, head) = try rewritten("GET http://a.b/ HTTP/1.1\r\nhost: a.b\r\nPROXY-CONNECTION: x\r\n\tcontinued\r\n"
                                      + "X-Long: one\r\n two\r\n\r\n")
        XCTAssertEqual(head, "GET / HTTP/1.1\r\nhost: a.b\r\nX-Long: one\r\n two\r\nConnection: close\r\n\r\n")
    }

    func testNonUTF8HeaderBytesAreKept() throws {
        var parser = HTTPHeadParser()
        let header = Data("X-Raw: ".utf8) + Data([0xE9, 0xFF]) + Data("\r\n".utf8)
        let step = parser.feed(Data("GET http://a.b/ HTTP/1.1\r\n".utf8) + header + Data("\r\n".utf8))
        guard case .request(let req) = step, case .http(let head) = req.kind else { return XCTFail("\(step)") }
        XCTAssertNotNil(head.firstRange(of: header))
    }
}
