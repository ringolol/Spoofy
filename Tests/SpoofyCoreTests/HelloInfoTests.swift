import XCTest
@testable import SpoofyCore

/// Step 5c (network-scanner plan §5): ClientHello / ServerHello summaries for the classifier.
final class HelloInfoTests: XCTestCase {
    private static func alpn(_ protocols: [String]) -> (type: UInt16, body: Data) {
        let list = protocols.reduce(Data()) { $0 + [UInt8($1.utf8.count)] + Data($1.utf8) }
        return (0x0010, ClientHelloBuilder.u16(list.count) + list)
    }

    func testCapturedHellos() throws {
        let tls13 = try XCTUnwrap(ClientHelloInfo.parse(record: Fixtures.tls13ClientHello))
        XCTAssertEqual(tls13.sni, "www.example.com")
        XCTAssertEqual(tls13.sessionID.count, 32)
        XCTAssertFalse(tls13.hasECH)
        let tls12 = try XCTUnwrap(ClientHelloInfo.parse(record: Fixtures.tls12ClientHello))
        XCTAssertEqual(tls12.sni, "api.github.com")
    }

    func testBuiltHelloWithECHAndALPN() throws {
        let record = ClientHelloBuilder.make(sni: "a.example", extensionsBefore: [
            Self.alpn(["h2", "http/1.1"]), (0xfe0d, Data(repeating: 0x11, count: 40)),
        ])
        let info = try XCTUnwrap(ClientHelloInfo.parse(record: record))
        XCTAssertEqual(info.sni, "a.example")
        XCTAssertTrue(info.hasECH)
        XCTAssertEqual(info.alpn, ["h2", "http/1.1"])
        XCTAssertEqual(info.sessionID, Data(repeating: 0xBB, count: 32))
    }

    func testHelloWithoutSNI() throws {
        XCTAssertNil(try XCTUnwrap(ClientHelloInfo.parse(record: ClientHelloBuilder.make(sni: nil))).sni)
    }

    func testNotAHello() {
        XCTAssertNil(ClientHelloInfo.parse(record: Data("GET / HTTP/1.1\r\n\r\n".utf8)))
        XCTAssertNil(ClientHelloInfo.parse(record: Fixtures.tls13ClientHello.prefix(30)))
    }

    func testExtractSNIOffsetIsUnchanged() throws {
        let message = try XCTUnwrap(TLSMessage.parse(from: Fixtures.tls13ClientHello))
        XCTAssertEqual(message.extractSNIOffset()?.start, 117)
        XCTAssertEqual(message.extractSNIOffset()?.end, 132)
    }

    // MARK: - ServerHello

    private static func serverHello(sessionID: Data, extensions: Data = Data()) -> Data {
        var body = Data([0x03, 0x03]) + Data(repeating: 0x01, count: 32)
        body += [UInt8(sessionID.count)] + sessionID
        body += [0x13, 0x01, 0x00]
        body += ClientHelloBuilder.u16(extensions.count) + extensions
        let handshake = Data([0x02]) + ClientHelloBuilder.u24(body.count) + body
        return Data([0x16, 0x03, 0x03]) + ClientHelloBuilder.u16(handshake.count) + handshake
    }

    func testTLS13ServerHello() throws {
        let id = Data(repeating: 0xBB, count: 32)
        let supportedVersions = Data([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])
        let info = try XCTUnwrap(ServerHelloInfo.parse(prefix: Self.serverHello(sessionID: id, extensions: supportedVersions)))
        XCTAssertEqual(info.sessionID, id)
        XCTAssertEqual(info.negotiatedVersion, 0x0304)
    }

    func testTLS12ServerHelloHasNoNegotiatedVersion() throws {
        let info = try XCTUnwrap(ServerHelloInfo.parse(prefix: Self.serverHello(sessionID: Data([1, 2, 3]))))
        XCTAssertEqual(info.sessionID, Data([1, 2, 3]))
        XCTAssertNil(info.negotiatedVersion)
    }

    func testTruncatedServerHello() throws {
        let full = Self.serverHello(sessionID: Data(repeating: 0xBB, count: 32),
                                    extensions: Data([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]))
        let info = try XCTUnwrap(ServerHelloInfo.parse(prefix: full.prefix(80)), "the session ID fits in 76 bytes")
        XCTAssertNil(info.negotiatedVersion)
        XCTAssertNil(ServerHelloInfo.parse(prefix: full.prefix(60)))
        XCTAssertNil(ServerHelloInfo.parse(prefix: Data("HTTP/1.1 302 Found\r\n".utf8)))
    }
}

final class PayloadSnifferTests: XCTestCase {
    func testClientFirstBytes() {
        if case .tls(let info) = PayloadSniffer.sniff(client: Fixtures.tls13ClientHello) {
            XCTAssertEqual(info.sni, "www.example.com")
        } else {
            XCTFail("expected TLS")
        }
        XCTAssertEqual(PayloadSniffer.sniff(client: Data([0x16, 0x03, 0x01, 0x00, 0x05, 0x02])), .tlsOther)
        XCTAssertEqual(PayloadSniffer.sniff(client: Data("GET /x HTTP/1.1\r\nHost: a.b\r\n\r\n".utf8)), .http(method: "GET", host: "a.b"))
        XCTAssertEqual(PayloadSniffer.sniff(client: Data("POST / HTTP/1.1\r\n".utf8)), .http(method: "POST", host: nil))
        XCTAssertEqual(PayloadSniffer.sniff(client: Data("SSH-2.0-OpenSSH_9.6\r\n".utf8)), .ssh)
        XCTAssertEqual(PayloadSniffer.sniff(client: Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])), .unknown(firstBytes: Data([1, 2, 3, 4, 5, 6, 7, 8])))
        XCTAssertEqual(PayloadSniffer.sniff(client: Data("GETX".utf8)), .unknown(firstBytes: Data("GETX".utf8)))
        XCTAssertEqual(PayloadSniffer.sniff(client: Data()), .none)
    }

    func testServerFirstBytes() {
        XCTAssertEqual(PayloadSniffer.sniff(server: Data("220 smtp.example ESMTP\r\n".utf8)), .serverFirst(.smtpOrFTP))
        XCTAssertEqual(PayloadSniffer.sniff(server: Data("* OK IMAP4rev1\r\n".utf8)), .serverFirst(.imap))
        XCTAssertEqual(PayloadSniffer.sniff(server: Data("+OK POP3\r\n".utf8)), .serverFirst(.pop3))
        XCTAssertEqual(PayloadSniffer.sniff(server: Data([0x00, 0x01])), .serverFirst(.other))
    }

    func testTags() {
        XCTAssertEqual(PayloadKind.http(method: "GET", host: nil).tag, .http)
        XCTAssertEqual(PayloadKind.serverFirst(.imap).tag, .imap)
        XCTAssertEqual(PayloadKind.unknown(firstBytes: Data()).tag, .tcp)
    }
}
