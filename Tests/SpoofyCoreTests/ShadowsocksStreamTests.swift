import Network
import XCTest
@testable import SpoofyCore

/// `ShadowsocksStream` over a `FakeConnection` standing in for the Outline server.
final class ShadowsocksStreamTests: XCTestCase {
    private let queue = DispatchQueue(label: "ShadowsocksStreamTests")
    private let masterKey = ShadowsocksCrypto.masterKey(from: "pw", keyLen: 32)
    private let header = ShadowsocksAEADCodec.addressHeader(host: "example.com", port: 443)!
    private var server: FakeConnection!

    override func setUp() {
        super.setUp()
        server = FakeConnection(queue: queue)
    }

    private func makeStream(clientDataWait: TimeInterval = 10) -> ShadowsocksStream {
        let salt = try! ShadowsocksAEADCodec.makeSalt(cipher: .chacha20IetfPoly1305, prefix: Data([0x16, 0x03]))
        return queue.sync {
            ShadowsocksStream(underlying: server, cipher: .chacha20IetfPoly1305, masterKey: masterKey, salt: salt,
                              addressHeader: header, queue: queue, clientDataWait: clientDataWait)
        }
    }

    /// What the server decrypts from everything the stream sent so far.
    private func serverView() throws -> Data {
        var decoder = ShadowsocksAEADCodec.Decoder(cipher: .chacha20IetfPoly1305, masterKey: masterKey)
        return try decoder.feed(server.sent.reduce(Data(), +))
    }

    private func send(_ stream: ShadowsocksStream, _ text: String) {
        let done = expectation(description: "sent")
        queue.async {
            stream.send(content: Data(text.utf8), contentContext: .defaultMessage, isComplete: false,
                        completion: .contentProcessed { error in
                XCTAssertNil(error)
                done.fulfill()
            })
        }
        wait(for: [done], timeout: 2)
    }

    private func receive(_ stream: ShadowsocksStream, max: Int = 65536) -> (data: Data?, isComplete: Bool, error: NWError?) {
        let done = expectation(description: "received")
        let result = LockedBox<(Data?, Bool, NWError?)>((nil, false, nil))
        queue.async {
            stream.receive(minimumIncompleteLength: 1, maximumLength: max) { data, _, isComplete, error in
                result.value = (data, isComplete, error)
                done.fulfill()
            }
        }
        wait(for: [done], timeout: 2)
        return result.value
    }

    /// Server → client bytes, as the Outline server would frame them.
    private func serverWire(_ chunks: [String]) throws -> [Data] {
        var encoder = ShadowsocksAEADCodec.Encoder(
            cipher: .chacha20IetfPoly1305, masterKey: masterKey,
            salt: try ShadowsocksAEADCodec.makeSalt(cipher: .chacha20IetfPoly1305, prefix: nil))
        return try chunks.map { try encoder.seal(Data($0.utf8)) }
    }

    // MARK: - Send

    func testFirstClientDataCarriesTheHeader() throws {
        let stream = makeStream()
        send(stream, "hello")
        XCTAssertEqual(server.sent.count, 1, "salt, header and data in one write")
        XCTAssertEqual(server.sent[0].prefix(2), Data([0x16, 0x03]), "the salt starts with the prefix")
        XCTAssertEqual(try serverView(), header + Data("hello".utf8))

        send(stream, "again")
        XCTAssertEqual(try serverView(), header + Data("helloagain".utf8))
    }

    /// N4: a server-first protocol gets the header after `clientDataWait`, without client data.
    func testHeaderGoesAloneWhenTheClientIsSilent() throws {
        let stream = makeStream(clientDataWait: 0.02)
        XCTAssertTrue(eventually { self.server.sent.count == 1 })
        XCTAssertEqual(try serverView(), header)

        send(stream, "late")
        XCTAssertEqual(server.sent.count, 2)
        XCTAssertEqual(try serverView(), header + Data("late".utf8))
    }

    func testHeaderTimerIsCancelledByTheFirstSend() {
        let stream = makeStream(clientDataWait: 0.05)
        send(stream, "x")
        usleep(150_000)
        XCTAssertEqual(server.sent.count, 1)
    }

    func testCancelStopsTheHeaderTimer() {
        let stream = makeStream(clientDataWait: 0.05)
        queue.sync { stream.cancel() }
        usleep(150_000)
        XCTAssertEqual(server.sent.count, 0)
        XCTAssertTrue(server.cancelled)
    }

    // MARK: - Receive

    func testReceiveDecryptsAcrossReads() throws {
        let stream = makeStream()
        let wire = try serverWire(["hello ", "world"]).reduce(Data(), +)
        // Split mid-frame: the first read has no complete payload, so the stream reads again.
        server.push(.data(wire.prefix(40)))
        server.push(.data(wire.dropFirst(40)))
        var out = Data()
        while out.count < 11 {
            let (data, _, error) = receive(stream)
            XCTAssertNil(error)
            out += try XCTUnwrap(data)
        }
        XCTAssertEqual(out, Data("hello world".utf8))
    }

    func testReceiveHonoursMaximumLength() throws {
        let stream = makeStream()
        server.push(.data(try serverWire(["abcdefgh"])[0]))
        XCTAssertEqual(receive(stream, max: 3).data, Data("abc".utf8))
        XCTAssertEqual(receive(stream, max: 3).data, Data("def".utf8))
        XCTAssertEqual(receive(stream, max: 3).data, Data("gh".utf8))
    }

    func testEOFAfterTheLastFrame() throws {
        let stream = makeStream()
        server.push(.data(try serverWire(["bye"])[0]))
        server.push(.eof)
        XCTAssertEqual(receive(stream).data, Data("bye".utf8))
        let end = receive(stream)
        XCTAssertNil(end.data)
        XCTAssertTrue(end.isComplete)
        XCTAssertNil(end.error)
    }

    func testTamperedInputFailsAndCancels() throws {
        let stream = makeStream()
        var wire = try serverWire(["secret"])[0]
        wire[wire.count - 1] ^= 0x01
        server.push(.data(wire))
        let result = receive(stream)
        XCTAssertNil(result.data)
        XCTAssertEqual(result.error, .posix(.EIO))
        XCTAssertTrue(server.cancelled)
    }

    // MARK: - Key (N3)

    /// A 44-character password is valid base64 of 32 bytes; it is still a password, not a key.
    func testPasswordThatLooksLikeABase64KeyGoesThroughEVPBytesToKey() {
        let password = Data(repeating: 0xAB, count: 32).base64EncodedString()
        XCTAssertEqual(password.count, 44)
        let config = OutlineServerConfig(host: "h", port: 1, password: password, cipher: .aes256Gcm, prefix: nil)
        XCTAssertEqual(ShadowsocksStream.masterKey(for: config), ShadowsocksCrypto.masterKey(from: password, keyLen: 32))
        XCTAssertNotEqual(ShadowsocksStream.masterKey(for: config), Data(repeating: 0xAB, count: 32))
    }
}
