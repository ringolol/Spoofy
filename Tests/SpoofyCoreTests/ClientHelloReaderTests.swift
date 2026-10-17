import XCTest
@testable import SpoofyCore

final class ClientHelloReaderTests: XCTestCase {
    private let hello = Fixtures.tls13ClientHello

    private func feedAll(_ chunks: [Data]) -> (outputs: [ClientHelloReader.Output], reader: ClientHelloReader) {
        var reader = ClientHelloReader()
        var outputs: [ClientHelloReader.Output] = []
        for chunk in chunks {
            outputs.append(reader.feed(chunk))
            if reader.state == .done { break }
        }
        return (outputs, reader)
    }

    private func clientHello(_ output: ClientHelloReader.Output?,
                             file: StaticString = #filePath, line: UInt = #line) -> (record: Data, sni: (start: Int, end: Int)?)? {
        guard case .clientHello(let record, let sni) = output else {
            XCTFail("expected .clientHello, got \(String(describing: output))", file: file, line: line)
            return nil
        }
        return (record, sni)
    }

    private func passthrough(_ output: ClientHelloReader.Output?,
                             file: StaticString = #filePath, line: UInt = #line) -> Data? {
        guard case .passthrough(let bytes) = output else {
            XCTFail("expected .passthrough, got \(String(describing: output))", file: file, line: line)
            return nil
        }
        return bytes
    }

    func testWholeHelloInOneChunk() throws {
        let (outputs, reader) = feedAll([hello])
        let got = try XCTUnwrap(clientHello(outputs.last))
        XCTAssertEqual(got.record, hello)
        let expected = try XCTUnwrap(TLSMessage.parse(from: hello)?.extractSNIOffset())
        XCTAssertEqual(got.sni?.start, expected.start)
        XCTAssertEqual(got.sni?.end, expected.end)
        XCTAssertEqual(reader.leftover, Data())
        XCTAssertEqual(reader.state, .done)
    }

    func testHelloOneByteAtATime() throws {
        let (outputs, _) = feedAll(hello.map { Data([$0]) })
        XCTAssertEqual(outputs.count, hello.count)
        for output in outputs.dropLast() {
            guard case .needMore = output else { return XCTFail("expected .needMore before the record is complete") }
        }
        XCTAssertEqual(try XCTUnwrap(clientHello(outputs.last)).record, hello)
    }

    func testStateAfterHeader() {
        var reader = ClientHelloReader()
        _ = reader.feed(hello.prefix(5))
        XCTAssertEqual(reader.state, .awaitingBody(recordLength: hello.count - 5))
    }

    func testBytesAfterTheRecordAreLeftover() throws {
        let tail = Data("early data".utf8)
        let (outputs, reader) = feedAll([hello.prefix(100), hello.dropFirst(100) + tail])
        XCTAssertEqual(try XCTUnwrap(clientHello(outputs.last)).record, hello)
        XCTAssertEqual(reader.leftover, tail)
    }

    // U7 / N15: decided on the first byte, without waiting for a 5-byte header.
    func testNonTLSFirstBytePassesThroughAtOnce() {
        XCTAssertEqual(passthrough(feedAll([Data("p".utf8)]).outputs.last), Data("p".utf8))
        XCTAssertEqual(passthrough(feedAll([Data("SSH-2.0-x\r\n".utf8)]).outputs.last), Data("SSH-2.0-x\r\n".utf8))
    }

    func testShortHandshakePrefixWaits() {
        let (outputs, reader) = feedAll([Data([0x16, 0x03])])
        guard case .needMore = outputs.last else { return XCTFail("expected .needMore") }
        XCTAssertEqual(reader.bufferedCount, 2)
    }

    func testBadVersionPassesThrough() {
        let bytes = Data([0x16, 0x07, 0x01, 0x00, 0x10])
        XCTAssertEqual(passthrough(feedAll([bytes]).outputs.last), bytes)
    }

    func testZeroAndOversizedLengthsPassThrough() {
        for length in [0, ClientHelloReader.maxRecord + 1, 0xFFFF] {
            let bytes = Data([0x16, 0x03, 0x01, UInt8(length >> 8), UInt8(length & 0xFF)])
            XCTAssertEqual(passthrough(feedAll([bytes]).outputs.last), bytes, "length \(length)")
        }
    }

    func testHandshakeThatIsNotAClientHelloPassesThroughWhole() {
        var other = hello
        other[5] = 0x02 // ServerHello
        let tail = Data("x".utf8)
        XCTAssertEqual(passthrough(feedAll([other + tail]).outputs.last), other + tail)
    }

    func testHelloWithoutSNIHasNoOffset() throws {
        let raw = ClientHelloBuilder.make(sni: nil)
        let got = try XCTUnwrap(clientHello(feedAll([raw]).outputs.last))
        XCTAssertNil(got.sni)
    }

    func testEOFForwardsWhatArrived() {
        var reader = ClientHelloReader()
        _ = reader.feed(hello.prefix(20))
        XCTAssertEqual(passthrough(reader.finishOnEOF()), hello.prefix(20))
        XCTAssertEqual(reader.state, .done)
    }
}
