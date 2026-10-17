import XCTest
@testable import SpoofyCore

final class TLSDesyncerTests: XCTestCase {
    private let hellos = [Fixtures.tls13ClientHello, Fixtures.tls12ClientHello]

    private func sniOffset(_ raw: Data) -> (start: Int, end: Int)? {
        TLSMessage.parse(from: raw)?.extractSNIOffset()
    }

    private func split(_ raw: Data, _ mode: SplitMode, chunk: Int = 8, fragment: Bool = false) -> [Data] {
        TLSDesyncer.split(raw: raw, mode: mode, chunkSize: chunk, sniOffset: sniOffset(raw), tlsRecordFragmentation: fragment)
    }

    /// Parses a byte stream as consecutive TLS records; returns their headers and joined payloads.
    private func records(_ stream: Data) throws -> (headers: [Data], payload: Data) {
        var headers: [Data] = []
        var payload = Data()
        var rest = stream
        while !rest.isEmpty {
            let message = try XCTUnwrap(TLSMessage.parse(from: Data(rest)), "malformed record stream")
            headers.append(message.raw.prefix(5))
            payload += message.raw.dropFirst(5)
            rest = rest.dropFirst(message.raw.count)
        }
        return (headers, payload)
    }

    /// Byte offsets (into the joined stream) where one segment ends and the next begins.
    private func boundaries(_ segments: [Data]) -> Set<Int> {
        var result = Set<Int>()
        var position = 0
        for segment in segments.dropLast() {
            position += segment.count
            result.insert(position)
        }
        return result
    }

    // MARK: - Invariants

    func testSegmentsJoinToInputForEveryMode() {
        for raw in hellos {
            for mode in SplitMode.allCases {
                let segments = split(raw, mode)
                XCTAssertEqual(Data(segments.joined()), raw, "mode \(mode)")
                XCTAssertFalse(segments.contains { $0.isEmpty }, "empty segment in mode \(mode)")
            }
        }
    }

    func testRecordFragmentationPreservesHandshakeBytes() throws {
        for raw in hellos {
            for mode in SplitMode.allCases {
                for chunk in [1, 7, 100, 5000] {
                    let stream = Data(split(raw, mode, chunk: chunk, fragment: true).joined())
                    let parsed = try records(stream)
                    XCTAssertEqual(parsed.payload, raw.dropFirst(5), "mode \(mode) chunk \(chunk)")
                    for header in parsed.headers {
                        XCTAssertEqual(header.prefix(3), raw.prefix(3), "record type/version must be copied")
                    }
                }
            }
        }
    }

    // MARK: - Modes

    func testNoneSendsOneSegment() {
        XCTAssertEqual(split(Fixtures.tls12ClientHello, .none, fragment: true), [Fixtures.tls12ClientHello])
    }

    func testFirstByteSplitsOffOneByte() {
        let segments = split(Fixtures.tls12ClientHello, .firstByte)
        XCTAssertEqual(segments.map(\.count), [1, 229])
    }

    func testFirstByteOnTinyInputIsUnchanged() {
        XCTAssertEqual(TLSDesyncer.splitFirstByte(raw: Data([0x16])), [Data([0x16])])
    }

    func testChunkModeBoundsEverySegment() {
        for chunk in [1, 3, 64] {
            for fragment in [false, true] {
                let segments = split(Fixtures.tls13ClientHello, .chunk, chunk: chunk, fragment: fragment)
                XCTAssertTrue(segments.allSatisfy { $0.count <= chunk }, "chunk \(chunk) fragment \(fragment)")
            }
        }
    }

    func testChunkSizeZeroIsTreatedAsOne() {
        let raw = Data([1, 2, 3])
        let segments = TLSDesyncer.split(raw: raw, mode: .chunk, chunkSize: 0, sniOffset: nil, tlsRecordFragmentation: false)
        XCTAssertEqual(segments, [Data([1]), Data([2]), Data([3])])
    }

    func testSNIModeSplitsEveryHostnameByte() throws {
        for raw in hellos {
            let offset = try XCTUnwrap(sniOffset(raw))
            let cuts = boundaries(split(raw, .sni))
            for position in offset.start...offset.end {
                XCTAssertTrue(cuts.contains(position), "no boundary at \(position)")
            }
        }
    }

    func testSNIModeWithoutSNIIsUnchanged() {
        let raw = ClientHelloBuilder.make(sni: nil)
        XCTAssertEqual(split(raw, .sni), [raw])
    }

    func testSplitSNIIgnoresOutOfRangeOffsets() {
        let raw = Data([1, 2, 3, 4])
        XCTAssertEqual(TLSDesyncer.splitSNI(raw: raw, start: 2, end: 9), [raw])
        XCTAssertEqual(TLSDesyncer.splitSNI(raw: raw, start: 3, end: 3), [raw])
        XCTAssertEqual(TLSDesyncer.splitSNI(raw: raw, start: -1, end: 2), [raw])
    }

    // U8: SNI mode used to split `raw` and drop the fragmented records.
    func testSNIModeHonoursRecordFragmentation() throws {
        let stream = Data(split(Fixtures.tls12ClientHello, .sni, chunk: 64, fragment: true).joined())
        XCTAssertGreaterThan(try records(stream).headers.count, 1)
    }

    /// Fragmented and SNI-split: the segments are exactly the fragmented records, with every
    /// hostname byte in a segment of its own, whichever records the hostname straddles.
    func testSNIModeWithFragmentationIsolatesEveryHostnameByte() throws {
        for raw in hellos {
            let sni = try XCTUnwrap(sniOffset(raw))
            // Chunk sizes that put record boundaries before, inside and after the hostname.
            for chunk in [1, 3, 7, sni.start - 3, 64, 5000] {
                let segments = split(raw, .sni, chunk: chunk, fragment: true)
                let fragmented = Data(TLSDesyncer.splitTLSRecords(raw: raw, size: chunk).joined())
                XCTAssertEqual(Data(segments.joined()), fragmented, "chunk \(chunk)")
                XCTAssertFalse(segments.contains { $0.isEmpty }, "chunk \(chunk)")
                var cuts = boundaries(segments)
                cuts.formUnion([0, fragmented.count])
                for i in sni.start..<sni.end {
                    // Where original byte i lands in the fragmented stream: each earlier record adds a header.
                    let payloadIndex = i - 5
                    let position = (payloadIndex / chunk) * (chunk + 5) + 5 + payloadIndex % chunk
                    XCTAssertEqual(fragmented[position], raw[i])
                    XCTAssertTrue(cuts.contains(position) && cuts.contains(position + 1),
                                  "chunk \(chunk): hostname byte \(i) shares a segment")
                }
            }
        }
    }

    // MARK: - Mask splitting

    func testSplitMaskCutsAroundSetBits() {
        let raw = Data([0, 1, 2, 3, 4])
        XCTAssertEqual(TLSDesyncer.splitMask(raw: raw, mask: 0b100),
                       [Data([0, 1]), Data([2]), Data([3, 4])])
        XCTAssertEqual(TLSDesyncer.splitMask(raw: raw, mask: 0b101),
                       [Data([0]), Data([1]), Data([2]), Data([3, 4])])
        XCTAssertEqual(TLSDesyncer.splitMask(raw: raw, mask: 0), [raw])
    }

    func testSplitMaskWrapsEvery64Bytes() {
        let raw = Data((0..<130).map { UInt8($0) })
        let cuts = boundaries(TLSDesyncer.splitMask(raw: raw, mask: 1))
        // Bit 0 marks bytes 0, 64 and 128 as single-byte segments.
        XCTAssertEqual(cuts, [1, 64, 65, 128, 129])
    }

    // MARK: - Record fragmentation

    func testSplitTLSRecordsHeaderLengths() throws {
        let raw = Fixtures.tls12ClientHello  // 225-byte payload
        let recordsOut = TLSDesyncer.splitTLSRecords(raw: raw, size: 100)
        XCTAssertEqual(recordsOut.map(\.count), [105, 105, 30])
        for record in recordsOut {
            let length = Int(record[3]) << 8 | Int(record[4])
            XCTAssertEqual(length, record.count - 5)
        }
    }

    func testSplitTLSRecordsOnTinyInputIsUnchanged() {
        let raw = Data([0x16, 0x03, 0x01, 0x00, 0x00])
        XCTAssertEqual(TLSDesyncer.splitTLSRecords(raw: raw, size: 1), [raw])
    }
}
