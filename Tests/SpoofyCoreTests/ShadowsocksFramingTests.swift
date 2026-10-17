import XCTest
@testable import SpoofyCore

/// `ShadowsocksAEADCodec` (plan §5.1, §6.8).
final class ShadowsocksFramingTests: XCTestCase {
    private let masterKey = ShadowsocksCrypto.masterKey(from: "password", keyLen: 32)
    private let salt = Data(0..<32)

    private func encoder(_ cipher: ShadowsocksCipher = .chacha20IetfPoly1305) -> ShadowsocksAEADCodec.Encoder {
        ShadowsocksAEADCodec.Encoder(cipher: cipher, masterKey: masterKey, salt: salt)
    }

    private func decoder(_ cipher: ShadowsocksCipher = .chacha20IetfPoly1305) -> ShadowsocksAEADCodec.Decoder {
        ShadowsocksAEADCodec.Decoder(cipher: cipher, masterKey: masterKey)
    }

    private func payload(_ count: Int) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
    }

    /// Wire size of `count` payload bytes without the salt: two tags per chunk.
    private func wireSize(_ count: Int) -> Int {
        let chunks = (count + 0x3FFE) / 0x3FFF
        return count + chunks * (2 + 2 * ShadowsocksCrypto.tagLength)
    }

    // MARK: - Round trip

    func testRoundTripAtChunkBoundaries() throws {
        for cipher in ShadowsocksCipher.allCases {
            for count in [0, 1, 0x3FFF, 0x3FFF + 1, 3 * 0x3FFF + 5] {
                var enc = encoder(cipher)
                var dec = decoder(cipher)
                let wire = try enc.seal(payload(count))
                XCTAssertEqual(wire.count, 32 + wireSize(count), "\(cipher) \(count)")
                XCTAssertEqual(try dec.feed(wire), payload(count), "\(cipher) \(count)")
            }
        }
    }

    func testOnlyTheFirstSealCarriesTheSalt() throws {
        var enc = encoder()
        let first = try enc.seal(payload(10))
        XCTAssertEqual(first.prefix(32), salt)
        XCTAssertEqual(try enc.seal(payload(10)).count, wireSize(10))
        XCTAssertEqual(try enc.seal(Data()).count, 0, "an empty seal after the salt emits nothing")
    }

    func testEmptyFirstSealIsJustTheSalt() throws {
        var enc = encoder()
        XCTAssertEqual(try enc.seal(Data()), salt)
    }

    func testFeedingByteByByteAndInRandomPiecesGivesTheSameOutput() throws {
        var enc = encoder(.aes256Gcm)
        var wire = Data()
        var expected = Data()
        for count in [1, 500, 0x3FFF + 3, 7] {
            wire += try enc.seal(payload(count))
            expected += payload(count)
        }

        var dec = decoder(.aes256Gcm)
        var out = Data()
        for byte in wire { out += try dec.feed(Data([byte])) }
        XCTAssertEqual(out, expected)

        var generator = SplitMix64(seed: 42)
        for _ in 0..<20 {
            var dec = decoder(.aes256Gcm)
            var out = Data()
            var rest = wire[...]
            while !rest.isEmpty {
                let n = Int.random(in: 1...700, using: &generator)
                out += try dec.feed(Data(rest.prefix(n)))
                rest = rest.dropFirst(n)
            }
            XCTAssertEqual(out, expected)
        }
    }

    func testEachCompleteFrameIsDeliveredAsSoonAsItArrives() throws {
        var enc = encoder()
        let wire = try enc.seal(payload(5)) + enc.seal(payload(6))
        var dec = decoder()
        let firstEnd = 32 + wireSize(5)
        XCTAssertEqual(try dec.feed(wire.prefix(firstEnd - 1)), Data())
        XCTAssertEqual(try dec.feed(wire[firstEnd - 1 ..< firstEnd + 1]), payload(5))
        XCTAssertEqual(try dec.feed(wire.dropFirst(firstEnd + 1)), payload(6))
    }

    // MARK: - Errors

    func testCorruptLengthTagFailsWithNoOutput() throws {
        var enc = encoder()
        var wire = try enc.seal(payload(20))
        wire[32 + 2 + 3] ^= 0x01   // inside the length frame's tag
        var dec = decoder()
        XCTAssertThrowsError(try dec.feed(wire)) {
            XCTAssertEqual($0 as? ShadowsocksAEADCodec.Error, .authenticationFailed)
        }
        XCTAssertThrowsError(try dec.feed(Data()), "the stream stays poisoned")
    }

    func testCorruptPayloadFails() throws {
        var enc = encoder()
        var wire = try enc.seal(payload(20))
        wire[wire.count - 1] ^= 0x80
        var dec = decoder()
        XCTAssertThrowsError(try dec.feed(wire)) {
            XCTAssertEqual($0 as? ShadowsocksAEADCodec.Error, .authenticationFailed)
        }
    }

    func testWrongKeyFails() throws {
        var enc = ShadowsocksAEADCodec.Encoder(cipher: .chacha20IetfPoly1305,
                                               masterKey: ShadowsocksCrypto.masterKey(from: "other", keyLen: 32), salt: salt)
        var dec = decoder()
        XCTAssertThrowsError(try dec.feed(enc.seal(payload(3))))
    }

    /// A peer that frames a length the spec forbids: the length frame opens, but the length is a protocol error.
    func testOutOfRangeLengthIsAProtocolError() throws {
        for length in [0, 0x3FFF + 1, 0xFFFF] {
            let subkey = ShadowsocksCrypto.deriveSubkey(masterKey: masterKey, salt: salt)
            var nonce = ShadowsocksCrypto.makeNonce()
            let frame = try ShadowsocksCrypto.aeadEncrypt(key: subkey, nonce: &nonce,
                                                          plaintext: Data([UInt8(length >> 8), UInt8(length & 0xFF)]),
                                                          cipher: .chacha20IetfPoly1305)
            var dec = decoder()
            XCTAssertThrowsError(try dec.feed(salt + frame), "\(length)") {
                XCTAssertEqual($0 as? ShadowsocksAEADCodec.Error, .invalidLength(length))
            }
        }
    }

    // MARK: - Salt (N2, N5)

    func testSaltStartsWithThePrefixAndKeepsItsLength() throws {
        let prefix = Data([0x16, 0x03, 0x01, 0x00, 0xA8])
        for cipher in ShadowsocksCipher.allCases {
            let salt = try ShadowsocksAEADCodec.makeSalt(cipher: cipher, prefix: prefix)
            XCTAssertEqual(salt.count, ShadowsocksCrypto.saltLength(for: cipher))
            XCTAssertEqual(salt.prefix(5), prefix)
        }
        let full = Data(repeating: 0x41, count: 32)
        XCTAssertEqual(try ShadowsocksAEADCodec.makeSalt(cipher: .aes256Gcm, prefix: full), full)
        XCTAssertThrowsError(try ShadowsocksAEADCodec.makeSalt(cipher: .aes256Gcm, prefix: full + Data([0]))) {
            XCTAssertEqual($0 as? ShadowsocksAEADCodec.Error, .prefixTooLong(33))
        }
    }

    func testSaltsAreRandom() throws {
        let salts = try (0..<50).map { _ in try ShadowsocksAEADCodec.makeSalt(cipher: .chacha20IetfPoly1305, prefix: nil) }
        XCTAssertEqual(Set(salts).count, 50)
        XCTAssertFalse(salts.contains(Data(count: 32)))
    }
}

/// Deterministic generator for reproducible "random" splits.
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
}
