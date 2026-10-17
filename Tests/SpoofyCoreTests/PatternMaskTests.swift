import XCTest
@testable import SpoofyCore

final class PatternMaskTests: XCTestCase {
    // Expected values come from SpoofDPI's Go genPatternMask (internal/desync/tls.go)
    // with rand.Uint() replaced by the given seed.
    func testMatchesGoReference() {
        let cases: [(seed: UInt64, mask: UInt64)] = [
            (0x0000_0000_0000_0000, 0x0101_0125_0101_81a9),
            (0x0000_0000_0000_0001, 0x2020_024a_0202_09a9),
            (0x0123_4567_89ab_cdef, 0x0404_804a_0101_21a9),
            (0x8000_0000_0000_0000, 0x0101_0149_0101_81a9),
            (0xffff_ffff_ffff_ffff, 0x0101_0125_0101_a0a9),
            (0xdead_beef_cafe_babe, 0x0202_1049_4040_14a9),
        ]
        for (seed, mask) in cases {
            XCTAssertEqual(genPatternMask(seed: seed), mask,
                           "seed 0x\(String(seed, radix: 16))")
        }
    }

    // C1 regression: Int(seed) used to trap whenever bit 63 of the seed was set.
    func testHighBitSeedsDoNotTrap() {
        for seed: UInt64 in [1 << 63, .max, .max - 1, 0x8000_0000_dead_beef] {
            _ = genPatternMask(seed: seed)
        }
    }

    func testEveryByteHasABitSet() {
        for _ in 0..<10_000 {
            let mask = genPatternMask()
            XCTAssertEqual(mask & 0xff, 0b1010_1001)
            for block in 0..<8 {
                XCTAssertNotEqual((mask >> (block * 8)) & 0xff, 0, "block \(block) of 0x\(String(mask, radix: 16))")
            }
        }
    }
}
