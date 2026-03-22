import Foundation

/// Generates a pseudo-random 64-bit mask using Xorshift, ported from Go's genPatternMask.
/// Ensures at least one bit is set per 8-bit block for reliable splitting.
func genPatternMask() -> UInt64 {
    var seed = UInt(arc4random()) | (UInt(arc4random()) << 32)

    var ret: UInt64 = 0

    // Block 0 [0-7 bits]: fixed pattern with LSB=1
    ret |= 0b10101001

    // Block 1 [8-15 bits]
    seed ^= (seed >> 13)
    ret |= UInt64(rotateLeft8(0b10000000, by: Int(seed))) << 8
    seed ^= (seed << 11)
    ret |= UInt64(rotateLeft8(0b10000000, by: -(Int(seed % 7) - 1))) << 8

    // Block 2 [16-23 bits]
    seed ^= (seed >> 17)
    ret |= UInt64(rotateLeft8(0b00000001, by: Int(seed))) << 16

    // Block 3 [24-31 bits]
    seed ^= (seed << 5)
    ret |= UInt64(rotateLeft8(0b00000001, by: Int(seed))) << 24

    // Block 4 [32-39 bits]
    seed ^= (seed >> 12)
    ret |= UInt64(rotateLeft8(0b00000001, by: Int(seed % 2))) << 32
    ret |= UInt64(rotateLeft8(0b00000001, by: Int(seed % 3) + 2)) << 32
    ret |= UInt64(rotateLeft8(0b00000001, by: Int(seed % 3) + 5)) << 32

    // Block 5 [40-47 bits]
    seed ^= (seed << 25)
    ret |= UInt64(rotateLeft8(0b00000001, by: Int(seed))) << 40

    // Block 6 [48-55 bits]
    seed ^= (seed >> 27)
    ret |= UInt64(rotateLeft8(0b00000001, by: Int(seed))) << 48

    // Block 7 [56-63 bits]
    seed ^= (seed << 13)
    ret |= UInt64(rotateLeft8(0b00000001, by: Int(seed))) << 56

    return ret
}

private func rotateLeft8(_ value: UInt8, by amount: Int) -> UInt8 {
    let shift = ((amount % 8) + 8) % 8
    return (value << shift) | (value >> (8 - shift))
}
