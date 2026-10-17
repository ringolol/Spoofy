import Foundation

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    /// Test-only: traps on malformed input.
    init(hex: String) {
        precondition(hex.count % 2 == 0, "odd-length hex")
        var bytes: [UInt8] = []
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}
