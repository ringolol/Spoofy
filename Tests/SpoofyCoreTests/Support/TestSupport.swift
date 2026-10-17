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

/// Polls `condition` every 10 ms until it holds or the deadline passes; returns its final value.
func eventually(timeout: TimeInterval = 5, _ condition: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while !condition() && Date() < deadline {
        usleep(10_000)
    }
    return condition()
}
