import Foundation

/// SOCKS4 / 4a CONNECT, read only far enough to name the target and refuse it (network-scanner
/// plan §2.5.4). Spoofy doesn't carry SOCKS4; the parser exists so the client gets a reply it
/// understands and the refusal says why. Carrying it later means returning `.request` here.
///
/// `VN CD DSTPORT DSTIP USERID\0`, plus `HOST\0` for 4a (DSTIP 0.0.0.x, x ≠ 0).
struct SOCKS4Parser: InboundParser {
    /// "Request rejected or failed".
    static let rejected = Data([0x00, 0x5B, 0, 0, 0, 0, 0, 0])
    /// Longest USERID or 4a host we buffer for.
    private static let maxField = 255

    private var buffer: [UInt8] = []

    mutating func feed(_ chunk: Data) -> InboundStep {
        buffer.append(contentsOf: chunk)
        guard buffer.count >= 8 else { return .needMore }
        let port = UInt16(buffer[2]) << 8 | UInt16(buffer[3])
        let ip = Array(buffer[4..<8])

        let userEnd = terminator(from: 8)
        if (userEnd ?? buffer.count) - 8 > Self.maxField { return malformed("SOCKS4 user ID too long") }
        guard let userEnd else { return .needMore }
        let target: DialTarget
        if ip[0] == 0, ip[1] == 0, ip[2] == 0, ip[3] != 0 {
            let hostEnd = terminator(from: userEnd + 1)
            if (hostEnd ?? buffer.count) - userEnd - 1 > Self.maxField { return malformed("SOCKS4a host too long") }
            guard let hostEnd else { return .needMore }
            target = DialTarget(host: String(decoding: buffer[(userEnd + 1)..<hostEnd], as: UTF8.self), port: port)
        } else {
            target = DialTarget(host: ip.map(String.init).joined(separator: "."), port: port)
        }
        return .fail(reply: Self.rejected, reason: .socks4(target: target))
    }

    private func terminator(from start: Int) -> Int? {
        guard start <= buffer.count else { return nil }
        return buffer[start...].firstIndex(of: 0)
    }

    private func malformed(_ reason: String) -> InboundStep {
        .fail(reply: Self.rejected, reason: .malformed(reason))
    }
}
