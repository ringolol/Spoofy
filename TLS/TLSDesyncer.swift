import Foundation
import Network

/// Splits a TLS ClientHello into multiple Data segments based on the configured split mode.
struct TLSDesyncer {

    /// Split the raw ClientHello data based on the given mode and settings.
    /// When `tlsRecordFragmentation` is true, the handshake is first split across
    /// multiple TLS records before the chosen split mode is applied to each record.
    static func split(raw: Data, mode: SplitMode, chunkSize: Int, sniOffset: (start: Int, end: Int)?, tlsRecordFragmentation: Bool) -> [Data] {
        // Step 1: Optionally wrap the handshake in multiple TLS records.
        let inputs: [Data]
        if tlsRecordFragmentation, mode != .none {
            inputs = splitTLSRecords(raw: raw, size: max(chunkSize, 1))
        } else {
            inputs = [raw]
        }

        // Step 2: Apply the chosen split mode to each piece.
        switch mode {
        case .sni:
            if let offset = sniOffset {
                return splitSNI(raw: raw, start: offset.start, end: offset.end)
            }
            return [raw]

        case .random:
            let mask = genPatternMask()
            return inputs.flatMap { splitMask(raw: $0, mask: mask) }

        case .chunk:
            let size = max(chunkSize, 1)
            return inputs.flatMap { splitChunks(raw: $0, size: size) }

        case .firstByte:
            return inputs.flatMap { splitFirstByte(raw: $0) }

        case .none:
            return [raw]
        }
    }

    // MARK: - Split Strategies

    /// Split into fixed-size chunks.  No segment cap — a typical ClientHello is
    /// ~1500-2000 bytes, and the Go implementation sends every byte individually.
    static func splitChunks(raw: Data, size: Int) -> [Data] {
        guard !raw.isEmpty, size > 0 else { return [raw] }

        var chunks: [Data] = []
        var offset = 0

        while offset < raw.count {
            let end = min(offset + size, raw.count)
            chunks.append(raw.subdata(in: offset..<end))
            offset = end
        }

        return chunks
    }

    /// Split first byte from the rest.
    static func splitFirstByte(raw: Data) -> [Data] {
        guard raw.count >= 2 else { return [raw] }
        return [raw.prefix(1), raw.dropFirst()]
    }

    /// Splits the TLS ClientHello so that each byte of the SNI hostname is a
    /// separate segment, matching the Go SpoofDPI behavior:
    ///   [before_sni] [s] [i] [t] [e] [.] [c] [o] [m] [after_sni]
    /// This forces each hostname character into its own TCP segment, preventing
    /// DPI from reconstructing the full hostname within a single packet.
    static func splitSNI(raw: Data, start: Int, end: Int) -> [Data] {
        guard !raw.isEmpty,
              start < end,
              start >= 0,
              end <= raw.count else {
            return [raw]
        }

        var segments: [Data] = []

        // Everything before the SNI hostname
        if start > 0 {
            segments.append(raw.subdata(in: 0..<start))
        }

        // Each byte of the SNI hostname as a separate segment
        for i in start..<end {
            segments.append(raw.subdata(in: i..<(i + 1)))
        }

        // Everything after the SNI hostname
        if end < raw.count {
            segments.append(raw.subdata(in: end..<raw.count))
        }

        return segments
    }

    /// Split the handshake payload across multiple TLS records.
    /// Each chunk gets its own 5-byte TLS record header (type=0x16, version matching
    /// original, length=chunkSize). The DPI must reassemble across TLS records to
    /// reconstruct the handshake message, which is much harder than TCP reassembly.
    static func splitTLSRecords(raw: Data, size: Int) -> [Data] {
        guard raw.count > 5 else { return [raw] }

        let recordType = raw[0]       // 0x16 = handshake
        let versionMajor = raw[1]     // e.g. 0x03
        let versionMinor = raw[2]     // e.g. 0x01
        let handshake = raw.subdata(in: 5..<raw.count)

        var records: [Data] = []
        var offset = 0
        while offset < handshake.count {
            let end = min(offset + size, handshake.count)
            let chunkLen = end - offset

            var record = Data(capacity: 5 + chunkLen)
            record.append(recordType)
            record.append(versionMajor)
            record.append(versionMinor)
            record.append(UInt8(chunkLen >> 8))
            record.append(UInt8(chunkLen & 0xFF))
            record.append(handshake.subdata(in: offset..<end))

            records.append(record)
            offset = end
        }
        return records
    }

    /// Split at positions determined by a 64-bit mask, rotating through the mask cyclically.
    static func splitMask(raw: Data, mask: UInt64) -> [Data] {
        guard !raw.isEmpty else { return [raw] }

        var segments: [Data] = []
        var start = 0
        var curBit: UInt64 = 1

        for i in 0..<raw.count {
            if mask & curBit == curBit {
                if i > start {
                    segments.append(raw.subdata(in: start..<i))
                }
                segments.append(raw.subdata(in: i..<(i + 1)))
                start = i + 1
            }
            // Rotate left by 1 (wrapping)
            curBit = (curBit << 1) | (curBit >> 63)
        }

        if raw.count > start {
            segments.append(raw.subdata(in: start..<raw.count))
        }

        return segments
    }
}
