import Foundation

/// Thresholds for the stall check and the classifier (network-scanner plan §4.1). Tuned in the
/// field test (step 5k).
enum DetectionConfig {
    /// An event earlier than this fraction of the RTT after the payload can't be from the server.
    static let earlyRatio = 0.5
    /// Below 10 ms an injected reply can't be told from a real one.
    static let minRTTForTiming = 0.010
    /// Seconds of silence after a ClientHello before it counts as a blackhole.
    static let helloBlackholeMin = 3.0
    /// Seconds of silence, while waiting on the server, before the trace records a stall.
    static let stallSeconds = 8.0
    /// Bytes received before a stall that look like a freeze (kind H).
    static let freezeWindow = 12_000...40_000
    static let blockPageStatus: Set<Int> = [301, 302, 303, 307, 403, 451]
    /// Seed from community lists; verify before shipping.
    static let blockPageHosts: [String] = []
    /// Phase 2 probe D6; seed from community lists.
    static let whitelistSNIs: [String] = []
}
