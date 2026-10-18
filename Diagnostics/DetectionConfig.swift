import Foundation

/// Thresholds for the stall check and the classifier (network-scanner plan §4.1). Tuned in the
/// field test (step 5k). An instance rather than constants so loopback tests can shorten the
/// waits.
struct DetectionConfig: Sendable {
    static let standard = DetectionConfig()

    /// An event earlier than this fraction of the RTT after the payload can't be from the server.
    var earlyRatio = 0.5
    /// Below 10 ms an injected reply can't be told from a real one.
    var minRTTForTiming = 0.010
    /// Seconds of silence after a ClientHello before it counts as a blackhole.
    var helloBlackholeMin = 3.0
    /// Seconds of silence, while waiting on the server, before the trace records a stall.
    var stallSeconds = 8.0
    /// Bytes received before a stall that look like a freeze (kind H).
    var freezeWindow = 12_000...40_000
    /// A reset with less than this downloaded is reported (weakly) as a mid-stream reset.
    var midStreamResetMax = 64_000
    var blockPageStatus: Set<Int> = [301, 302, 303, 307, 403, 451]
    /// Seed from community lists; verify before shipping.
    var blockPageHosts: Set<String> = []
    /// Phase 2 probe D6; seed from community lists.
    var whitelistSNIs: [String] = []
}
