import Foundation

/// Where the scanner attaches to the core (network-scanner plan §1). Optional everywhere: with no
/// observer the proxy behaves exactly as before.
protocol ConnectionObserver: AnyObject {
    /// Called on the session queue once a request is routed (not for rejects). Returns nil to skip
    /// tracing this connection. The trace is then touched only on `queue`.
    func begin(_ start: TraceStart, queue: DispatchQueue) -> ConnectionTrace?
    /// A request the proxy refused before routing it anywhere (§2.5.4). Any queue.
    func refused(_ record: RefusalRecord)
}

/// What a session knows when it routes a request (§2.1, phase `created`).
struct TraceStart: Sendable {
    /// The session id.
    let id: UInt64
    /// Wall clock, for display only.
    let startedAt: Date
    /// `DispatchTime` uptime; every other timestamp in the trace is on this clock.
    let startedAtNanos: UInt64
    let inbound: InboundProtocol
    /// Lowercased `DialTarget.host`.
    let host: String
    let port: UInt16
    let isIPLiteral: Bool
    let profileID: UUID
    let profileName: String
    let isDefaultProfile: Bool
    let outbound: TraceOutbound
}

/// `OutboundKind` without the Outline password or prefix, for keeping and showing.
enum TraceOutbound: Equatable, Sendable {
    case direct
    case desync(DesyncParameters)
    case shadowsocks(host: String, port: UInt16)

    /// Nil for `.reject`, which is never traced.
    init?(_ kind: OutboundKind) {
        switch kind {
        case .direct: self = .direct
        case .desync(let parameters): self = .desync(parameters)
        case .shadowsocks(let config): self = .shadowsocks(host: config.host, port: config.port)
        case .reject: return nil
        }
    }
}

struct RefusalRecord: Sendable {
    let at: Date
    /// Nil for over-capacity: nothing was read yet.
    let inbound: InboundProtocol?
    let reason: RefusalReason
    /// When the request got far enough to name one.
    let target: DialTarget?
}

enum RefusalReason: Equatable, Sendable {
    case handshake(InboundFailure)
    /// The Router's `.reject` (a VPN route without a server).
    case routeRejected(profileName: String)
    /// `ProxyServer` already has `maxConcurrentConnections` sessions.
    case overCapacity

    /// The target, for the failures that carry one.
    var target: DialTarget? {
        if case .handshake(.socks4(let target)) = self { return target }
        return nil
    }
}
