import Foundation
import Network

/// The connection's own view of its transport (network-scanner plan §2.3), behind a protocol so
/// the trace can be tested without a socket.
protocol TransportReports: AnyObject {
    /// `completion` runs once on `queue`; nil when the connection has no report.
    func establishment(queue: DispatchQueue, completion: @escaping (EstablishmentInfo?) -> Void)
    /// Starts counting from now; `collect` ends the period.
    func startTransfer() -> PendingTransfer
}

protocol PendingTransfer {
    /// `completion` runs on `queue`, possibly never if the connection is already gone.
    func collect(queue: DispatchQueue, completion: @escaping (TransferInfo) -> Void)
}

struct EstablishmentInfo: Equatable, Sendable {
    enum DNSSource: Equatable, Sendable { case query, cache, expiredCache }

    /// The TCP handshake's RTT.
    var tcpRTT: TimeInterval?
    /// The system resolver's lookup, when the connection resolved a name itself (DoH off or empty).
    var systemDNSDuration: TimeInterval?
    var systemDNSSource: DNSSource?
    /// The address the connection used.
    var resolvedIP: String?
}

struct TransferInfo: Equatable, Sendable {
    var retransmittedBytes: UInt64?
    var minimumRTT: TimeInterval?
    var smoothedRTT: TimeInterval?

    /// Folds in a later period: retransmits add up, the minimum RTT is the smaller, the smoothed
    /// RTT is the latest. A zero RTT means "not measured".
    mutating func add(_ other: TransferInfo) {
        if let more = other.retransmittedBytes { retransmittedBytes = (retransmittedBytes ?? 0) + more }
        if let rtt = other.minimumRTT, rtt > 0 { minimumRTT = min(minimumRTT ?? rtt, rtt) }
        if let rtt = other.smoothedRTT, rtt > 0 { smoothedRTT = rtt }
    }
}

/// `TransportReports` for a real connection. Holds it weakly: the session owns it.
final class NWTransportReports: TransportReports {
    private weak var connection: NWConnection?

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    func establishment(queue: DispatchQueue, completion: @escaping (EstablishmentInfo?) -> Void) {
        guard let connection else { return queue.async { completion(nil) } }
        let fallbackIP = Self.host(of: connection.currentPath?.remoteEndpoint)
        connection.requestEstablishmentReport(queue: queue) { report in
            guard let report else { return completion(nil) }
            var info = EstablishmentInfo()
            info.tcpRTT = report.handshakes.first { $0.definition == NWProtocolTCP.definition }?.handshakeRTT
            if let resolution = report.resolutions.last {
                info.systemDNSDuration = resolution.duration
                switch resolution.source {
                case .query: info.systemDNSSource = .query
                case .cache: info.systemDNSSource = .cache
                case .expiredCache: info.systemDNSSource = .expiredCache
                @unknown default: break
                }
            }
            info.resolvedIP = Self.host(of: report.resolutions.last?.successfulEndpoint) ?? fallbackIP
            completion(info)
        }
    }

    func startTransfer() -> PendingTransfer {
        guard let connection else { return NoTransfer() }
        return NWPendingTransfer(report: connection.startDataTransferReport())
    }

    private static func host(of endpoint: NWEndpoint?) -> String? {
        guard case .hostPort(let host, _)? = endpoint else { return nil }
        switch host {
        case .ipv4(let address): return "\(address)"
        case .ipv6(let address): return "\(address)"
        case .name(let name, _): return name
        @unknown default: return nil
        }
    }
}

private struct NWPendingTransfer: PendingTransfer {
    let report: NWConnection.PendingDataTransferReport

    func collect(queue: DispatchQueue, completion: @escaping (TransferInfo) -> Void) {
        report.collect(queue: queue) { report in
            let path = report.aggregatePathReport
            completion(TransferInfo(retransmittedBytes: path.retransmittedTransportByteCount,
                                    minimumRTT: path.transportMinimumRTT, smoothedRTT: path.transportSmoothedRTT))
        }
    }
}

private struct NoTransfer: PendingTransfer {
    func collect(queue: DispatchQueue, completion: @escaping (TransferInfo) -> Void) {}
}
