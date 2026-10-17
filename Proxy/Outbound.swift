import Foundation
import Network
import os.log

enum OutboundError: Error, CustomStringConvertible {
    case dial(DialError)
    /// The Outline server couldn't be reached, or the target can't be encoded for it.
    case shadowsocks

    var description: String {
        switch self {
        case .dial(let error): return error.description
        case .shadowsocks: return "Outline connect failed"
        }
    }
}

/// Opens the upstream side of a session (plan §6.5). The returned connection is adopted by the
/// session and ready for relay; whatever the outbound does to the bytes (Shadowsocks encryption)
/// is inside it. The desync of the first TLS record is a separate step (`SegmentWriter`), because
/// a tunnel dials before its success reply and the ClientHello only comes after that reply.
protocol Outbound {
    func connect(_ target: DialTarget, session: SessionScope,
                 completion: @escaping (Result<any ConnectionProtocol, OutboundError>) -> Void)
}

/// Straight to the target: `.direct` and `.desync`.
struct DirectOutbound: Outbound {
    let dialer: Dialing
    let resolver: Resolver?

    func connect(_ target: DialTarget, session: SessionScope,
                 completion: @escaping (Result<any ConnectionProtocol, OutboundError>) -> Void) {
        dialer.dial(target, resolver: resolver, session: session) { result in
            completion(result.map { $0 }.mapError { .dial($0) })
        }
    }
}

/// Through an Outline server. With DoH on, the target name is resolved locally and the
/// Shadowsocks address header carries the address (as before the refactor).
struct ShadowsocksOutbound: Outbound {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Outbound")

    let dialer: Dialing
    let config: OutlineServerConfig
    let resolver: Resolver?

    func connect(_ target: DialTarget, session: SessionScope,
                 completion: @escaping (Result<any ConnectionProtocol, OutboundError>) -> Void) {
        let open = { (host: String) in
            ShadowsocksStream.connect(config: config, targetHost: host, targetPort: target.port,
                                      dialer: dialer, session: session) { stream in
                guard let stream else { return completion(.failure(.shadowsocks)) }
                session.adopt(stream)
                completion(.success(stream))
            }
        }
        guard let resolver, !ServerConnector.isIPLiteral(target.host) else { return open(target.host) }
        resolver.resolve(domain: target.host, on: session.queue) { ips in
            let resolved = ips.flatMap { ServerConnector.interleave($0).first } ?? target.host
            if resolved != target.host { Self.logger.debug("[\(target.host)] DoH resolved to \(resolved)") }
            open(resolved)
        }
    }
}
