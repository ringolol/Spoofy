import Foundation
import Network
@testable import SpoofyCore

/// A minimal Shadowsocks AEAD server on loopback, built on `ShadowsocksAEADCodec`: it reads the
/// address header, dials the target, and relays both ways. Not an interop check (both sides share
/// the codec; the KATs and the opt-in shadowbox test cover that), but it lets the harness run the
/// VPN route end to end.
final class LoopbackShadowsocksServer {
    let password: String
    let cipher: ShadowsocksCipher
    private(set) var port: UInt16 = 0
    private let listener: NWListener
    private let queue = DispatchQueue(label: "LoopbackShadowsocksServer")
    private let lock = NSLock()
    private var tunnels: [Tunnel] = []
    private var _targets: [String] = []
    private var _firstReadSizes: [Int] = []

    /// Every target from an address header, as `host:port`.
    var targets: [String] { lock.withLock { _targets } }
    /// Bytes in the first read of each connection: salt plus however much the client coalesced.
    var firstReadSizes: [Int] { lock.withLock { _firstReadSizes } }

    init(password: String = "test-password", cipher: ShadowsocksCipher = .chacha20IetfPoly1305) throws {
        self.password = password
        self.cipher = cipher
        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        listener = try NWListener(using: params, on: .any)

        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
            if case .failed = state { ready.signal() }
        }
        listener.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, let port = listener.port else {
            throw HarnessError.timeout("shadowsocks listener")
        }
        self.port = port.rawValue
    }

    var config: OutlineServerConfig {
        OutlineServerConfig(host: "127.0.0.1", port: port, password: password, cipher: cipher, prefix: nil)
    }

    func stop() {
        listener.cancel()
        lock.withLock { tunnels }.forEach { $0.close() }
    }

    private func accept(_ conn: NWConnection) {
        let masterKey = ShadowsocksCrypto.masterKey(from: password, keyLen: ShadowsocksCrypto.keyLength(for: cipher))
        let tunnel = Tunnel(client: conn, cipher: cipher, masterKey: masterKey, queue: queue) { [weak self] event in
            guard let self else { return }
            self.lock.withLock {
                switch event {
                case .firstRead(let size): self._firstReadSizes.append(size)
                case .target(let target): self._targets.append(target)
                }
            }
        }
        lock.withLock { tunnels.append(tunnel) }
        tunnel.start()
    }

    private final class Tunnel {
        enum Event { case firstRead(Int), target(String) }

        private let client: NWConnection
        private var target: NWConnection?
        private let queue: DispatchQueue
        private let report: (Event) -> Void
        private var decoder: ShadowsocksAEADCodec.Decoder
        private var encoder: ShadowsocksAEADCodec.Encoder
        private var plaintext = Data()
        private var sawFirstRead = false

        init(client: NWConnection, cipher: ShadowsocksCipher, masterKey: Data, queue: DispatchQueue,
             report: @escaping (Event) -> Void) {
            self.client = client
            self.queue = queue
            self.report = report
            decoder = .init(cipher: cipher, masterKey: masterKey)
            encoder = .init(cipher: cipher, masterKey: masterKey,
                            salt: try! ShadowsocksAEADCodec.makeSalt(cipher: cipher, prefix: nil))
        }

        func start() {
            client.start(queue: queue)
            readClient()
        }

        func close() {
            client.cancel()
            target?.cancel()
        }

        private func readClient() {
            client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [self] data, _, isComplete, error in
                if let data, !data.isEmpty {
                    if !sawFirstRead {
                        sawFirstRead = true
                        report(.firstRead(data.count))
                    }
                    guard let decoded = try? decoder.feed(data) else { return close() }
                    plaintext += decoded
                    forward()
                }
                if isComplete || error != nil { return close() }
                readClient()
            }
        }

        /// Until the target is dialled, `plaintext` holds the address header and what follows it.
        private func forward() {
            if let target {
                if !plaintext.isEmpty { target.send(content: plaintext, completion: .idempotent) }
                plaintext = Data()
                return
            }
            guard let (host, port, length) = Self.parseAddress(plaintext) else { return }
            report(.target("\(host):\(port)"))
            plaintext = Data(plaintext.dropFirst(length))
            let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            target = conn
            conn.start(queue: queue)
            forward()
            readTarget(conn)
        }

        private func readTarget(_ conn: NWConnection) {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [self] data, _, isComplete, error in
                if let data, !data.isEmpty, let sealed = try? encoder.seal(data) {
                    client.send(content: sealed, completion: .idempotent)
                }
                if isComplete || error != nil { return close() }
                readTarget(conn)
            }
        }

        /// The SOCKS5-style address at the start of `data`, or nil if it isn't complete yet.
        private static func parseAddress(_ data: Data) -> (String, UInt16, Int)? {
            let bytes = [UInt8](data)
            guard let type = bytes.first else { return nil }
            let hostEnd: Int
            let host: String
            switch type {
            case 0x01:
                hostEnd = 5
                guard bytes.count >= hostEnd else { return nil }
                host = bytes[1..<5].map(String.init).joined(separator: ".")
            case 0x03:
                guard bytes.count >= 2 else { return nil }
                hostEnd = 2 + Int(bytes[1])
                guard bytes.count >= hostEnd else { return nil }
                host = String(decoding: bytes[2..<hostEnd], as: UTF8.self)
            case 0x04:
                hostEnd = 17
                guard bytes.count >= hostEnd else { return nil }
                var addr = in6_addr()
                withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: bytes[1..<17]) }
                var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                inet_ntop(AF_INET6, &addr, &text, socklen_t(text.count))
                host = String(cString: text)
            default:
                return nil
            }
            guard bytes.count >= hostEnd + 2 else { return nil }
            return (host, UInt16(bytes[hostEnd]) << 8 | UInt16(bytes[hostEnd + 1]), hostEnd + 2)
        }
    }
}
