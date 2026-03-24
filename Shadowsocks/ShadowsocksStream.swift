import Foundation
import Network
import CryptoKit
import os.log

/// Wraps an NWConnection to an Outline/Shadowsocks server, providing transparent
/// AEAD encryption/decryption. Conforms to ConnectionProtocol so it can be used
/// directly with ConnectionRelay.
final class ShadowsocksStream: ConnectionProtocol {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Shadowsocks")

    private let underlying: NWConnection
    private let masterKey: Data
    private let cipher: ShadowsocksCipher
    private let prefix: Data?
    private let targetHost: String
    private let targetPort: UInt16
    private let queue: DispatchQueue

    // Send state
    private var sendKey: SymmetricKey?
    private var sendNonce: [UInt8] = ShadowsocksCrypto.makeNonce()
    private var preambleSent = false
    private var addressSent = false

    // Receive state machine
    private enum ReceiveState {
        case awaitingSalt
        case awaitingLengthFrame
        case awaitingPayloadFrame(payloadLen: Int)
    }

    private var recvState: ReceiveState = .awaitingSalt
    private var recvBuffer = Data()
    private var recvKey: SymmetricKey?
    private var recvNonce: [UInt8] = ShadowsocksCrypto.makeNonce()
    private var pendingDecrypted = Data()

    // MARK: - Init / Connect

    private init(
        underlying: NWConnection,
        masterKey: Data,
        cipher: ShadowsocksCipher,
        prefix: Data?,
        targetHost: String,
        targetPort: UInt16,
        queue: DispatchQueue
    ) {
        self.underlying = underlying
        self.masterKey = masterKey
        self.cipher = cipher
        self.prefix = prefix
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.queue = queue
    }

    /// Creates a ShadowsocksStream connected to the Outline server.
    /// On success, the stream is ready for send/receive via ConnectionRelay.
    static func connect(
        config: OutlineServerConfig,
        targetHost: String,
        targetPort: UInt16,
        queue: DispatchQueue,
        completion: @escaping (ShadowsocksStream?) -> Void
    ) {
        let keyLen = ShadowsocksCrypto.keyLength(for: config.cipher)

        // Outline uses base64-encoded PSK directly — NOT EVP_BytesToKey.
        // The password field in the ss:// URI is the base64-encoded raw key.
        // Try multiple base64 variants: standard, standard+padding, base64url+padding.
        let masterKey: Data
        if let decoded = Self.flexibleBase64Decode(config.password), decoded.count == keyLen {
            masterKey = decoded
        } else {
            masterKey = ShadowsocksCrypto.masterKey(from: config.password, keyLen: keyLen)
        }

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcpOptions)
        params.preferNoProxies = true

        let host = NWEndpoint.Host(config.host)
        let port = NWEndpoint.Port(rawValue: config.port)!
        let conn = NWConnection(host: host, port: port, using: params)

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.stateUpdateHandler = nil
                let stream = ShadowsocksStream(
                    underlying: conn,
                    masterKey: masterKey,
                    cipher: config.cipher,
                    prefix: config.prefix,
                    targetHost: targetHost,
                    targetPort: targetPort,
                    queue: queue
                )
                logger.info("Connected to Outline server \(config.host):\(config.port) for \(targetHost):\(targetPort)")
                completion(stream)
            case .failed(let error):
                conn.stateUpdateHandler = nil
                logger.error("Failed to connect to Outline server: \(error.localizedDescription)")
                conn.cancel()
                completion(nil)
            case .cancelled:
                conn.stateUpdateHandler = nil
                completion(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    // MARK: - ConnectionProtocol: Send

    func send(content: Data?, contentContext: NWConnection.ContentContext,
              isComplete: Bool, completion: NWConnection.SendCompletion) {
        guard let plaintext = content, !plaintext.isEmpty else {
            underlying.send(content: nil, contentContext: contentContext,
                           isComplete: isComplete, completion: completion)
            return
        }

        do {
            var encrypted = Data()

            // Send preamble (salt) on first send.
            // If a prefix is configured, it replaces the first N bytes of the salt
            // (prefix is embedded INTO the salt, not prepended before it).
            if !preambleSent {
                let saltLen = ShadowsocksCrypto.saltLength(for: cipher)
                var salt = Data(count: saltLen)
                salt.withUnsafeMutableBytes { ptr in
                    _ = SecRandomCopyBytes(kSecRandomDefault, saltLen, ptr.baseAddress!)
                }
                if let prefix = prefix {
                    salt.replaceSubrange(0..<prefix.count, with: prefix)
                }
                sendKey = ShadowsocksCrypto.deriveSubkey(masterKey: masterKey, salt: salt)
                encrypted.append(salt)
                preambleSent = true
            }

            // Build payload: prepend target address on first payload
            var payload: Data
            if !addressSent {
                payload = encodeTargetAddress() + plaintext
                addressSent = true
            } else {
                payload = plaintext
            }

            // Chunk and encrypt
            var offset = 0
            while offset < payload.count {
                let chunkSize = min(ShadowsocksCrypto.maxPayloadSize, payload.count - offset)
                let chunk = payload[payload.startIndex.advanced(by: offset)..<payload.startIndex.advanced(by: offset + chunkSize)]

                // Encrypt length (2 bytes big-endian)
                let lenBytes = Data([UInt8(chunkSize >> 8), UInt8(chunkSize & 0xFF)])
                let encLen = try ShadowsocksCrypto.aeadEncrypt(
                    key: sendKey!, nonce: &sendNonce, plaintext: lenBytes, cipher: cipher
                )
                encrypted.append(encLen)

                // Encrypt payload
                let encPayload = try ShadowsocksCrypto.aeadEncrypt(
                    key: sendKey!, nonce: &sendNonce, plaintext: Data(chunk), cipher: cipher
                )
                encrypted.append(encPayload)

                offset += chunkSize
            }

            underlying.send(content: encrypted, contentContext: contentContext,
                           isComplete: isComplete, completion: completion)
        } catch {
            Self.logger.error("Shadowsocks encrypt error: \(error.localizedDescription)")
            cancel()
            if case .contentProcessed(let handler) = completion {
                handler(NWError.posix(.EIO))
            }
        }
    }

    // MARK: - ConnectionProtocol: Receive

    func receive(minimumIncompleteLength: Int, maximumLength: Int,
                 completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void) {
        // Deliver buffered decrypted data first
        if !pendingDecrypted.isEmpty {
            let chunk = pendingDecrypted.prefix(maximumLength)
            pendingDecrypted.removeFirst(chunk.count)
            completion(Data(chunk), .defaultMessage, false, nil)
            return
        }
        readAndProcess(maximumLength: maximumLength, completion: completion)
    }

    private func readAndProcess(
        maximumLength: Int,
        completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    ) {
        underlying.receive(minimumIncompleteLength: 1, maximumLength: 32768) { [self] data, ctx, isComplete, error in
            if let error = error {
                completion(nil, ctx, isComplete, error)
                return
            }
            if let data = data {
                recvBuffer.append(data)
            }

            // Drive state machine as far as buffer allows
            let ok = processRecvBuffer()
            if !ok {
                // Decryption failure — connection is poisoned
                Self.logger.error("Shadowsocks decrypt failure, closing stream")
                completion(nil, nil, true, NWError.posix(.EIO))
                cancel()
                return
            }

            // Deliver if we have decrypted data
            if !pendingDecrypted.isEmpty {
                let chunk = pendingDecrypted.prefix(maximumLength)
                pendingDecrypted.removeFirst(chunk.count)
                completion(Data(chunk), .defaultMessage, false, nil)
            } else if isComplete {
                completion(nil, ctx, true, nil)
            } else {
                // Need more data — recurse
                readAndProcess(maximumLength: maximumLength, completion: completion)
            }
        }
    }

    /// Processes recvBuffer through the state machine, appending decrypted payloads
    /// to pendingDecrypted. Returns false on decryption failure (fatal).
    private func processRecvBuffer() -> Bool {
        while true {
            switch recvState {
            case .awaitingSalt:
                let saltLen = ShadowsocksCrypto.saltLength(for: cipher)
                guard recvBuffer.count >= saltLen else { return true }
                let salt = recvBuffer.prefix(saltLen)
                recvBuffer.removeFirst(saltLen)
                recvKey = ShadowsocksCrypto.deriveSubkey(masterKey: masterKey, salt: Data(salt))
                recvState = .awaitingLengthFrame
                continue

            case .awaitingLengthFrame:
                let needed = 2 + ShadowsocksCrypto.tagLength  // 18 bytes
                guard recvBuffer.count >= needed else { return true }
                let frame = Data(recvBuffer.prefix(needed))
                recvBuffer.removeFirst(needed)
                guard let lenBytes = ShadowsocksCrypto.aeadDecrypt(
                    key: recvKey!, nonce: &recvNonce, ciphertext: frame, cipher: cipher
                ) else { return false }
                let payloadLen = Int(lenBytes[0]) << 8 | Int(lenBytes[1])
                guard payloadLen > 0 && payloadLen <= ShadowsocksCrypto.maxPayloadSize else { return false }
                recvState = .awaitingPayloadFrame(payloadLen: payloadLen)
                continue

            case .awaitingPayloadFrame(let payloadLen):
                let needed = payloadLen + ShadowsocksCrypto.tagLength
                guard recvBuffer.count >= needed else { return true }
                let frame = Data(recvBuffer.prefix(needed))
                recvBuffer.removeFirst(needed)
                guard let payload = ShadowsocksCrypto.aeadDecrypt(
                    key: recvKey!, nonce: &recvNonce, ciphertext: frame, cipher: cipher
                ) else { return false }
                pendingDecrypted.append(payload)
                recvState = .awaitingLengthFrame
                continue
            }
        }
    }

    // MARK: - ConnectionProtocol: Cancel

    func cancel() {
        underlying.cancel()
    }

    // MARK: - Target Address Encoding

    /// Decodes a base64 string, trying standard, padded, and base64url variants.
    private static func flexibleBase64Decode(_ input: String) -> Data? {
        // Standard base64 as-is
        if let d = Data(base64Encoded: input) { return d }
        // Add padding if missing
        var padded = input
        let r = padded.count % 4
        if r != 0 { padded.append(String(repeating: "=", count: 4 - r)) }
        if let d = Data(base64Encoded: padded) { return d }
        // Base64url: replace - with +, _ with /, then pad
        var urlSafe = input
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let r2 = urlSafe.count % 4
        if r2 != 0 { urlSafe.append(String(repeating: "=", count: 4 - r2)) }
        return Data(base64Encoded: urlSafe)
    }

    /// Encodes the target host:port as a SOCKS5 address header.
    /// - IPv4:   [0x01][4 bytes][port big-endian]
    /// - Domain: [0x03][len][domain bytes][port big-endian]
    /// - IPv6:   [0x04][16 bytes][port big-endian]
    private func encodeTargetAddress() -> Data {
        var addr = Data()
        let portBytes = Data([UInt8(targetPort >> 8), UInt8(targetPort & 0xFF)])

        var ipv4Addr = in_addr()
        var ipv6Addr = in6_addr()
        if inet_pton(AF_INET, targetHost, &ipv4Addr) == 1 {
            addr.append(0x01)
            withUnsafeBytes(of: &ipv4Addr) { addr.append(contentsOf: $0) }
        } else if inet_pton(AF_INET6, targetHost, &ipv6Addr) == 1 {
            addr.append(0x04)
            withUnsafeBytes(of: &ipv6Addr) { addr.append(contentsOf: $0) }
        } else {
            let domainBytes = Array(targetHost.utf8)
            addr.append(0x03)
            addr.append(UInt8(domainBytes.count))
            addr.append(contentsOf: domainBytes)
        }

        addr.append(portBytes)
        return addr
    }
}
