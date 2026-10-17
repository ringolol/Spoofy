import Foundation
import CryptoKit

/// Shadowsocks AEAD framing with no I/O (plan §6.8). One direction of a TCP stream is
/// `[salt][enc len][tag][enc payload][tag]…`, with payload chunks of at most 0x3FFF bytes.
enum ShadowsocksAEADCodec {
    enum Error: Swift.Error, Equatable {
        /// A length or payload frame failed to open: wrong key, or tampered bytes.
        case authenticationFailed
        /// A decrypted length outside 1…0x3FFF.
        case invalidLength(Int)
        /// The configured prefix doesn't fit in the salt (N2).
        case prefixTooLong(Int)
    }

    /// A fresh salt that starts with `prefix` and keeps the cipher's full salt length (N2).
    /// `SystemRandomNumberGenerator` can't fail, unlike the unchecked `SecRandomCopyBytes` it
    /// replaces, whose failure left an all-zero salt and so reused nonces across connections (N5).
    static func makeSalt(cipher: ShadowsocksCipher, prefix: Data?) throws -> Data {
        let length = ShadowsocksCrypto.saltLength(for: cipher)
        let prefix = prefix ?? Data()
        guard prefix.count <= length else { throw Error.prefixTooLong(prefix.count) }
        var rng = SystemRandomNumberGenerator()
        let random = (prefix.count..<length).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
        return prefix + Data(random)
    }

    /// The client → server direction. The first `seal` also emits the salt.
    struct Encoder {
        let cipher: ShadowsocksCipher
        private let key: SymmetricKey
        private var nonce = ShadowsocksCrypto.makeNonce()
        private var pendingSalt: Data?

        init(cipher: ShadowsocksCipher, masterKey: Data, salt: Data) {
            self.cipher = cipher
            key = ShadowsocksCrypto.deriveSubkey(masterKey: masterKey, salt: salt)
            pendingSalt = salt
        }

        /// Encrypts `payload`, split into chunks of at most 0x3FFF bytes. An empty payload
        /// produces no chunk (but still the salt, if it hasn't gone out yet).
        mutating func seal(_ payload: Data) throws -> Data {
            var out = pendingSalt ?? Data()
            pendingSalt = nil
            var offset = payload.startIndex
            while offset < payload.endIndex {
                let end = min(offset + ShadowsocksCrypto.maxPayloadSize, payload.endIndex)
                let length = end - offset
                out += try ShadowsocksCrypto.aeadEncrypt(
                    key: key, nonce: &nonce, plaintext: Data([UInt8(length >> 8), UInt8(length & 0xFF)]), cipher: cipher)
                out += try ShadowsocksCrypto.aeadEncrypt(
                    key: key, nonce: &nonce, plaintext: Data(payload[offset..<end]), cipher: cipher)
                offset = end
            }
            return out
        }
    }

    /// The server → client direction: `awaitingSalt → awaitingLengthFrame → awaitingPayloadFrame`,
    /// fed in arbitrary pieces.
    struct Decoder {
        private enum State {
            case awaitingSalt
            case awaitingLengthFrame
            case awaitingPayloadFrame(length: Int)
            case failed(Error)
        }

        let cipher: ShadowsocksCipher
        private let masterKey: Data
        private var key: SymmetricKey?
        private var nonce = ShadowsocksCrypto.makeNonce()
        private var state = State.awaitingSalt
        private var buffer = Data()

        init(cipher: ShadowsocksCipher, masterKey: Data) {
            self.cipher = cipher
            self.masterKey = masterKey
        }

        /// Returns the plaintext of every frame that `data` completes, in order. After an error
        /// the stream is poisoned: every later call throws the same error.
        mutating func feed(_ data: Data) throws -> Data {
            if case .failed(let error) = state { throw error }
            buffer += data
            var out = Data()
            do {
                while let payload = try step() { out += payload }
            } catch let error as Error {
                state = .failed(error)
                buffer = Data()
                throw error
            }
            return out
        }

        /// Advances one frame. Returns nil when more input is needed.
        private mutating func step() throws -> Data? {
            switch state {
            case .awaitingSalt:
                let length = ShadowsocksCrypto.saltLength(for: cipher)
                guard let salt = take(length) else { return nil }
                key = ShadowsocksCrypto.deriveSubkey(masterKey: masterKey, salt: salt)
                state = .awaitingLengthFrame
                return Data()

            case .awaitingLengthFrame:
                guard let frame = take(2 + ShadowsocksCrypto.tagLength) else { return nil }
                guard let bytes = ShadowsocksCrypto.aeadDecrypt(key: key!, nonce: &nonce, ciphertext: frame, cipher: cipher) else {
                    throw Error.authenticationFailed
                }
                let length = Int(bytes[bytes.startIndex]) << 8 | Int(bytes[bytes.startIndex + 1])
                guard (1...ShadowsocksCrypto.maxPayloadSize).contains(length) else { throw Error.invalidLength(length) }
                state = .awaitingPayloadFrame(length: length)
                return Data()

            case .awaitingPayloadFrame(let length):
                guard let frame = take(length + ShadowsocksCrypto.tagLength) else { return nil }
                guard let payload = ShadowsocksCrypto.aeadDecrypt(key: key!, nonce: &nonce, ciphertext: frame, cipher: cipher) else {
                    throw Error.authenticationFailed
                }
                state = .awaitingLengthFrame
                return payload

            case .failed(let error):
                throw error
            }
        }

        private mutating func take(_ count: Int) -> Data? {
            guard buffer.count >= count else { return nil }
            let head = Data(buffer.prefix(count))
            buffer = Data(buffer.dropFirst(count))
            return head
        }
    }

    // MARK: - Address header

    /// Encodes the target as a SOCKS5 address:
    /// - IPv4:   [0x01][4 bytes][port big-endian]
    /// - Domain: [0x03][len][domain bytes][port big-endian]
    /// - IPv6:   [0x04][16 bytes][port big-endian]
    /// Returns nil for an empty domain or one longer than 255 bytes (the length is a single byte, C3).
    static func addressHeader(host: String, port: UInt16) -> Data? {
        var addr = Data()
        var ipv4Addr = in_addr()
        var ipv6Addr = in6_addr()
        if inet_pton(AF_INET, host, &ipv4Addr) == 1 {
            addr.append(0x01)
            withUnsafeBytes(of: &ipv4Addr) { addr.append(contentsOf: $0) }
        } else if inet_pton(AF_INET6, host, &ipv6Addr) == 1 {
            addr.append(0x04)
            withUnsafeBytes(of: &ipv6Addr) { addr.append(contentsOf: $0) }
        } else {
            let domainBytes = Array(host.utf8)
            guard (1...255).contains(domainBytes.count) else { return nil }
            addr.append(0x03)
            addr.append(UInt8(domainBytes.count))
            addr.append(contentsOf: domainBytes)
        }
        addr.append(contentsOf: [UInt8(port >> 8), UInt8(port & 0xFF)])
        return addr
    }
}
