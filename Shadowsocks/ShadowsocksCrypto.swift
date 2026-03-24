import Foundation
import CryptoKit
import CommonCrypto

/// Pure cryptographic operations for Shadowsocks AEAD protocol.
/// Supports chacha20-ietf-poly1305 and aes-256-gcm ciphers.
enum ShadowsocksCrypto {

    // MARK: - Key Derivation

    /// Derives master key from password using OpenSSL's EVP_BytesToKey (MD5-based).
    /// This is the standard Shadowsocks AEAD key derivation from a password string.
    static func masterKey(from password: String, keyLen: Int) -> Data {
        let passwordBytes = Array(password.utf8)
        var key = Data(capacity: keyLen)
        var prev = Data()

        while key.count < keyLen {
            var input = Data()
            input.append(prev)
            input.append(contentsOf: passwordBytes)

            var hash = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
            _ = input.withUnsafeBytes { ptr in
                CC_MD5(ptr.baseAddress, CC_LONG(input.count), &hash)
            }
            prev = Data(hash)
            key.append(prev)
        }

        return key.prefix(keyLen)
    }

    /// Derives a per-session subkey from master key and random salt using HKDF-SHA1.
    /// Info string is "ss-subkey" per the Shadowsocks AEAD specification.
    static func deriveSubkey(masterKey: Data, salt: Data) -> SymmetricKey {
        let ikm = SymmetricKey(data: masterKey)
        let subkey = HKDF<Insecure.SHA1>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: Array("ss-subkey".utf8),
            outputByteCount: masterKey.count
        )
        return subkey
    }

    // MARK: - AEAD Encrypt / Decrypt

    /// Encrypts plaintext with AEAD cipher. Returns ciphertext + 16-byte tag.
    /// Nonce is a 12-byte little-endian counter, incremented after this call.
    static func aeadEncrypt(
        key: SymmetricKey,
        nonce: inout [UInt8],
        plaintext: Data,
        cipher: ShadowsocksCipher
    ) throws -> Data {
        let result: Data
        switch cipher {
        case .chacha20IetfPoly1305:
            let n = try ChaChaPoly.Nonce(data: nonce)
            let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: n)
            result = sealed.ciphertext + sealed.tag
        case .aes256Gcm:
            let n = try AES.GCM.Nonce(data: nonce)
            let sealed = try AES.GCM.seal(plaintext, using: key, nonce: n)
            result = sealed.ciphertext + sealed.tag
        }
        incrementNonce(&nonce)
        return result
    }

    /// Decrypts ciphertext (payload + 16-byte tag) with AEAD cipher.
    /// Returns nil on authentication failure. Nonce is incremented after this call.
    static func aeadDecrypt(
        key: SymmetricKey,
        nonce: inout [UInt8],
        ciphertext: Data,
        cipher: ShadowsocksCipher
    ) -> Data? {
        guard ciphertext.count >= 16 else { return nil }
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)

        let result: Data?
        do {
            switch cipher {
            case .chacha20IetfPoly1305:
                let n = try ChaChaPoly.Nonce(data: nonce)
                let box = try ChaChaPoly.SealedBox(nonce: n, ciphertext: ct, tag: tag)
                result = try ChaChaPoly.open(box, using: key)
            case .aes256Gcm:
                let n = try AES.GCM.Nonce(data: nonce)
                let box = try AES.GCM.SealedBox(nonce: n, ciphertext: ct, tag: tag)
                result = try AES.GCM.open(box, using: key)
            }
        } catch {
            return nil
        }
        incrementNonce(&nonce)
        return result
    }

    // MARK: - Nonce

    /// Increments a 12-byte little-endian nonce counter by 1.
    static func incrementNonce(_ nonce: inout [UInt8]) {
        for i in 0..<nonce.count {
            nonce[i] &+= 1
            if nonce[i] != 0 { break }
        }
    }

    /// Returns a zeroed 12-byte nonce.
    static func makeNonce() -> [UInt8] {
        [UInt8](repeating: 0, count: 12)
    }

    // MARK: - Constants

    /// Key length in bytes for supported ciphers (both are 32).
    static func keyLength(for cipher: ShadowsocksCipher) -> Int {
        switch cipher {
        case .chacha20IetfPoly1305: return 32
        case .aes256Gcm: return 32
        }
    }

    /// Salt length equals key length per the Shadowsocks AEAD spec.
    static func saltLength(for cipher: ShadowsocksCipher) -> Int {
        keyLength(for: cipher)
    }

    /// AEAD tag length (16 bytes for both ciphers).
    static let tagLength = 16

    /// Maximum payload per AEAD chunk (0x3FFF = 16383).
    static let maxPayloadSize = 0x3FFF
}
