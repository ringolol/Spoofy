import CryptoKit
import XCTest
@testable import SpoofyCore

final class ShadowsocksCryptoTests: XCTestCase {
    // EVP_BytesToKey(MD5); the first 16 bytes are md5("password").
    func testMasterKeyKnownAnswer() {
        let key = ShadowsocksCrypto.masterKey(from: "password", keyLen: 32)
        XCTAssertEqual(key.hex, "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08")
    }

    // HKDF-SHA1(ikm: master key, salt: 00 01 ... 1f, info: "ss-subkey").
    func testDeriveSubkeyKnownAnswer() {
        let master = ShadowsocksCrypto.masterKey(from: "password", keyLen: 32)
        let salt = Data(0..<32)
        let subkey = ShadowsocksCrypto.deriveSubkey(masterKey: master, salt: salt)
        XCTAssertEqual(subkey.withUnsafeBytes { Data($0) }.hex,
                       "ee187aed3f87574907a39db98606f60a526114831288097cac66054b33a9464f")
    }

    // MARK: - AEAD (vectors from Go: x/crypto/chacha20poly1305 and crypto/cipher GCM, no AAD)

    private let key = SymmetricKey(data: Data(0..<32))
    private let plaintext = Data("Spoofy shadowsocks KAT".utf8)

    private let vectors: [(ShadowsocksCipher, nonce0: String, nonce1: String)] = [
        (.chacha20IetfPoly1305,
         "4bc82d5ecb9f86a27b00380ed830214493c2d3bea0f9af048988223b3030106cd187854d78ee",
         "c74f1481a29abc591f3ab79c1a4cb2384acbd0936cade351f383992d33e40198727576d48bbb"),
        (.aes256Gcm,
         "5dccdab1d355a3ce60c9cd5a6f5ffefab930761869d59f0606b91e0aee70989003b414dd62dd",
         "b15ced50c2d6cc74226561ac4bb2e7a8a712ef653dfc68d958870ff1afb69f5777fefd6bc0de"),
    ]

    func testEncryptKnownAnswerAndNonceAdvance() throws {
        for (cipher, expected0, expected1) in vectors {
            var nonce = ShadowsocksCrypto.makeNonce()
            let first = try ShadowsocksCrypto.aeadEncrypt(key: key, nonce: &nonce, plaintext: plaintext, cipher: cipher)
            XCTAssertEqual(first.hex, expected0, "\(cipher)")
            XCTAssertEqual(nonce, [1] + Array(repeating: 0, count: 11))
            let second = try ShadowsocksCrypto.aeadEncrypt(key: key, nonce: &nonce, plaintext: plaintext, cipher: cipher)
            XCTAssertEqual(second.hex, expected1, "\(cipher)")
        }
    }

    func testDecryptKnownAnswer() {
        for (cipher, expected0, _) in vectors {
            var nonce = ShadowsocksCrypto.makeNonce()
            let opened = ShadowsocksCrypto.aeadDecrypt(key: key, nonce: &nonce, ciphertext: Data(hex: expected0), cipher: cipher)
            XCTAssertEqual(opened, plaintext, "\(cipher)")
            XCTAssertEqual(nonce[0], 1)
        }
    }

    func testTamperedTagFailsAndKeepsNonce() {
        for (cipher, expected0, _) in vectors {
            var ciphertext = Data(hex: expected0)
            ciphertext[ciphertext.count - 1] ^= 0x01
            var nonce = ShadowsocksCrypto.makeNonce()
            XCTAssertNil(ShadowsocksCrypto.aeadDecrypt(key: key, nonce: &nonce, ciphertext: ciphertext, cipher: cipher))
            XCTAssertEqual(nonce, ShadowsocksCrypto.makeNonce(), "nonce must not advance on failure")
        }
    }

    func testCiphertextShorterThanTagFails() {
        var nonce = ShadowsocksCrypto.makeNonce()
        XCTAssertNil(ShadowsocksCrypto.aeadDecrypt(key: key, nonce: &nonce, ciphertext: Data(count: 15), cipher: .aes256Gcm))
    }

    func testEmptyPlaintextIsJustATag() throws {
        var nonce = ShadowsocksCrypto.makeNonce()
        let sealed = try ShadowsocksCrypto.aeadEncrypt(key: key, nonce: &nonce, plaintext: Data(), cipher: .chacha20IetfPoly1305)
        XCTAssertEqual(sealed.count, ShadowsocksCrypto.tagLength)
    }

    // MARK: - Nonce

    func testIncrementNonceIsLittleEndian() {
        var nonce = ShadowsocksCrypto.makeNonce()
        ShadowsocksCrypto.incrementNonce(&nonce)
        XCTAssertEqual(nonce, [1] + Array(repeating: 0, count: 11))

        nonce = [0xFF] + Array(repeating: 0, count: 11)
        ShadowsocksCrypto.incrementNonce(&nonce)
        XCTAssertEqual(nonce, [0, 1] + Array(repeating: 0, count: 10))

        nonce = [0xFF, 0xFF, 0x05] + Array(repeating: 0, count: 9)
        ShadowsocksCrypto.incrementNonce(&nonce)
        XCTAssertEqual(nonce, [0, 0, 0x06] + Array(repeating: 0, count: 9))
    }

    func testIncrementNonceWrapsAround() {
        var nonce = [UInt8](repeating: 0xFF, count: 12)
        ShadowsocksCrypto.incrementNonce(&nonce)
        XCTAssertEqual(nonce, ShadowsocksCrypto.makeNonce())
    }

    func testSizes() {
        for cipher in ShadowsocksCipher.allCases {
            XCTAssertEqual(ShadowsocksCrypto.keyLength(for: cipher), 32)
            XCTAssertEqual(ShadowsocksCrypto.saltLength(for: cipher), 32)
        }
        XCTAssertEqual(ShadowsocksCrypto.maxPayloadSize, 0x3FFF)
    }
}
