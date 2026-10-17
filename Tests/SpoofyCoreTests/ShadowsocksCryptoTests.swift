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
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
