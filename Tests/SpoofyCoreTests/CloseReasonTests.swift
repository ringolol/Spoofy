import Network
import XCTest
@testable import SpoofyCore

/// Step 5a: structured close and handshake-failure reasons keep the old log text.
final class CloseReasonTests: XCTestCase {
    func testInboundFailureDescriptionsMatchTheOldText() {
        let cases: [(InboundFailure, String)] = [
            (.socks5AuthRequired(offered: [2]), "no acceptable auth method (offered [2])"),
            (.socks5Command(3), "unsupported command 3"),
            (.socks5AddressType(9), "unsupported address type 9"),
            (.headTooLarge, "head over 65536 bytes"),
            (.malformed("malformed request line"), "malformed request line"),
        ]
        for (failure, text) in cases {
            XCTAssertEqual(failure.description, text)
        }
    }

    func testCloseReasonDescriptionsMatchTheOldText() {
        let refused = NWError.posix(.ECONNREFUSED)
        let cases: [(CloseReason, String)] = [
            (.handshakeReadError(refused), "read error in handshake: \(refused.localizedDescription)"),
            (.clientClosedInHandshake, "client closed during handshake"),
            (.handshakeFailed(.socks5Command(2)), "handshake failed: unsupported command 2"),
            (.rejected("VPN route has no Outline config"), "VPN route has no Outline config"),
            (.connectFailed(.shadowsocks), "connect failed: Outline connect failed"),
            (.clientClosedBeforeFirstFlight, "client closed before its first flight"),
            (.firstFlightWriteFailed(refused), "first flight write failed: \(refused.localizedDescription)"),
            (.relayFinished, "relay finished"),
            (.idleTimeout, "idle timeout"),
            (.clientWriteFailed(refused), "client write failed: \(refused.localizedDescription)"),
            (.upstreamWriteFailed(refused), "upstream write failed: \(refused.localizedDescription)"),
            (.deadline("handshake", seconds: 10), "handshake deadline (10.0s)"),
            (.routeChanged(.direct), "route changed to direct"),
            (.proxyStopped, "proxy stopped"),
            (.clientConnectionFailed(refused), "client connection failed: \(refused.localizedDescription)"),
            (.clientConnectionCancelled, "client connection cancelled"),
        ]
        for (reason, text) in cases {
            XCTAssertEqual(reason.description, text)
        }
    }

    // MARK: - Parsers report structured failures

    private func socks5Failure(_ bytes: [UInt8]) -> InboundFailure? {
        var parser = SOCKS5Parser()
        var step = parser.feed(Data(bytes))
        while case .reply(_, let then) = step { step = then }
        guard case .fail(_, let failure) = step else { return nil }
        return failure
    }

    func testSOCKS5Failures() {
        XCTAssertEqual(socks5Failure([0x05, 0x01, 0x02]), .socks5AuthRequired(offered: [2]))
        XCTAssertEqual(socks5Failure([0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), .socks5Command(3))
        XCTAssertEqual(socks5Failure([0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), .socks5Command(2))
        XCTAssertEqual(socks5Failure([0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09]), .socks5AddressType(9))
    }

    func testHTTPHeadTooLarge() {
        var parser = HTTPHeadParser()
        guard case .fail(_, let failure) = parser.feed(Data(repeating: 0x41, count: HTTPHeadParser.maxHead + 1)) else {
            return XCTFail("expected a failure")
        }
        XCTAssertEqual(failure, .headTooLarge)
    }
}
