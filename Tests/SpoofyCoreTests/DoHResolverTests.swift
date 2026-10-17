import XCTest
@testable import SpoofyCore

/// The lookup path of `DoHResolver` over an injected transport (N10).
final class DoHResolverTests: XCTestCase {
    private let queue = DispatchQueue(label: "DoHResolverTests")

    /// Answers each query from `records` by QTYPE; records requests.
    private final class FakeTransport {
        var records: [UInt16: [[UInt8]]]
        let lock = NSLock()
        private var _qtypes: [UInt16] = []
        var qtypes: [UInt16] { lock.withLock { _qtypes } }

        init(_ records: [UInt16: [[UInt8]]]) { self.records = records }

        func handle(_ request: URLRequest, _ completion: @escaping (Data?) -> Void) {
            let query = Self.decodeQuery(request.url!)
            let qtype = query.readUInt16(at: query.count - 4)
            lock.withLock { _qtypes.append(qtype) }
            let answers = records[qtype]
            DispatchQueue.global().async {
                completion(answers.map { Self.response(to: query, qtype: qtype, rdatas: $0) })
            }
        }

        static func decodeQuery(_ url: URL) -> Data {
            var b64 = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!.first { $0.name == "dns" }!.value!
            b64 = b64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
            return Data(base64Encoded: b64)!
        }

        static func response(to query: Data, qtype: UInt16, rdatas: [[UInt8]]) -> Data {
            var data = Data(query.prefix(2)) + [0x81, 0x80]
            data.appendUInt16(1)
            data.appendUInt16(UInt16(rdatas.count))
            data.appendUInt16(0)
            data.appendUInt16(0)
            data += query.dropFirst(12)
            for rdata in rdatas {
                data += [0xC0, 0x0C]
                data.appendUInt16(qtype)
                data.appendUInt16(1)
                data.appendUInt16(0)
                data.appendUInt16(600)
                data.appendUInt16(UInt16(rdata.count))
                data += rdata
            }
            return data
        }
    }

    private func resolve(_ resolver: DoHResolver, _ name: String) -> [String]? {
        let done = expectation(description: "resolved")
        let box = LockedBox<[String]??>(nil)
        resolver.resolve(domain: name, on: queue) { ips in
            dispatchPrecondition(condition: .onQueue(self.queue))
            box.value = .some(ips)
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
        return box.value ?? nil
    }

    private static let v6: [UInt8] = [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [1]

    func testQueriesAAndAAAAAndMergesIPv4First() {
        let transport = FakeTransport([1: [[93, 184, 216, 34]], 28: [Self.v6]])
        let resolver = DoHResolver(serverURL: "https://dns.test/dns-query", transport: transport.handle)
        XCTAssertEqual(resolve(resolver, "example.com"), ["93.184.216.34", "2001:db8:0:0:0:0:0:1"])
        XCTAssertEqual(Set(transport.qtypes), [1, 28])
    }

    func testIPv6OnlyHostResolves() {
        let transport = FakeTransport([1: [], 28: [Self.v6]])
        let resolver = DoHResolver(serverURL: "https://dns.test/dns-query", transport: transport.handle)
        XCTAssertEqual(resolve(resolver, "v6only.test"), ["2001:db8:0:0:0:0:0:1"])
    }

    func testOneFailedQueryStillReturnsTheOther() {
        let transport = FakeTransport([1: [[10, 0, 0, 1]]]) // AAAA transport fails
        let resolver = DoHResolver(serverURL: "https://dns.test/dns-query", transport: transport.handle)
        XCTAssertEqual(resolve(resolver, "example.com"), ["10.0.0.1"])
    }

    func testNoAnswersIsNil() {
        let transport = FakeTransport([1: [], 28: []])
        let resolver = DoHResolver(serverURL: "https://dns.test/dns-query", transport: transport.handle)
        XCTAssertNil(resolve(resolver, "nx.test"))
    }

    func testSecondLookupIsServedFromCache() {
        let transport = FakeTransport([1: [[10, 0, 0, 1]], 28: []])
        let resolver = DoHResolver(serverURL: "https://dns.test/dns-query", transport: transport.handle)
        XCTAssertEqual(resolve(resolver, "example.com"), ["10.0.0.1"])
        XCTAssertEqual(resolve(resolver, "example.com"), ["10.0.0.1"])
        XCTAssertEqual(transport.qtypes.count, 2)
    }

    func testIPLiteralsShortCircuitWithoutAQuery() {
        let transport = FakeTransport([:])
        let resolver = DoHResolver(serverURL: "https://dns.test/dns-query", transport: transport.handle)
        XCTAssertEqual(resolve(resolver, "1.2.3.4"), ["1.2.3.4"])
        XCTAssertEqual(resolve(resolver, "[::1]"), ["::1"])
        XCTAssertEqual(resolve(resolver, "::1"), ["::1"])
        XCTAssertEqual(transport.qtypes, [])
    }
}
