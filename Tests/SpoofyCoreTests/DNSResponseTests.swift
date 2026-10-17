import XCTest
@testable import SpoofyCore

final class DNSResponseTests: XCTestCase {
    private let resolver = DoHResolver(serverURL: "https://dns.example/dns-query")

    private struct Answer {
        var type: UInt16
        var ttl: UInt32
        var rdata: Data
        static func a(_ ip: [UInt8], ttl: UInt32 = 3600) -> Answer { Answer(type: 1, ttl: ttl, rdata: Data(ip)) }
        static func aaaa(_ ip: [UInt8], ttl: UInt32 = 3600) -> Answer { Answer(type: 28, ttl: ttl, rdata: Data(ip)) }
    }

    private static let questionName = Data([7]) + Data("example".utf8) + Data([3]) + Data("com".utf8) + Data([0])

    /// A response for "example.com" whose answers use a compression pointer to the question name.
    private func response(rcode: UInt8 = 0, answers: [Answer]) -> Data {
        var data = Data([0x12, 0x34, 0x81, 0x80 | rcode])
        data.appendUInt16(1)
        data.appendUInt16(UInt16(answers.count))
        data.appendUInt16(0)
        data.appendUInt16(0)
        data += Self.questionName
        data.appendUInt16(1)
        data.appendUInt16(1)
        for answer in answers {
            data += [0xC0, 0x0C]
            data.appendUInt16(answer.type)
            data.appendUInt16(1)
            data.appendUInt16(UInt16(answer.ttl >> 16))
            data.appendUInt16(UInt16(answer.ttl & 0xFFFF))
            data.appendUInt16(UInt16(answer.rdata.count))
            data += answer.rdata
        }
        return data
    }

    func testARecords() {
        let result = resolver.parseDNSResponse(data: response(answers: [.a([93, 184, 216, 34]), .a([10, 0, 0, 1], ttl: 60)]))
        XCTAssertEqual(result.ips, ["93.184.216.34", "10.0.0.1"])
        XCTAssertEqual(result.ttl, 60)
    }

    func testAAAARecordIsFormattedWithoutCompression() {
        let ip: [UInt8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        let result = resolver.parseDNSResponse(data: response(answers: [.aaaa(ip)]))
        XCTAssertEqual(result.ips, ["2001:db8:0:0:0:0:0:1"])
    }

    func testCNAMEChainYieldsOnlyAddresses() {
        let cname = Answer(type: 5, ttl: 3600, rdata: Data([3]) + Data("cdn".utf8) + Data([0xC0, 0x0C]))
        let result = resolver.parseDNSResponse(data: response(answers: [cname, .a([1, 2, 3, 4])]))
        XCTAssertEqual(result.ips, ["1.2.3.4"])
    }

    func testTTLIsClampedBetween30And300() {
        XCTAssertEqual(resolver.parseDNSResponse(data: response(answers: [.a([1, 1, 1, 1], ttl: 5)])).ttl, 30)
        XCTAssertEqual(resolver.parseDNSResponse(data: response(answers: [.a([1, 1, 1, 1], ttl: 86400)])).ttl, 300)
        XCTAssertEqual(resolver.parseDNSResponse(data: response(answers: [.a([1, 1, 1, 1], ttl: 0x0001_0000)])).ttl, 300)
    }

    func testWrongRDataLengthIsSkipped() {
        let bogus = Answer(type: 1, ttl: 60, rdata: Data([1, 2, 3]))
        XCTAssertEqual(resolver.parseDNSResponse(data: response(answers: [bogus, .a([5, 6, 7, 8])])).ips, ["5.6.7.8"])
    }

    func testErrorRcodesYieldNoAddresses() {
        XCTAssertEqual(resolver.parseDNSResponse(data: response(rcode: 3, answers: [])).ips, [])
        // SERVFAIL is rejected even if an answer is present.
        XCTAssertEqual(resolver.parseDNSResponse(data: response(rcode: 2, answers: [.a([1, 2, 3, 4])])).ips, [])
    }

    func testShortOrEmptyDataIsSafe() {
        XCTAssertEqual(resolver.parseDNSResponse(data: Data()).ips, [])
        XCTAssertEqual(resolver.parseDNSResponse(data: Data(repeating: 0, count: 11)).ips, [])
    }

    func testEveryTruncationIsSafe() {
        let full = response(answers: [.a([93, 184, 216, 34]), .aaaa(Array(repeating: 0xAB, count: 16))])
        for length in 0...full.count {
            let result = resolver.parseDNSResponse(data: full.prefix(length))
            XCTAssertLessThanOrEqual(result.ips.count, 2)
        }
        XCTAssertEqual(resolver.parseDNSResponse(data: full).ips.count, 2)
    }

    func testSelfReferencingPointerTerminates() {
        // Question name is a pointer to itself (offset 12). The parser skips pointers without
        // following them, so it can't loop.
        var data = Data([0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
        data += [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]
        data += [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 9, 9, 9, 9]
        XCTAssertEqual(resolver.parseDNSResponse(data: data).ips, ["9.9.9.9"])
    }

    func testHugeCountsOnTinyMessageAreSafe() {
        let data = Data([0x12, 0x34, 0x81, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3F])
        XCTAssertEqual(resolver.parseDNSResponse(data: data).ips, [])
    }
}

final class DNSCacheTests: XCTestCase {
    private var now = Date(timeIntervalSince1970: 1_000_000)
    private lazy var cache = DNSCache(now: { [unowned self] in self.now })

    func testHitBeforeExpiryMissAfter() {
        cache.set(domain: "example.com", ips: ["1.2.3.4"], ttl: 60)
        now += 60
        XCTAssertEqual(cache.get(domain: "example.com"), ["1.2.3.4"], "still valid at exactly ttl")
        now += 1
        XCTAssertNil(cache.get(domain: "example.com"))
    }

    func testOverwriteRefreshesEntry() {
        cache.set(domain: "example.com", ips: ["1.1.1.1"], ttl: 10)
        now += 5
        cache.set(domain: "example.com", ips: ["2.2.2.2"], ttl: 10)
        now += 8
        XCTAssertEqual(cache.get(domain: "example.com"), ["2.2.2.2"])
    }

    func testCapacityEvictsSoonestToExpireQuarter() {
        for i in 0..<500 {
            cache.set(domain: "host\(i)", ips: ["10.0.0.1"], ttl: UInt32(1000 + i))
        }
        cache.set(domain: "new", ips: ["10.0.0.2"], ttl: 1)
        XCTAssertNil(cache.get(domain: "host0"))
        XCTAssertNil(cache.get(domain: "host124"))
        XCTAssertNotNil(cache.get(domain: "host125"))
        XCTAssertNotNil(cache.get(domain: "host499"))
        XCTAssertNotNil(cache.get(domain: "new"))
    }
}
