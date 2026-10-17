import Foundation
import os.log

/// DNS-over-HTTPS resolver. Builds a DNS wire-format query, sends it via GET to a DoH endpoint,
/// and parses A/AAAA records from the response.
final class DoHResolver: Resolver {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "DoH")

    /// Fetches a URL and calls back with the body of a 200 response, or nil. Injectable for tests.
    typealias Transport = (URLRequest, @escaping (Data?) -> Void) -> Void

    private let serverURL: String
    private let transport: Transport
    private let cache: DNSCache

    convenience init(serverURL: String) {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 5
        config.connectionProxyDictionary = [:] // Bypass tunnel proxy to avoid circular dependency
        let session = URLSession(configuration: config)
        self.init(serverURL: serverURL) { request, completion in
            session.dataTask(with: request) { data, response, error in
                if let error {
                    Self.logger.error("DoH request failed: \(error.localizedDescription)")
                    return completion(nil)
                }
                guard (response as? HTTPURLResponse)?.statusCode == 200, let data else {
                    Self.logger.error("DoH bad response")
                    return completion(nil)
                }
                completion(data)
            }.resume()
        }
    }

    init(serverURL: String, cache: DNSCache = DNSCache(), transport: @escaping Transport) {
        self.serverURL = serverURL.hasPrefix("https://") ? serverURL : "https://\(serverURL)/dns-query"
        self.transport = transport
        self.cache = cache
    }

    /// Resolve a domain to IP addresses (A then AAAA). Returns cached results when available.
    /// `completion` always runs asynchronously on `queue` (the caller's session queue).
    func resolve(domain: String, on queue: DispatchQueue, completion: @escaping ([String]?) -> Void) {
        // N10: an IP literal (bracketed IPv6 too) is its own answer; never query for it.
        let bare = domain.hasPrefix("[") && domain.hasSuffix("]") ? String(domain.dropFirst().dropLast()) : domain
        if ServerConnector.isIPLiteral(bare) {
            queue.async { completion([bare]) }
            return
        }
        resolve(domain: domain) { ips in
            queue.async { completion(ips) }
        }
    }

    /// Calls `completion` on the caller's thread for a cache hit, otherwise on a transport queue.
    private func resolve(domain: String, completion: @escaping ([String]?) -> Void) {
        if let cached = cache.get(domain: domain) {
            completion(cached)
            return
        }

        // N10: query A and AAAA in parallel, so IPv6-only hosts resolve too.
        let group = DispatchGroup()
        let lock = NSLock()
        var answers: [UInt16: (ips: [String], ttl: UInt32)] = [:]
        let qtypes: [UInt16] = [1, 28]
        let requests = qtypes.compactMap { makeRequest(domain: domain, qtype: $0) }
        guard requests.count == qtypes.count else {
            completion(nil)
            return
        }
        for (qtype, request) in zip(qtypes, requests) {
            group.enter()
            transport(request) { [weak self] data in
                if let self, let data {
                    let answer = self.parseDNSResponse(data: data)
                    lock.withLock { answers[qtype] = answer }
                }
                group.leave()
            }
        }

        group.notify(queue: .global()) { [weak self] in
            let (v4, v6) = lock.withLock { (answers[1], answers[28]) }
            let ips = (v4?.ips ?? []) + (v6?.ips ?? [])
            guard let self, !ips.isEmpty else { return completion(nil) }
            let ttl = [v4, v6].compactMap { $0 }.filter { !$0.ips.isEmpty }.map(\.ttl).min() ?? 300
            self.cache.set(domain: domain, ips: ips, ttl: ttl)
            completion(ips)
        }
    }

    private func makeRequest(domain: String, qtype: UInt16) -> URLRequest? {
        guard let query = buildDNSQuery(domain: domain, qtype: qtype) else {
            Self.logger.error("Invalid domain name for DNS query: \(domain)")
            return nil
        }
        var urlString = serverURL
        if !urlString.contains("/dns-query") && !urlString.contains("?") {
            urlString += "/dns-query"
        }
        urlString += "?dns=\(query.base64URLEncoded())"
        guard let url = URL(string: urlString) else {
            Self.logger.error("Invalid DoH URL: \(urlString)")
            return nil
        }
        var request = URLRequest(url: url)
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        return request
    }

    // MARK: - DNS Wire Format

    /// Build a minimal DNS query in wire format.
    /// Returns nil when the name can't be encoded (empty, label > 63 bytes, name > 253 bytes).
    func buildDNSQuery(domain: String, qtype: UInt16) -> Data? {
        let labels = domain.split(separator: ".").map { Array($0.utf8) }
        guard !labels.isEmpty,
              labels.allSatisfy({ $0.count <= 63 }),
              labels.reduce(labels.count - 1, { $0 + $1.count }) <= 253 else {
            return nil
        }

        var data = Data()

        // Transaction ID (random)
        data.appendUInt16(UInt16.random(in: 0...UInt16.max))

        // Flags: standard query, recursion desired
        data.appendUInt16(0x0100)

        // Questions: 1
        data.appendUInt16(1)
        // Answer, Authority, Additional: 0
        data.appendUInt16(0)
        data.appendUInt16(0)
        data.appendUInt16(0)

        // Question: domain name
        for label in labels {
            data.append(UInt8(label.count))
            data.append(contentsOf: label)
        }
        data.append(0) // Root label

        // QTYPE
        data.appendUInt16(qtype)
        // QCLASS: IN
        data.appendUInt16(1)

        return data
    }

    /// Parse a DNS response, extracting A and AAAA record IPs and minimum TTL.
    func parseDNSResponse(data: Data) -> (ips: [String], ttl: UInt32) {
        guard data.count >= 12 else { return ([], 300) }

        // Check RCODE (lower 4 bits of byte 3)
        let rcode = data[3] & 0x0F
        guard rcode == 0 || rcode == 3 else { return ([], 300) } // 0=OK, 3=NXDOMAIN

        let qdcount = Int(data.readUInt16(at: 4))
        let ancount = Int(data.readUInt16(at: 6))

        var offset = 12

        // Skip questions
        for _ in 0..<qdcount {
            offset = skipDNSName(data: data, offset: offset)
            offset += 4 // QTYPE + QCLASS
        }

        var ips: [String] = []
        var minTTL: UInt32 = 300

        // Parse answers
        for _ in 0..<ancount {
            guard offset < data.count else { break }

            offset = skipDNSName(data: data, offset: offset)
            guard offset + 10 <= data.count else { break }

            let atype = data.readUInt16(at: offset)
            let ttl = UInt32(data.readUInt16(at: offset + 4)) << 16 | UInt32(data.readUInt16(at: offset + 6))
            let rdlength = Int(data.readUInt16(at: offset + 8))
            offset += 10

            guard offset + rdlength <= data.count else { break }

            if atype == 1 && rdlength == 4 {
                // A record
                let ip = "\(data[offset]).\(data[offset+1]).\(data[offset+2]).\(data[offset+3])"
                ips.append(ip)
                minTTL = min(minTTL, max(ttl, 30))
            } else if atype == 28 && rdlength == 16 {
                // AAAA record
                var parts: [String] = []
                for i in stride(from: 0, to: 16, by: 2) {
                    let val = data.readUInt16(at: offset + i)
                    parts.append(String(val, radix: 16))
                }
                ips.append(parts.joined(separator: ":"))
                minTTL = min(minTTL, max(ttl, 30))
            }

            offset += rdlength
        }

        return (ips, minTTL)
    }

    /// Skip a DNS name (handling compression pointers).
    private func skipDNSName(data: Data, offset: Int) -> Int {
        var pos = offset
        while pos < data.count {
            let len = Int(data[pos])
            if len == 0 {
                return pos + 1
            }
            if len & 0xC0 == 0xC0 {
                // Compression pointer - 2 bytes total
                return pos + 2
            }
            pos += 1 + len
        }
        return pos
    }
}

// MARK: - Data Extensions for DNS

extension Data {
    mutating func appendUInt16(_ value: UInt16) {
        append(UInt8(value >> 8))
        append(UInt8(value & 0xFF))
    }

    func base64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
