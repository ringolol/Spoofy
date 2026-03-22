import Foundation
import os.log

/// DNS-over-HTTPS resolver. Builds a DNS wire-format query, sends it via GET to a DoH endpoint,
/// and parses A/AAAA records from the response.
final class DoHResolver {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "DoH")

    private let serverURL: String
    private let session: URLSession
    private let cache: DNSCache

    init(serverURL: String) {
        self.serverURL = serverURL.hasPrefix("https://") ? serverURL : "https://\(serverURL)/dns-query"
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 5
        config.connectionProxyDictionary = [:] // Bypass tunnel proxy to avoid circular dependency
        self.session = URLSession(configuration: config)
        self.cache = DNSCache()
    }

    /// Resolve a domain to IP addresses. Returns cached results when available.
    func resolve(domain: String, completion: @escaping ([String]?) -> Void) {
        // Check cache first
        if let cached = cache.get(domain: domain) {
            completion(cached)
            return
        }

        // Build DNS query for A record
        let query = buildDNSQuery(domain: domain, qtype: 1) // A record
        let encoded = query.base64URLEncoded()

        var urlString = serverURL
        if !urlString.contains("/dns-query") && !urlString.contains("?") {
            urlString += "/dns-query"
        }
        urlString += "?dns=\(encoded)"

        guard let url = URL(string: urlString) else {
            Self.logger.error("Invalid DoH URL: \(urlString)")
            completion(nil)
            return
        }

        var request = URLRequest(url: url)
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")

        let task = session.dataTask(with: request) { [weak self] data, response, error in
            guard let self = self else {
                completion(nil)
                return
            }

            if let error = error {
                Self.logger.error("DoH request failed: \(error.localizedDescription)")
                completion(nil)
                return
            }

            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200,
                  let data = data else {
                Self.logger.error("DoH bad response")
                completion(nil)
                return
            }

            let (ips, ttl) = self.parseDNSResponse(data: data)
            if !ips.isEmpty {
                self.cache.set(domain: domain, ips: ips, ttl: ttl)
            }

            completion(ips.isEmpty ? nil : ips)
        }
        task.resume()
    }

    // MARK: - DNS Wire Format

    /// Build a minimal DNS query in wire format.
    private func buildDNSQuery(domain: String, qtype: UInt16) -> Data {
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
        for label in domain.split(separator: ".") {
            data.append(UInt8(label.count))
            data.append(contentsOf: label.utf8)
        }
        data.append(0) // Root label

        // QTYPE
        data.appendUInt16(qtype)
        // QCLASS: IN
        data.appendUInt16(1)

        return data
    }

    /// Parse a DNS response, extracting A and AAAA record IPs and minimum TTL.
    private func parseDNSResponse(data: Data) -> (ips: [String], ttl: UInt32) {
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
