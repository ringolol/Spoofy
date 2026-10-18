import Foundation
import Network

/// HTTP proxy request head: CONNECT and absolute-form plain HTTP (plan §6.4.1).
///
/// The head is read incrementally up to `maxHead` bytes (N9: a long head, or one split over
/// several reads, used to get a 400). A plain-HTTP request is rewritten to origin-form with the
/// proxy hop-by-hop headers removed and `Connection: close` added, so each upstream connection
/// carries exactly one request and a keep-alive client can't reach a second host through it.
struct HTTPHeadParser: InboundParser {
    static let maxHead = 65_536

    private static let terminator = Data("\r\n\r\n".utf8)
    /// Hop-by-hop headers of the client↔proxy hop; `Connection: close` replaces them.
    private static let droppedHeaders: Set<String> = ["proxy-connection", "proxy-authorization", "connection", "keep-alive"]

    private var buffer = Data()

    mutating func feed(_ chunk: Data) -> InboundStep {
        buffer.append(chunk)
        guard let end = buffer.firstRange(of: Self.terminator) else {
            return buffer.count > Self.maxHead ? Self.fail(431, "Request Header Fields Too Large", .headTooLarge) : .needMore
        }
        let headLength = end.upperBound - buffer.startIndex
        guard headLength <= Self.maxHead else {
            return Self.fail(431, "Request Header Fields Too Large", .headTooLarge)
        }
        let head = Data(buffer[buffer.startIndex..<end.upperBound])
        let leftover = Data(buffer[end.upperBound...])
        buffer = Data()
        return Self.parse(head: head, leftover: leftover)
    }

    // MARK: - Responses

    static func response(_ status: Int, _ reason: String) -> Data {
        Data("HTTP/1.1 \(status) \(reason)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8)
    }

    static let connectEstablished = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)

    private static func fail(_ status: Int, _ reason: String, _ why: InboundFailure) -> InboundStep {
        .fail(reply: response(status, reason), reason: why)
    }

    // MARK: - Parsing

    /// `head` ends with CRLF CRLF.
    private static func parse(head: Data, leftover: Data) -> InboundStep {
        // Lines without their CRLF; the last two are the empty lines of the terminator.
        var lines = head.split(separator: Data("\r\n".utf8), omittingEmptySubsequences: false)
        lines.removeLast(2)
        guard let requestLine = lines.first,
              let line = String(data: requestLine, encoding: .ascii) else {
            return fail(400, "Bad Request", .malformed("request line is not ASCII"))
        }
        if line == "PRI * HTTP/2.0" {
            return fail(400, "Bad Request", .http2Preface)
        }
        let parts = line.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 3,
              !parts[0].isEmpty, parts[0].allSatisfy(isTokenChar),
              parts[2].hasPrefix("HTTP/1.") else {
            return fail(400, "Bad Request", .malformed("malformed request line"))
        }
        let method = String(parts[0])
        let target = parts[1]
        let version = String(parts[2])

        if method.uppercased() == "CONNECT" {
            guard let dialTarget = parseAuthority(target, defaultPort: nil) else {
                return fail(400, "Bad Request", .malformed("bad CONNECT authority"))
            }
            return .request(InboundRequest(target: dialTarget, kind: .tunnel, leftover: leftover))
        }

        guard target.lowercased().hasPrefix("http://") else {
            // Not something a proxy can forward.
            if target.hasPrefix("/") { return fail(400, "Bad Request", .httpOriginForm) }
            if target.lowercased().hasPrefix("https://") { return fail(400, "Bad Request", .httpsAbsoluteForm) }
            return fail(400, "Bad Request", .malformed("not an absolute http:// target"))
        }
        let rest = target.dropFirst("http://".count)
        let authorityEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? rest.endIndex
        var authority = rest[..<authorityEnd]
        if let at = authority.lastIndex(of: "@") {
            authority = authority[authority.index(after: at)...]  // drop userinfo
        }
        guard let dialTarget = parseAuthority(authority, defaultPort: 80) else {
            return fail(400, "Bad Request", .malformed("bad absolute-form authority"))
        }
        var path = String(rest[authorityEnd...].prefix { $0 != "#" })
        if path.isEmpty || path.hasPrefix("?") { path = "/" + path }

        let rewritten = rewrite(method: method, path: path, version: version,
                                headerLines: lines.dropFirst(), authority: authority)
        return .request(InboundRequest(target: dialTarget, kind: .http(head: rewritten), leftover: leftover))
    }

    private static func rewrite(method: String, path: String, version: String,
                                headerLines: ArraySlice<Data>, authority: Substring) -> Data {
        var out = Data("\(method) \(path) \(version)\r\n".utf8)
        var hasHost = false
        var droppingFold = false
        for line in headerLines {
            // obs-fold continuation: belongs to the previous header.
            if let first = line.first, first == 0x20 || first == 0x09 {
                if !droppingFold { out.append(line + Data("\r\n".utf8)) }
                continue
            }
            let name = line.prefix { $0 != UInt8(ascii: ":") }
            let lowered = String(decoding: name, as: UTF8.self).trimmingCharacters(in: .whitespaces).lowercased()
            droppingFold = droppedHeaders.contains(lowered)
            if droppingFold { continue }
            if lowered == "host" { hasHost = true }
            out.append(line + Data("\r\n".utf8))
        }
        if !hasHost { out.append(Data("Host: \(authority)\r\n".utf8)) }
        out.append(Data("Connection: close\r\n\r\n".utf8))
        return out
    }

    /// `host:port`, `[v6]:port`, or without the port when `defaultPort` is set. The host is at most
    /// 255 bytes (C3: the Shadowsocks address header can't carry more).
    static func parseAuthority(_ authority: Substring, defaultPort: UInt16?) -> DialTarget? {
        let host: Substring
        let portText: Substring?
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            host = authority[authority.index(after: authority.startIndex)..<close]
            guard IPv6Address(String(host)) != nil else { return nil }
            let after = authority[authority.index(after: close)...]
            if after.isEmpty {
                portText = nil
            } else {
                guard after.hasPrefix(":") else { return nil }
                portText = after.dropFirst()
            }
        } else if let colon = authority.lastIndex(of: ":") {
            host = authority[..<colon]
            portText = authority[authority.index(after: colon)...]
            // A bare IPv6 address without brackets is ambiguous.
            guard !host.contains(":") else { return nil }
        } else {
            host = authority
            portText = nil
        }

        let port: UInt16
        if let portText {
            guard !portText.isEmpty, portText.allSatisfy(\.isASCIIDigit),
                  let value = UInt16(portText), value != 0 else { return nil }
            port = value
        } else {
            guard let defaultPort else { return nil }
            port = defaultPort
        }

        guard !host.isEmpty, host.utf8.count <= 255,
              host.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F && $0 != UInt8(ascii: "/") && $0 != UInt8(ascii: "@") }) else {
            return nil
        }
        return DialTarget(host: String(host), port: port)
    }

    /// RFC 9110 tchar.
    private static func isTokenChar(_ c: Character) -> Bool {
        guard let ascii = c.asciiValue else { return false }
        switch ascii {
        case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"):
            return true
        default:
            return "!#$%&'*+-.^_`|~".utf8.contains(ascii)
        }
    }
}

private extension Character {
    var isASCIIDigit: Bool { ("0"..."9").contains(self) }
}
