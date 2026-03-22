import Foundation

struct HTTPRequestLine {
    let method: String
    let host: String
    let port: UInt16
    let isConnect: Bool
    /// The raw bytes of the full HTTP request (for forwarding plain HTTP).
    let rawData: Data

    private static let validMethods: Set<String> = [
        "DELETE", "GET", "HEAD", "POST", "PUT",
        "CONNECT", "OPTIONS", "TRACE",
        "COPY", "LOCK", "MKCOL", "MOVE",
        "PROPFIND", "PROPPATCH", "SEARCH", "UNLOCK",
        "BIND", "REBIND", "UNBIND",
        "ACL", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE",
        "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE",
        "PATCH", "PURGE", "MKCALENDAR", "LINK", "UNLINK",
    ]

    var isValidMethod: Bool {
        HTTPRequestLine.validMethods.contains(method)
    }

    /// Parse an HTTP request line from raw data.
    /// Expects at least the first line: "METHOD host:port HTTP/1.x\r\n" or "METHOD http://host/path HTTP/1.x\r\n"
    static func parse(from data: Data) -> HTTPRequestLine? {
        // Find the end of the first line
        guard let headerEnd = data.firstRange(of: Data("\r\n".utf8)) else { return nil }

        guard let firstLine = String(data: data[data.startIndex..<headerEnd.lowerBound], encoding: .utf8) else {
            return nil
        }

        let parts = firstLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return nil }

        let method = String(parts[0]).uppercased()
        let target = String(parts[1])
        let isConnect = method == "CONNECT"

        let (host, port) = parseHostPort(from: target, isConnect: isConnect)

        return HTTPRequestLine(
            method: method,
            host: host,
            port: port,
            isConnect: isConnect,
            rawData: data
        )
    }

    private static func parseHostPort(from target: String, isConnect: Bool) -> (String, UInt16) {
        var hostStr = target

        // Strip scheme if present (e.g. "http://host/path")
        if let schemeRange = hostStr.range(of: "://") {
            hostStr = String(hostStr[schemeRange.upperBound...])
        }

        // Strip path if present
        if let slashIdx = hostStr.firstIndex(of: "/") {
            hostStr = String(hostStr[hostStr.startIndex..<slashIdx])
        }

        // Check for [IPv6]:port format
        if hostStr.hasPrefix("[") {
            if let closeBracket = hostStr.firstIndex(of: "]") {
                let afterBracket = hostStr.index(after: closeBracket)
                let ipv6 = String(hostStr[hostStr.index(after: hostStr.startIndex)..<closeBracket])
                if afterBracket < hostStr.endIndex && hostStr[afterBracket] == ":" {
                    let portStr = String(hostStr[hostStr.index(after: afterBracket)...])
                    let port = UInt16(portStr) ?? (isConnect ? 443 : 80)
                    return (ipv6, port)
                }
                return (ipv6, isConnect ? 443 : 80)
            }
        }

        // Regular host:port
        if let colonIdx = hostStr.lastIndex(of: ":") {
            let host = String(hostStr[hostStr.startIndex..<colonIdx])
            let portStr = String(hostStr[hostStr.index(after: colonIdx)...])
            if let port = UInt16(portStr) {
                return (host, port)
            }
        }

        return (hostStr, isConnect ? 443 : 80)
    }
}
