import Foundation

/// Parses Shadowsocks `ss://` URIs (SIP002 and legacy formats) into OutlineServerConfig.
enum OutlineAccessKey {

    /// Parses an `ss://` URI into an OutlineServerConfig.
    ///
    /// Supports:
    /// - **SIP002**: `ss://BASE64URL(method:password)@host:port/?query#fragment`
    /// - **Legacy**: `ss://BASE64(method:password@host:port)#fragment`
    ///
    /// Query params: `prefix=<url-encoded bytes>`, `outline=1`
    static func parse(_ uri: String) -> OutlineServerConfig? {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("ss://") else { return nil }
        let body = String(trimmed.dropFirst(5))

        // Split off fragment (#name)
        let (mainPart, _) = splitFragment(body)

        // Try SIP002 first, then legacy
        return parseSIP002(mainPart) ?? parseLegacy(mainPart)
    }

    // MARK: - SIP002

    private static func parseSIP002(_ input: String) -> OutlineServerConfig? {
        // SIP002: base64url(method:password)@host:port/?query
        // Find the last '@' to split userinfo from host (password could contain '@' in theory)
        guard let atIndex = input.lastIndex(of: "@") else { return nil }

        let userinfoPart = String(input[input.startIndex..<atIndex])
        let hostPart = String(input[input.index(after: atIndex)...])

        // Decode userinfo (base64url-encoded "method:password")
        guard let decoded = base64URLDecode(userinfoPart),
              let userinfoString = String(data: decoded, encoding: .utf8) else {
            return nil
        }

        // Split on first ':' → method + password
        guard let colonIndex = userinfoString.firstIndex(of: ":") else { return nil }
        let method = String(userinfoString[userinfoString.startIndex..<colonIndex])
        let password = String(userinfoString[userinfoString.index(after: colonIndex)...])

        guard let cipher = ShadowsocksCipher(rawValue: method) else { return nil }

        // Parse host:port and optional query string
        let (hostPort, query) = splitQuery(hostPart)
        guard let (host, port) = parseHostPort(hostPort) else { return nil }

        // Parse query params
        let prefix = parsePrefix(from: query)

        return OutlineServerConfig(
            host: host,
            port: port,
            password: password,
            cipher: cipher,
            prefix: prefix
        )
    }

    // MARK: - Legacy

    private static func parseLegacy(_ input: String) -> OutlineServerConfig? {
        // Legacy: base64(method:password@host:port)
        // Strip any query string first
        let (mainPart, _) = splitQuery(input)

        guard let decoded = base64Decode(mainPart),
              let decodedString = String(data: decoded, encoding: .utf8) else {
            return nil
        }

        // Split on last '@' → method:password and host:port
        guard let atIndex = decodedString.lastIndex(of: "@") else { return nil }
        let credentials = String(decodedString[decodedString.startIndex..<atIndex])
        let hostPortStr = String(decodedString[decodedString.index(after: atIndex)...])

        // Split credentials on first ':'
        guard let colonIndex = credentials.firstIndex(of: ":") else { return nil }
        let method = String(credentials[credentials.startIndex..<colonIndex])
        let password = String(credentials[credentials.index(after: colonIndex)...])

        guard let cipher = ShadowsocksCipher(rawValue: method) else { return nil }
        guard let (host, port) = parseHostPort(hostPortStr) else { return nil }

        return OutlineServerConfig(
            host: host,
            port: port,
            password: password,
            cipher: cipher,
            prefix: nil
        )
    }

    // MARK: - Helpers

    private static func splitFragment(_ input: String) -> (main: String, fragment: String?) {
        guard let hashIndex = input.lastIndex(of: "#") else { return (input, nil) }
        let main = String(input[input.startIndex..<hashIndex])
        let fragment = String(input[input.index(after: hashIndex)...])
        return (main, fragment)
    }

    private static func splitQuery(_ input: String) -> (path: String, query: String?) {
        // Handle both /? and ? as query separator
        if let qIndex = input.firstIndex(of: "?") {
            var pathEnd = qIndex
            if pathEnd > input.startIndex && input[input.index(before: pathEnd)] == "/" {
                pathEnd = input.index(before: pathEnd)
            }
            let path = String(input[input.startIndex..<pathEnd])
            let query = String(input[input.index(after: qIndex)...])
            return (path, query)
        }
        return (input, nil)
    }

    private static func parseHostPort(_ input: String) -> (host: String, port: UInt16)? {
        // Handle IPv6: [host]:port
        if input.hasPrefix("[") {
            guard let closeBracket = input.firstIndex(of: "]") else { return nil }
            let host = String(input[input.index(after: input.startIndex)..<closeBracket])
            let afterBracket = input.index(after: closeBracket)
            guard afterBracket < input.endIndex, input[afterBracket] == ":" else { return nil }
            let portStr = String(input[input.index(after: afterBracket)...])
            guard let port = UInt16(portStr) else { return nil }
            return (host, port)
        }

        // IPv4 or domain: host:port (split on last ':' to handle edge cases)
        guard let colonIndex = input.lastIndex(of: ":") else { return nil }
        let host = String(input[input.startIndex..<colonIndex])
        let portStr = String(input[input.index(after: colonIndex)...])
        guard !host.isEmpty, let port = UInt16(portStr) else { return nil }
        return (host, port)
    }

    private static func parsePrefix(from query: String?) -> Data? {
        guard let query = query else { return nil }
        // Parse query params manually
        let pairs = query.split(separator: "&", omittingEmptySubsequences: true)
        for pair in pairs {
            let kv = pair.split(separator: "=", maxSplits: 1)
            guard kv.count == 2, kv[0] == "prefix" else { continue }
            let value = String(kv[1])
            return urlDecodeBytes(value)
        }
        return nil
    }

    /// URL-decodes a string into raw bytes. Percent-encoded bytes (%HH) are decoded
    /// to their byte values; other characters are encoded as UTF-8.
    private static func urlDecodeBytes(_ input: String) -> Data {
        var result = Data()
        var i = input.startIndex
        while i < input.endIndex {
            if input[i] == "%" {
                let hi = input.index(after: i)
                let lo = input.index(after: hi)
                guard hi < input.endIndex, lo < input.endIndex,
                      let byte = UInt8(String(input[hi...lo]), radix: 16) else {
                    result.append(contentsOf: Array(String(input[i]).utf8))
                    i = input.index(after: i)
                    continue
                }
                result.append(byte)
                i = input.index(after: lo)
            } else {
                result.append(contentsOf: Array(String(input[i]).utf8))
                i = input.index(after: i)
            }
        }
        return result
    }

    // MARK: - Base64

    private static func base64URLDecode(_ input: String) -> Data? {
        var base64 = input
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Add padding if needed
        let remainder = base64.count % 4
        if remainder != 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }

    private static func base64Decode(_ input: String) -> Data? {
        var padded = input
        let remainder = padded.count % 4
        if remainder != 0 {
            padded.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: padded)
    }
}
