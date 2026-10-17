import Foundation

/// Parses Shadowsocks `ss://` URIs (SIP002 and legacy formats) into OutlineServerConfig.
enum OutlineAccessKey {
    enum ParseError: Error, Equatable, CustomStringConvertible {
        case notAnAccessKey
        case unsupportedCipher(String)
        case invalidPrefix
        /// outline-sdk rejects a prefix longer than the salt ("prefix is too long", N2).
        case prefixTooLong(Int, max: Int)

        var description: String {
            switch self {
            case .notAnAccessKey: return "Invalid access key"
            case .unsupportedCipher(let method): return "Unsupported cipher \"\(method)\" (use chacha20-ietf-poly1305 or aes-256-gcm)"
            case .invalidPrefix: return "Invalid prefix: every character must be in U+0000…U+00FF"
            case .prefixTooLong(let count, let max): return "Prefix is \(count) bytes; at most \(max) are allowed"
            }
        }
    }

    /// Parses an `ss://` URI into an OutlineServerConfig.
    ///
    /// Supports:
    /// - **SIP002**: `ss://BASE64URL(method:password)@host:port/?query#fragment`
    /// - **Legacy**: `ss://BASE64(method:password@host:port)#fragment`
    ///
    /// Query params: `prefix=<url-encoded code points>`, `outline=1`
    static func decode(_ uri: String) throws -> OutlineServerConfig {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("ss://") else { throw ParseError.notAnAccessKey }
        let body = String(trimmed.dropFirst(5))

        // Split off fragment (#name)
        let (mainPart, _) = splitFragment(body)

        // Try SIP002 first, then legacy
        guard let config = try parseSIP002(mainPart) ?? parseLegacy(mainPart) else { throw ParseError.notAnAccessKey }
        return config
    }

    static func parse(_ uri: String) -> OutlineServerConfig? {
        try? decode(uri)
    }

    // MARK: - SIP002

    private static func parseSIP002(_ input: String) throws -> OutlineServerConfig? {
        // SIP002: base64url(method:password)@host:port/?query
        // Find the last '@' to split userinfo from host (password could contain '@' in theory)
        guard let atIndex = input.lastIndex(of: "@") else { return nil }

        let userinfoPart = String(input[input.startIndex..<atIndex])
        let hostPart = String(input[input.index(after: atIndex)...])

        // Decode userinfo (base64url-encoded "method:password")
        guard let decoded = Data(base64URLEncodedLenient: userinfoPart),
              let userinfoString = String(data: decoded, encoding: .utf8) else {
            return nil
        }

        // Split on first ':' → method + password
        guard let colonIndex = userinfoString.firstIndex(of: ":") else { return nil }
        let method = String(userinfoString[userinfoString.startIndex..<colonIndex])
        let password = String(userinfoString[userinfoString.index(after: colonIndex)...])

        guard let cipher = ShadowsocksCipher(rawValue: method) else { throw ParseError.unsupportedCipher(method) }

        // Parse host:port and optional query string
        let (hostPort, query) = splitQuery(hostPart)
        guard let (host, port) = parseHostPort(hostPort) else { return nil }

        // Parse query params
        let prefix = try parsePrefix(from: query)
        let maxPrefix = ShadowsocksCrypto.saltLength(for: cipher)
        if let prefix, prefix.count > maxPrefix { throw ParseError.prefixTooLong(prefix.count, max: maxPrefix) }

        return OutlineServerConfig(
            host: host,
            port: port,
            password: password,
            cipher: cipher,
            prefix: prefix
        )
    }

    // MARK: - Legacy

    private static func parseLegacy(_ input: String) throws -> OutlineServerConfig? {
        // Legacy: base64(method:password@host:port)
        // Strip any query string first
        let (mainPart, _) = splitQuery(input)

        guard let decoded = Data(base64URLEncodedLenient: mainPart),
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

        guard let cipher = ShadowsocksCipher(rawValue: method) else { throw ParseError.unsupportedCipher(method) }
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

    /// Like outline-sdk (`url.Query().Get("prefix")`, then `configurl.parseStringPrefix`): the
    /// value is query-unescaped to a UTF-8 string and each code point becomes one byte, so
    /// `%C2%A8` (U+00A8) is the byte 0xA8 (N13). A code point above U+00FF is an error.
    private static func parsePrefix(from query: String?) throws -> Data? {
        guard let query = query else { return nil }
        for pair in query.split(separator: "&", omittingEmptySubsequences: true) {
            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard queryUnescape(kv[0]).flatMap({ String(bytes: $0, encoding: .utf8) }) == "prefix" else { continue }
            guard let bytes = queryUnescape(kv.count == 2 ? kv[1] : ""),
                  let text = String(bytes: bytes, encoding: .utf8) else { throw ParseError.invalidPrefix }
            var prefix = Data()
            for scalar in text.unicodeScalars {
                guard scalar.value <= 0xFF else { throw ParseError.invalidPrefix }
                prefix.append(UInt8(scalar.value))
            }
            return prefix
        }
        return nil
    }

    /// Go's `url.QueryUnescape`: `%HH` is a byte, `+` is a space, anything else is its UTF-8.
    /// A malformed escape is an error.
    private static func queryUnescape(_ input: Substring) -> Data? {
        var result = Data()
        var bytes = Array(input.utf8)[...]
        while let byte = bytes.popFirst() {
            switch byte {
            case UInt8(ascii: "%"):
                let digits = bytes.prefix(2)
                guard digits.count == 2, digits.allSatisfy({ Character(Unicode.Scalar($0)).isHexDigit }),
                      let value = UInt8(String(decoding: digits, as: UTF8.self), radix: 16) else { return nil }
                result.append(value)
                bytes = bytes.dropFirst(2)
            case UInt8(ascii: "+"):
                result.append(UInt8(ascii: " "))
            default:
                result.append(byte)
            }
        }
        return result
    }
}
