import Foundation

/// What a tunnel turned out to carry (network-scanner plan §2.5.2). Set once per connection, from
/// the first payload in either direction.
enum PayloadKind: Equatable, Sendable {
    /// The first record is a ClientHello.
    case tls(ClientHelloInfo)
    /// 0x16 0x03 but not a parsable ClientHello.
    case tlsOther
    case http(method: String, host: String?)
    case ssh
    /// The client stayed silent and the server spoke first.
    case serverFirst(ServerGreeting)
    /// At most 8 bytes, for the detail view only.
    case unknown(firstBytes: Data)
    /// Nothing was sent either way.
    case none

    /// For row chips and grouping.
    var tag: PayloadKindTag {
        switch self {
        case .tls, .tlsOther: return .tls
        case .http: return .http
        case .ssh: return .ssh
        case .serverFirst(.smtpOrFTP): return .smtp
        case .serverFirst(.imap): return .imap
        case .serverFirst(.pop3): return .pop3
        case .serverFirst(.other), .unknown: return .tcp
        case .none: return .none
        }
    }
}

enum ServerGreeting: Equatable, Sendable {
    /// "220"
    case smtpOrFTP
    /// "* OK"
    case imap
    /// "+OK"
    case pop3
    case other
}

enum PayloadKindTag: String, Sendable {
    case tls = "TLS", http = "HTTP", ssh = "SSH", smtp = "SMTP", imap = "IMAP", pop3 = "POP3", tcp = "TCP", none = "-"
}

/// Pure: names the protocol from the first bytes of a connection.
enum PayloadSniffer {
    private static let methods: Set<String> = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"]

    static func sniff(client bytes: Data) -> PayloadKind {
        let bytes = Data(bytes)
        guard !bytes.isEmpty else { return .none }
        if bytes.count >= 3, bytes[0] == 0x16, bytes[1] == 0x03, bytes[2] <= 0x04 {
            return ClientHelloInfo.parse(record: bytes).map(PayloadKind.tls) ?? .tlsOther
        }
        if let space = bytes.prefix(8).firstIndex(of: 0x20),
           case let method = String(decoding: bytes[..<space], as: UTF8.self), methods.contains(method) {
            return .http(method: method, host: hostHeader(in: bytes))
        }
        if bytes.starts(with: Data("SSH-".utf8)) { return .ssh }
        return .unknown(firstBytes: Data(bytes.prefix(8)))
    }

    static func sniff(server bytes: Data) -> PayloadKind {
        guard !bytes.isEmpty else { return .none }
        if bytes.starts(with: Data("220".utf8)) { return .serverFirst(.smtpOrFTP) }
        if bytes.starts(with: Data("* OK".utf8)) { return .serverFirst(.imap) }
        if bytes.starts(with: Data("+OK".utf8)) { return .serverFirst(.pop3) }
        return .serverFirst(.other)
    }

    private static func hostHeader(in bytes: Data) -> String? {
        let text = String(decoding: bytes.prefix(4096), as: UTF8.self)
        for line in text.components(separatedBy: "\r\n").dropFirst() {
            if line.isEmpty { break }
            guard let colon = line.firstIndex(of: ":"),
                  line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "host" else { continue }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : value
        }
        return nil
    }
}
