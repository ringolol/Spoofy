import Foundation

/// The registrable part of a host name, approximately: the last two labels, or three under a
/// known two-level suffix (network-scanner plan §7.4). No public suffix list; wildcards stay
/// editable after saving.
enum BaseDomain {
    private static let twoLevelSuffixes: Set<String> = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
        "com.br", "com.tr", "com.ua", "org.ua", "kiev.ua", "com.ru", "org.ru", "net.ru", "msk.ru", "spb.ru",
        "co.il", "co.kr", "co.nz", "co.za", "co.in", "com.cn", "com.hk", "com.tw", "com.sg", "com.mx",
        "com.ar", "com.by", "com.kz",
    ]

    /// Nil for IP literals and single-label names.
    static func of(_ host: String) -> String? {
        let host = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !ServerConnector.isIPLiteral(host) else { return nil }
        let labels = host.split(separator: ".")
        guard labels.count >= 2 else { return nil }
        let lastTwo = labels.suffix(2).joined(separator: ".")
        if twoLevelSuffixes.contains(lastTwo) {
            return labels.count >= 3 ? labels.suffix(3).joined(separator: ".") : nil
        }
        return lastTwo
    }

    /// `*.example.com` for `www.example.com` and for `example.com`; nil for IPs.
    static func suggestWildcard(for host: String) -> String? {
        of(host).map { "*.\($0)" }
    }
}
