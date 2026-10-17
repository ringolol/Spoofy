import Foundation

/// The host patterns of one profile (plan §6.6), compared label by label. Built once per config
/// snapshot, not per connection.
///
/// - `example.com`: exactly that host.
/// - `*.example.com`: `example.com` and any subdomain of it.
/// - `example.*`: `example` followed by any labels (`example.com`, `example.co.uk`).
/// - `*.google.*`: the label `google` anywhere in the host (U3: not `notgoogle.org`). The middle
///   may be several labels (`*.youtube.googleapis.*`).
/// - `*.*`: every host.
/// - `*`, an empty pattern, or one with an empty label (`.example.com`): nothing.
///
/// Case, surrounding whitespace and trailing dots are ignored on both sides.
struct DomainMatcher: Equatable {
    private struct Pattern: Equatable {
        let labels: [String]
        let anyBefore: Bool
        let anyAfter: Bool

        init?(_ text: String) {
            var labels = DomainMatcher.labels(of: text).map(String.init)
            let anyBefore = labels.first == "*"
            if anyBefore { labels.removeFirst() }
            let anyAfter = labels.last == "*"
            if anyAfter { labels.removeLast() }
            // `*` alone is only ever the leading wildcard; with nothing fixed it would match everything.
            if labels.isEmpty && !(anyBefore && anyAfter) { return nil }
            if labels.contains(where: \.isEmpty) { return nil }
            self.labels = labels
            self.anyBefore = anyBefore
            self.anyAfter = anyAfter
        }

        func matches(_ host: [Substring]) -> Bool {
            let n = labels.count
            switch (anyBefore, anyAfter) {
            case (false, false): return host.count == n && Self.equal(host[...], labels)
            case (true, false): return host.count >= n && Self.equal(host.suffix(n), labels)
            case (false, true): return host.count >= n && Self.equal(host.prefix(n), labels)
            case (true, true):
                guard n > 0 else { return true }
                guard host.count >= n else { return false }
                return (0...(host.count - n)).contains { Self.equal(host[$0..<($0 + n)], labels) }
            }
        }

        private static func equal(_ host: ArraySlice<Substring>, _ labels: [String]) -> Bool {
            zip(host, labels).allSatisfy { $0 == $1 }
        }
    }

    private let patterns: [Pattern]

    init(patterns: [String]) {
        self.patterns = patterns.compactMap(Pattern.init)
    }

    /// True when no pattern can match anything (a profile with no usable patterns).
    var isEmpty: Bool { patterns.isEmpty }

    func matches(_ host: String) -> Bool {
        matches(labels: Self.labels(of: host))
    }

    /// For callers that test one host against many matchers: split it once with `labels(of:)`.
    func matches(labels host: [Substring]) -> Bool {
        patterns.contains { $0.matches(host) }
    }

    static func labels(of name: String) -> [Substring] {
        var trimmed = Substring(name.trimmingCharacters(in: .whitespaces).lowercased())
        while trimmed.hasSuffix(".") { trimmed = trimmed.dropLast() }
        return trimmed.split(separator: ".", omittingEmptySubsequences: false)
    }
}
