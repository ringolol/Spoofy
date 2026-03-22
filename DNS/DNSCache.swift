import Foundation

/// Simple DNS cache with TTL support, capped at 500 entries.
final class DNSCache {
    private struct Entry {
        let ips: [String]
        let expiry: Date
    }

    private var cache: [String: Entry] = [:]
    private let lock = NSLock()
    private let maxEntries = 500

    func get(domain: String) -> [String]? {
        lock.lock()
        defer { lock.unlock() }

        guard let entry = cache[domain] else { return nil }

        if Date() > entry.expiry {
            cache.removeValue(forKey: domain)
            return nil
        }

        return entry.ips
    }

    func set(domain: String, ips: [String], ttl: UInt32) {
        lock.lock()
        defer { lock.unlock() }

        // Evict oldest entries if over capacity
        if cache.count >= maxEntries {
            let sortedKeys = cache.sorted { $0.value.expiry < $1.value.expiry }
            for (key, _) in sortedKeys.prefix(maxEntries / 4) {
                cache.removeValue(forKey: key)
            }
        }

        cache[domain] = Entry(
            ips: ips,
            expiry: Date().addingTimeInterval(TimeInterval(ttl))
        )
    }
}
