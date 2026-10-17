import Foundation
@testable import SpoofyCore

/// Maps names to fixed addresses without a network, and records every lookup.
/// An unmapped name resolves to nil, which makes the dialer fall back to the system resolver.
final class FakeResolver: Resolver {
    private let table: [String: [String]]
    private let delay: TimeInterval
    private let lock = NSLock()
    private var _queries: [String] = []

    var queries: [String] { lock.withLock { _queries } }

    init(_ table: [String: [String]], delay: TimeInterval = 0) {
        self.table = table
        self.delay = delay
    }

    func resolve(domain: String, on queue: DispatchQueue, completion: @escaping ([String]?) -> Void) {
        lock.withLock { _queries.append(domain) }
        let answer = table[domain]
        queue.asyncAfter(deadline: .now() + delay) { completion(answer) }
    }
}
