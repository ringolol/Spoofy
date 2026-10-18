import Foundation

/// The scanner's memory (network-scanner plan §6.1): live sessions, one record per host, a
/// global ring of recent outcomes and the refusals. Owned by the app and handed to every
/// `ProxyServer`, so it survives stop/start; memory only.
///
/// Sessions call in from their own queues. One lock; every critical section is a dictionary
/// update or a copy, so a session never waits long.
final class ConnectionLog: ConnectionObserver {
    static let hostCap = 500
    static let recentPerHost = 8
    static let recentGlobalCap = 300
    static let refusalGroupCap = 32
    static let refusalTargets = 5
    static let ipsPerHost = 4
    static let snisPerHost = 4

    private let config: DetectionConfig
    private let reportWait: TimeInterval
    private let lock = NSLock()
    private var state = LogSnapshot()

    init(config: DetectionConfig = .standard, reportWait: TimeInterval = 1) {
        self.config = config
        self.reportWait = reportWait
    }

    func snapshot() -> LogSnapshot {
        lock.withLock { state }
    }

    /// Forgets hosts and refusals. Live sessions stay listed and land as hosts when they end.
    func clear() {
        lock.withLock {
            let active = state.active
            state = LogSnapshot()
            state.active = active
        }
    }

    // MARK: - ConnectionObserver

    func begin(_ start: TraceStart, queue: DispatchQueue) -> ConnectionTrace? {
        let id = start.id
        lock.withLock {
            state.active[id] = ActiveEntry(id: id, host: start.host, port: start.port, phase: .created,
                                           startedAt: start.startedAt)
        }
        return ConnectionTrace(start, queue: queue, reportWait: reportWait, config: config,
                               onPhase: { [weak self] phase in self?.updateActive(id, phase: phase) },
                               onFinish: { [weak self] summary in self?.complete(summary) })
    }

    func refused(_ record: RefusalRecord) {
        lock.withLock { state.addRefusal(record) }
    }

    // MARK: - From the traces (session queues)

    func updateActive(_ id: UInt64, phase: TracePhase) {
        lock.withLock { state.active[id]?.phase = phase }
    }

    func complete(_ summary: TraceSummary) {
        // Classified outside the lock: pure, and the only work here that isn't a copy.
        let outcome = TraceClassifier.classify(summary, config: config)
        lock.withLock {
            state.active[summary.start.id] = nil
            state.add(ClassifiedTrace(summary: summary, outcome: outcome))
        }
    }
}

/// A copy of the log, safe to read off the main thread.
struct LogSnapshot: Sendable {
    var active: [UInt64: ActiveEntry] = [:]
    /// Keyed by lowercased host.
    var hosts: [String: HostRecord] = [:]
    var recentGlobal = Ring<GlobalOutcome>(capacity: ConnectionLog.recentGlobalCap)
    var refusals: [RefusalGroupKey: RefusalGroup] = [:]

    fileprivate mutating func add(_ trace: ClassifiedTrace) {
        let start = trace.summary.start
        let endedAt = trace.summary.endedDate
        if hosts[start.host] == nil, hosts.count >= ConnectionLog.hostCap,
           let stalest = hosts.min(by: { $0.value.lastSeen < $1.value.lastSeen })?.key {
            hosts[stalest] = nil
        }
        hosts[start.host, default: HostRecord(host: start.host, firstSeen: start.startedAt)].add(trace)
        recentGlobal.append(GlobalOutcome(host: start.host, outcome: trace.outcome, endedAt: endedAt,
                                          outbound: start.outbound, profileID: start.profileID,
                                          profileName: start.profileName))
    }

    fileprivate mutating func addRefusal(_ record: RefusalRecord) {
        let key = record.reason.groupKey
        if refusals[key] == nil, refusals.count >= ConnectionLog.refusalGroupCap,
           let stalest = refusals.min(by: { $0.value.lastSeen < $1.value.lastSeen })?.key {
            refusals[stalest] = nil
        }
        refusals[key, default: RefusalGroup(key: key, firstSeen: record.at)].add(record)
    }
}

struct ActiveEntry: Equatable, Sendable {
    let id: UInt64
    let host: String
    let port: UInt16
    var phase: TracePhase
    let startedAt: Date
}

struct ClassifiedTrace: Sendable {
    let summary: TraceSummary
    let outcome: TraceOutcome
}

struct HostRecord: Sendable {
    let host: String
    let firstSeen: Date
    var lastSeen: Date
    var ports: Set<UInt16> = []
    /// The addresses connected to, at most `ConnectionLog.ipsPerHost`.
    var ips: [String] = []
    /// For IP-literal hosts: the names the client asked for in its ClientHello.
    var snis: Set<String> = []
    var connectionCount = 0
    var bytesUp = 0
    var bytesDown = 0
    var recent = Ring<ClassifiedTrace>(capacity: ConnectionLog.recentPerHost)

    init(host: String, firstSeen: Date) {
        self.host = host
        self.firstSeen = firstSeen
        self.lastSeen = firstSeen
    }

    fileprivate mutating func add(_ trace: ClassifiedTrace) {
        let summary = trace.summary
        lastSeen = max(lastSeen, summary.endedDate)
        ports.insert(summary.start.port)
        if let ip = [summary.connectedAddress, summary.establishment.resolvedIP]
            .compactMap({ $0 }).first(where: ServerConnector.isIPLiteral),
           !ips.contains(ip), ips.count < ConnectionLog.ipsPerHost {
            ips.append(ip)
        }
        if summary.start.isIPLiteral, case .tls(let hello) = summary.kind, let sni = hello.sni,
           snis.count < ConnectionLog.snisPerHost {
            snis.insert(sni.lowercased())
        }
        connectionCount += 1
        bytesUp += summary.bytesUp
        bytesDown += summary.bytesDown
        recent.append(trace)
    }
}

/// One finished connection in the global ring, for the network-state checks (§6.3).
struct GlobalOutcome: Sendable {
    let host: String
    let outcome: TraceOutcome
    let endedAt: Date
    let outbound: TraceOutbound
    let profileID: UUID
    let profileName: String
}

/// Refusals with the same cause, whatever the target (§2.5.4).
enum RefusalGroupKey: Hashable, Sendable {
    case socks5AuthRequired
    case socks5Command(UInt8)
    case socks5AddressType(UInt8)
    case socks4
    case httpOriginForm
    case httpsAbsoluteForm
    case http2Preface
    case headTooLarge
    case malformed
    case routeRejected(profileName: String)
    case overCapacity
}

extension RefusalReason {
    var groupKey: RefusalGroupKey {
        switch self {
        case .handshake(let failure):
            switch failure {
            case .socks5AuthRequired: return .socks5AuthRequired
            case .socks5Command(let command): return .socks5Command(command)
            case .socks5AddressType(let type): return .socks5AddressType(type)
            case .socks4: return .socks4
            case .httpOriginForm: return .httpOriginForm
            case .httpsAbsoluteForm: return .httpsAbsoluteForm
            case .http2Preface: return .http2Preface
            case .headTooLarge: return .headTooLarge
            case .malformed: return .malformed
            }
        case .routeRejected(let name): return .routeRejected(profileName: name)
        case .overCapacity: return .overCapacity
        }
    }
}

struct RefusalGroup: Sendable {
    let key: RefusalGroupKey
    let firstSeen: Date
    var lastSeen: Date
    var count = 0
    /// The latest, for the detail text.
    var lastReason: RefusalReason?
    var lastInbound: InboundProtocol?
    /// The last `ConnectionLog.refusalTargets` distinct targets, newest last.
    var targets: [DialTarget] = []

    init(key: RefusalGroupKey, firstSeen: Date) {
        self.key = key
        self.firstSeen = firstSeen
        self.lastSeen = firstSeen
    }

    fileprivate mutating func add(_ record: RefusalRecord) {
        count += 1
        lastSeen = max(lastSeen, record.at)
        lastReason = record.reason
        if let inbound = record.inbound { lastInbound = inbound }
        if let target = record.target {
            targets.removeAll { $0 == target }
            targets.append(target)
            if targets.count > ConnectionLog.refusalTargets { targets.removeFirst() }
        }
    }
}

/// A fixed-size buffer that drops the oldest element.
struct Ring<Element>: Sendable where Element: Sendable {
    let capacity: Int
    private var storage: [Element] = []
    private var head = 0

    init(capacity: Int) {
        self.capacity = capacity
    }

    var count: Int { storage.count }

    /// Oldest first.
    var elements: [Element] {
        Array(storage[head...] + storage[..<head])
    }

    mutating func append(_ element: Element) {
        if storage.count < capacity {
            storage.append(element)
        } else {
            storage[head] = element
            head = (head + 1) % capacity
        }
    }
}
