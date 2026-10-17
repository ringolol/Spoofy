import Foundation
import Network
import os.log

/// One accepted client connection, from the first byte to close (plan §6.5). Replaces the
/// HTTP, HTTPS and SOCKS5 handlers. Everything runs on `scope.queue`.
///
/// ```
/// accepted ─▶ handshaking ─▶ connecting ─▶ (desync tunnel) readingFirstFlight ─▶ writingFirstFlight ─┐
///                │               │                                                                  ├─▶ relaying ─▶ closed
///                │               ├──────▶ (other tunnels, plain HTTP) ─────────────────────────────┘
///                └───────────────┴─ parse error / reject / dial failure ─▶ failing (error reply) ─▶ closed
/// ```
///
/// Every tunnel dials before its success reply, so a failed dial gets a real error reply (502 /
/// SOCKS5 code) instead of 200 followed by a reset. The handshake deadline (N8) covers the
/// client-side waits: from accept until the request is parsed, and again from the success reply
/// until the first flight is complete. The dial has its own timeout.
final class Session {
    struct Limits {
        /// Time a client gets to finish its handshake, and again to finish its first flight (N8).
        var handshakeTimeout: TimeInterval = 10
        /// How long a desync tunnel waits for the client to speak before relaying as-is (U7).
        var firstByteTimeout: TimeInterval = 2
        var idleTimeout: TimeInterval = 120
    }

    struct Dependencies {
        let router: Router
        let limits: Limits
        /// The outbound for a routing decision; never called for `.reject`.
        let makeOutbound: (RouteDecision) -> Outbound

        init(router: Router, limits: Limits, makeOutbound: @escaping (RouteDecision) -> Outbound) {
            self.router = router
            self.limits = limits
            self.makeOutbound = makeOutbound
        }

        init(router: Router, limits: Limits, dialer: Dialing, resolverCache: DoHResolverCache) {
            self.init(router: router, limits: limits) { decision in
                let resolver = resolverCache.resolver(for: decision.profile)
                if case .shadowsocks(let config) = decision.outbound {
                    return ShadowsocksOutbound(dialer: dialer, config: config, resolver: resolver)
                }
                return DirectOutbound(dialer: dialer, resolver: resolver)
            }
        }
    }

    enum Phase: String {
        case accepted, handshaking, connecting, readingFirstFlight, writingFirstFlight, relaying
        /// Sending an error reply, then closing.
        case failing
        case closed
    }

    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Session")
    private static let readSize = 65_536

    let scope: SessionScope
    var id: UInt64 { scope.id }
    var queue: DispatchQueue { scope.queue }
    /// Called once, on `queue`, when the session closes.
    var onClose: (() -> Void)?

    private let client: any ConnectionProtocol
    private let deps: Dependencies
    /// Starts as `deps.router`; replaced by `reroute`.
    private var router: Router
    private let startedAt = DispatchTime.now()

    private(set) var phase: Phase = .accepted
    private var inbound: InboundProtocol?
    private var parser: InboundParser?
    private var request: InboundRequest?
    private var decision: RouteDecision?
    private var relayStats: ConnectionRelay.Stats?
    private var deadlineGeneration = 0

    convenience init(id: UInt64, client: any ConnectionProtocol, target: DispatchQueue, deps: Dependencies) {
        self.init(scope: SessionScope(id: id, target: target), client: client, deps: deps)
    }

    /// For tests whose fake client must deliver on the session queue.
    init(scope: SessionScope, client: any ConnectionProtocol, deps: Dependencies) {
        self.scope = scope
        self.client = client
        self.deps = deps
        self.router = deps.router
    }

    private var label: String {
        guard let target = request?.target else { return "#\(id)" }
        return "#\(id) \(target.host):\(target.port)"
    }

    // MARK: - Lifecycle

    /// Takes ownership of the client and starts the handshake deadline. The client may not be
    /// ready yet; call `clientReady()` when it is.
    func accept() {
        assertOnQueue()
        scope.adopt(client)
        armDeadline("handshake")
    }

    func clientReady() {
        assertOnQueue()
        guard phase == .accepted else { return }
        phase = .handshaking
        receiveHandshake()
    }

    /// `accept()` + `clientReady()`, for a client that is already connected.
    func start() {
        accept()
        clientReady()
    }

    /// Idempotent; late callbacks after this are ignored.
    func close(_ reason: String) {
        assertOnQueue()
        guard phase != .closed else { return }
        let reached = phase
        phase = .closed
        deadlineGeneration += 1
        client.cancel()
        scope.close()
        let seconds = Double(DispatchTime.now().uptimeNanoseconds - startedAt.uptimeNanoseconds) / 1e9
        let route = decision.map { "\($0.outbound)" } ?? "-"
        let traffic = relayStats.map { ", \($0.bytesFromLeft) B up, \($0.bytesFromRight) B down" } ?? ""
        Self.logger.info("[\(self.label, privacy: .public)] closed in \(reached.rawValue, privacy: .public) after \(String(format: "%.1f", seconds), privacy: .public)s: \(reason, privacy: .public) (route \(route, privacy: .public)\(traffic, privacy: .public))")
        let onClose = self.onClose
        self.onClose = nil
        onClose?()
    }

    /// A settings change (U13). A session that hasn't routed yet just uses the new router. One
    /// that has is closed if the new route differs, so the client reconnects on the new route.
    /// Once relaying, the desync is history: direct and desync count as the same route.
    func reroute(_ router: Router) {
        assertOnQueue()
        self.router = router
        guard phase != .closed, phase != .failing, let request, let decision else { return }
        let new = router.route(request.target, kind: request.kind).outbound
        let changed = phase == .relaying
            ? Self.relayPath(new) != Self.relayPath(decision.outbound)
            : new != decision.outbound
        if changed {
            close("route changed to \(new)")
        }
    }

    private static func relayPath(_ outbound: OutboundKind) -> OutboundKind {
        if case .desync = outbound { return .direct }
        return outbound
    }

    // MARK: - Deadline (N8)

    private func armDeadline(_ what: String) {
        deadlineGeneration += 1
        let generation = deadlineGeneration
        queue.asyncAfter(deadline: .now() + deps.limits.handshakeTimeout) { [self] in
            guard generation == deadlineGeneration, phase != .closed else { return }
            close("\(what) deadline (\(deps.limits.handshakeTimeout)s)")
        }
    }

    private func disarmDeadline() {
        deadlineGeneration += 1
    }

    // MARK: - Handshake

    private func receiveHandshake() {
        client.receive(minimumIncompleteLength: 1, maximumLength: Self.readSize) { [self] data, _, isComplete, error in
            guard phase == .handshaking else { return }
            if let error { return close("read error in handshake: \(error.localizedDescription)") }
            if let data, !data.isEmpty {
                if parser == nil {
                    let detected = InboundProtocol(firstByte: data[data.startIndex])
                    inbound = detected
                    parser = detected.makeParser()
                }
                return handle(parser!.feed(data))
            }
            if isComplete { return close("client closed during handshake") }
            receiveHandshake()
        }
    }

    private func handle(_ step: InboundStep) {
        guard phase == .handshaking else { return }
        switch step {
        case .needMore:
            receiveHandshake()
        case .reply(let bytes, let then):
            sendToClient(bytes) { [self] in handle(then) }
        case .fail(let reply, let reason):
            fail(reply: reply, reason: "handshake failed: \(reason)")
        case .request(let request):
            begin(request)
        }
    }

    // MARK: - Routing and connecting

    private func begin(_ request: InboundRequest) {
        self.request = request
        disarmDeadline()
        let decision = router.route(request.target, kind: request.kind)
        self.decision = decision
        Self.logger.info("[\(self.label, privacy: .public)] \(self.inbound?.rawValue ?? "?", privacy: .public) \(request.kind == .tunnel ? "tunnel" : "http", privacy: .public) → \(String(describing: decision.outbound), privacy: .public)")

        if case .reject(let reason) = decision.outbound {
            return fail(reply: rejectReply(), reason: reason)
        }

        phase = .connecting
        deps.makeOutbound(decision).connect(request.target, session: scope) { [self] result in
            guard phase == .connecting else { return }
            switch result {
            case .failure(let error):
                fail(reply: failureReply(for: error), reason: "connect failed: \(error)")
            case .success(let upstream):
                connected(upstream, request: request, outbound: decision.outbound)
            }
        }
    }

    private func connected(_ upstream: any ConnectionProtocol, request: InboundRequest, outbound: OutboundKind) {
        switch request.kind {
        case .http(let head):
            // No reply: the origin's response is the reply.
            write([head + request.leftover], to: upstream) { [self] in relay(upstream) }
        case .tunnel:
            sendToClient(successReply()) { [self] in
                if case .desync(let parameters) = outbound {
                    readFirstFlight(upstream, initial: request.leftover, desync: parameters)
                } else {
                    write([request.leftover], to: upstream) { [self] in relay(upstream) }
                }
            }
        }
    }

    private func readFirstFlight(_ upstream: any ConnectionProtocol, initial: Data, desync: DesyncParameters) {
        phase = .readingFirstFlight
        armDeadline("first flight")
        let reader = FirstFlightReader(client: client, queue: queue, firstByteTimeout: deps.limits.firstByteTimeout, label: label)
        reader.read(initial: initial) { [self] flight in
            guard phase == .readingFirstFlight else { return }
            guard let flight else { return close("client closed before its first flight") }
            phase = .writingFirstFlight
            disarmDeadline()
            SegmentWriter.writeFirstFlight(flight, desync: desync, to: upstream, label: label) { [self] error in
                guard phase == .writingFirstFlight else { return }
                // N7: never relay after a failed segment write.
                if let error { return close("first flight write failed: \(error.localizedDescription)") }
                relay(upstream, firstClientReceive: reader.inFlightRead)
            }
        }
    }

    private func relay(_ upstream: any ConnectionProtocol, firstClientReceive: ((@escaping ReceiveHandler) -> Void)? = nil) {
        guard phase != .closed else { return }
        phase = .relaying
        ConnectionRelay.relay(left: client, right: upstream, label: label, queue: queue,
                              idleTimeout: deps.limits.idleTimeout, firstLeftReceive: firstClientReceive) { [self] stats in
            relayStats = stats
            close(stats.idleTimedOut ? "idle timeout" : "relay finished")
        }
    }

    // MARK: - Writing

    private func sendToClient(_ bytes: Data, then next: @escaping () -> Void) {
        let before = phase
        client.send(content: bytes, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { [self] error in
            guard phase == before else { return }
            if let error { return close("client write failed: \(error.localizedDescription)") }
            next()
        })
    }

    private func write(_ chunks: [Data], to upstream: any ConnectionProtocol, then next: @escaping () -> Void) {
        let before = phase
        SegmentWriter.write(chunks.filter { !$0.isEmpty }, to: upstream) { [self] error in
            guard phase == before else { return }
            if let error { return close("upstream write failed: \(error.localizedDescription)") }
            next()
        }
    }

    /// Sends `reply` (if any) and closes.
    private func fail(reply: Data?, reason: String) {
        guard let reply else { return close(reason) }
        phase = .failing
        sendToClient(reply) { [self] in close(reason) }
    }

    // MARK: - Replies

    private func successReply() -> Data {
        inbound == .socks5 ? SOCKS5Parser.reply(SOCKS5Parser.succeeded) : HTTPHeadParser.connectEstablished
    }

    private func rejectReply() -> Data {
        inbound == .socks5 ? SOCKS5Parser.reply(SOCKS5Parser.notAllowedByRuleset) : HTTPHeadParser.response(502, "Bad Gateway")
    }

    private func failureReply(for error: OutboundError) -> Data {
        if inbound == .socks5 { return SOCKS5Parser.reply(SOCKS5Parser.replyCode(for: error)) }
        if case .dial(.timeout) = error { return HTTPHeadParser.response(504, "Gateway Timeout") }
        return HTTPHeadParser.response(502, "Bad Gateway")
    }

    private func assertOnQueue() {
        #if DEBUG
        dispatchPrecondition(condition: .onQueue(queue))
        #endif
    }
}
