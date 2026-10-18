# Plan: Network scanner, block detection and auto-fix

Status: draft, revised 2026-10-18 for the post-refactor core (refactor-and-tests steps 4a–4g).
3 phases. Phase 1 (scanner + passive classifier) is shippable on its own. Phase 2 (active
diagnosis) and phase 3 (fix finder / auto-config) build on it.

## Goal

A new **Network** screen that lists every host/IP that went through the proxy. It shows:

- which profile (rule) each host currently matches, as a badge;
- whether the host looks **blocked**, and **how** (SNI, IP, DNS, HTTP block page, 16–20 KB
  freeze, ECH, whitelist mode), with confidence and evidence;
- what the proxy **couldn't carry** (refused protocols and requests, §2.5);
- multi-select → add to an existing profile or create a new one.

Later phases add a per-host **Diagnose** (active probes that tell SNI vs IP vs DNS vs whitelist
apart) and **Find a fix** (try every strategy Spoofy has, then propose profiles automatically).

Non-goals:
- Raw packet inspection (TTL / IP-ID / late "real" answers). iOS gives a normal app no raw
  sockets, and the kernel TCP stack hides those packets from us. Revisit only if a
  `NEPacketTunnelProvider` mode ever ships.
- QUIC / UDP. The proxy only carries TCP, so QUIC blocking is invisible (browsers fall back
  to TCP through the proxy anyway). The scanner does say what it can't carry: refused SOCKS5
  UDP / BIND, SOCKS4, malformed requests (§2.5).
- Persisting the log. It lives in memory only and is never exported.
- Throughput-based throttling detection in phase 1 (too noisy passively; see §10.4).

## Background: what we're detecting

Russian blocking is mostly TSPU (in-path, stateful DPI at ISP edges, centrally controlled)
plus some leftover ISP-level filtering. Behaviour differs by ISP and region.

| Kind | What the client observes | Spoofy fix |
|---|---|---|
| **A. SNI block** | TCP connects; after ClientHello: silence (flow blackholed) or a near-instant RST | split modes |
| **B. IP block** | TCP connect times out / refused; or connect OK but every ClientHello dropped regardless of SNI | VPN only |
| **C. HTTP block page** | plain HTTP: injected 302 / 403 / 451, faster than the real server could answer | partial |
| **D. DNS spoofing** | system resolver returns a bogon / block-page IP | DoH |
| **E. Throttling** | works, but very slow after SNI match | often split |
| **G. ECH block** | like A, but triggered by the ECH extension (0xfe0d) | none in proxy (client must disable ECH) |
| **H. 16–20 KB freeze** | handshake + ~14–34 KB of server data, then silence, no RST. Mostly foreign hosting ASes on mobile | VPN |
| **I. Whitelist mode** | everything outside an allow-list is blackholed. Network-wide, not per host | none (VPN via whitelisted endpoint) |
| **J. Outline route blocked** | every host in a VPN-route profile fails the same way | different server/transport |

Thresholds for H come from community reports and vary by ISP, so every number in this plan
lives in `DetectionConfig` (§4.1), not inline.

## Current state (what we build on)

The proxy core was rebuilt by `plans/refactor-and-tests.md` (steps 4a–4g). The parts this plan
hooks into:

- **`Session`** (`Proxy/Session.swift`) runs one client connection through
  `accepted → handshaking → connecting → [readingFirstFlight → writingFirstFlight] → relaying
  → closed`, with `failing` for error replies. Everything runs on the session's serial queue
  (`SessionScope.queue`), so session state needs no locks (refactor §6.1).
  - `begin(_ request:)` is the one place routing happens (`router.route(target, kind:)` →
    `RouteDecision { profile, outbound }`), after the inbound handshake and before the dial.
  - Every tunnel **dials before its success reply**. The ClientHello only arrives after that
    reply, so `Router` never sees the SNI.
  - `close(_ reason: String)` is the single, idempotent exit. It logs one line with phase,
    duration, route and `ConnectionRelay.Stats` bytes. Reasons are free text.
  - `reroute(_:)` (U13): a settings change closes live sessions whose route changed, with
    reason `"route changed to …"`.
- **Inbound** (`Inbound.swift`, `HTTPHeadParser`, `SOCKS5Parser`): pure, incremental parsers
  returning `InboundStep` (`needMore / reply / request / fail(reply:reason: String)`). The
  first byte picks the parser (`0x05` → SOCKS5, anything else → HTTP).
- **`Router`** (`Router.swift`): `RouteDecision` → `OutboundKind` = `direct / desync(DesyncParameters)
  / shadowsocks(OutlineServerConfig) / reject(reason:)`. Built from a `ProxyConfig`, or from a
  `profileForHost` closure (tests use that seam).
- **`ServerConnector`** (`ServerConnector.swift`, the old network-scanner §1, landed as 4b):
  `dial(_:resolver:session:completion:)`. DoH, else system DNS inside `NWConnection`. A
  staggered race over interleaved addresses, every attempt adopted by the `SessionScope`. `.waiting`
  fails that attempt (N11). Result is `NWConnection` or `DialError.allFailed([NWError]) /
  .timeout / .cancelled`. `ShadowsocksStream.connect` dials the Outline server through the same
  `Dialing`.
- **Outbounds** (`Outbound.swift`): `DirectOutbound` (dial), `ShadowsocksOutbound` (optional DoH
  of the target name, then `ShadowsocksStream.connect`). Errors: `OutboundError.dial(DialError)
  / .shadowsocks`.
- **First flight**: `FirstFlightReader` drives `ClientHelloReader` and yields
  `FirstFlight.clientHello(record, sniOffset, leftover) / .raw(bytes) / .empty` (`.empty` = the
  client stayed silent for `firstByteTimeout`, 2 s, U7). `SegmentWriter.writeFirstFlight` desyncs
  it. Only **desync** tunnels go through this; `direct` and Shadowsocks tunnels write the
  pipelined `leftover` and go straight to the relay.
- **`ConnectionRelay.relay(left:right:…:completion: (Stats) -> Void)`**: `left` is the client,
  `right` the upstream. It returns byte counts and `idleTimedOut`; it doesn't say which side
  ended or why. Idle timeout 120 s, checked every 15 s (`idleCheckInterval` is injectable).
  Callbacks run on the session queue.
- **`ProxyServer`**: admission (≤200 sessions) and the session registry on `serverQueue`;
  `update(_ config:)` swaps the snapshot and reroutes sessions. Dependencies are injected
  (`resolverCache`, `dialer`, `limits`), which is how the loopback harness builds it.
- **Settings**: `SettingsStore` (`@MainActor ObservableObject`, decoded once, written through,
  `onChange` → `ProxyManager` → `server.update(store.snapshot)`). `ProxyConfig` is the immutable
  snapshot: `profile(for:)` returns the first matching enabled custom profile, with Master's
  inherited DoH/Outline settings applied, else Master. Custom profiles without usable patterns
  match nothing (U1). `DomainMatcher` compares label by label; IP literals match exactly.
- **App layer**: `ContentView` (status circle, Start/Stop, gear → `SettingsView`),
  `SettingsView` + `ProfileEditView(profileID:)` read the store as an `@EnvironmentObject`, so
  edits made elsewhere show up immediately. `ProxyManager.Status` is
  `stopped / starting / running / error`.
- **Tests**: `swift test` on macOS through `Package.swift` (`SpoofyCore`, sources `Proxy TLS DNS
  Shadowsocks Shared`). Support: `FakeConnection`, `FakeResolver`, `LoopbackOrigin` (`echo /
  recordAll / serverFirst`), `LoopbackShadowsocksServer`, `TestClient`, and a test-only
  `ClientHelloBuilder.make(sni:extensionsBefore:)`. `Spoofy/` isn't compiled by the package; the
  `xcodebuild` check covers it.
- Verified in the iOS 26.5 SDK (all available since iOS 13/14):
  `NWConnection.requestEstablishmentReport` → `resolutions[].{source, duration,
  successfulEndpoint, dnsProtocol}`, `handshakes[].{definition, handshakeRTT}`;
  `startDataTransferReport().collect` → `aggregatePathReport.{transportMinimumRTT,
  transportSmoothedRTT, retransmittedTransportByteCount, receivedApplicationByteCount, …}`.

### Rules this plan follows (from CLAUDE.md)

- New core code goes in a new **`Diagnostics/`** folder: Foundation / Network / CryptoKit /
  os.log only. Add `"Diagnostics"` to `sources:` in `Package.swift` and every file to the app
  target in `project.pbxproj`. UI goes in `Spoofy/`.
- Trace state is touched only on the session queue. The log is the one shared object, with a
  lock. No `DispatchQueue.global()`.
- The network code never reads `SettingsStore`; it gets `ProxyConfig` and an injected observer.
- One step = one tested commit (§16).

---

# Phase 1: scanner + passive classifier

## 1. Observation seams

Where the scanner attaches to the core. Each seam is optional (nil = today's behaviour) so the
existing tests keep passing unchanged.

| Seam | Change | Records |
|---|---|---|
| `ProxyServer.init(…, observer: ConnectionObserver? = nil)` | stored, passed into every `Session.Dependencies` | — |
| `ProxyServer.admit` | over the cap: `observer?.refused(.init(reason: .overCapacity, …))` | refusal |
| `Session.begin` | after routing, unless `.reject`: `trace = observer?.begin(…)`; `scope.trace = trace` | `created` |
| `Session.handle(.fail)` / `begin` reject | `observer?.refused(…)` (§2.5.4) | refusal |
| `SessionScope.trace: ConnectionTrace?` | new stored property; set once in `begin` | — |
| `ServerConnector.dial` / `DialAttempt` | reads `session.trace`: DoH start/end, each attempt's start, failure, `.ready` | `resolving`, `connecting`, `connected`, per-address errors |
| `ShadowsocksOutbound.connect` | DoH of the target name; `ShadowsocksStream.connect` → nil | DoH, `.outlineConnectFailed` |
| `Session.connected` / `readFirstFlight` | first flight, applied strategy, first payload write | `payloadSent`, `PayloadKind`, `AppliedStrategy` |
| `ConnectionRelay.relay(…, observer: RelayObserver? = nil)` | per-chunk, first end event, ticks | bytes, `responding`, end reason, stall |
| `Session.close(_ reason: CloseReason)` | `trace?.finish(fallback: reason.endReason)` | `ended` |

`ConnectionObserver` is a core protocol (`Diagnostics/ConnectionObserver.swift`) so tests can
record calls without the real log:

```swift
protocol ConnectionObserver: AnyObject {
    /// Session queue. Returns nil to skip tracing this connection.
    func begin(_ start: TraceStart, queue: DispatchQueue) -> ConnectionTrace?
    /// Any queue (session or server).
    func refused(_ record: RefusalRecord)
}
```

`ConnectionLog` (§6.1) is the production implementation. `ProxyManager` owns it and passes it
to `ProxyServer(config:observer:)`.

**Why `SessionScope.trace` and not a new parameter on `Dialing.dial`:** the scope already goes
everywhere a connection is opened for the session (dial attempts, the Outline dial inside
`ShadowsocksStream.connect`), so the trace reaches those places without changing `Dialing`,
`Outbound` or the Shadowsocks API. For a Shadowsocks route the dial events describe the Outline
server, which is exactly what R0 (§4.4) needs.

**`CloseReason`.** `Session.close(_ reason: String)` becomes `close(_ reason: CloseReason)`.
`description` returns today's text, so the log line is unchanged. This makes the end of a
session machine-readable:

```swift
enum CloseReason: CustomStringConvertible {
    case handshakeReadError(NWError), clientClosedInHandshake
    case handshakeFailed(InboundFailure)          // §2.5.4
    case rejected(String)                         // Router .reject
    case connectFailed(OutboundError)
    case clientClosedBeforeFirstFlight, firstFlightWriteFailed(NWError)
    case relayFinished, idleTimeout
    case clientWriteFailed(NWError), upstreamWriteFailed(NWError)
    case deadline(String)                         // N8, "handshake" / "first flight"
    case routeChanged(OutboundKind)               // U13
    case proxyStopped
    case clientConnectionFailed(NWError), clientConnectionCancelled
}
```

`ProxyServer` uses the last three (`stop()`, `admit`'s client state handler).

## 2. Connection trace

`Diagnostics/ConnectionTrace.swift`. One reference-type object per routed session, created in
`Session.begin` and **touched only on the session queue**, so it has no lock. It pushes two
things to the log (which has the lock): a small `ActiveEntry` on phase changes (for the live
count and active rows) and the final immutable `TraceSummary`.

### 2.1 Lifecycle state machine

```
created ──► resolving ──► connecting ──► connected ──► payloadSent ──► responding ──► ended
   │            │              │             │              │              │
   └────────────┴──────────────┴─────────────┴──────────────┴──────────────┴──► ended
```

Transitions only move forward; an event for an earlier phase is recorded but doesn't move the
phase back (e.g. a second dial attempt starting after the first failed stays in `connecting`).

| Phase | Entered by (current code) | Recorded |
|---|---|---|
| `created` | `Session.begin`, after `router.route` | `id` (= session id), `startedAt` (wall `Date` + mono ns), `inbound` (§2.5.2), `host` (lowercased `DialTarget.host`), `port`, `isIPLiteral` (`ServerConnector.isIPLiteral`), `profileID`, `profileName`, `isDefaultProfile`, `fingerprint` (§6.4), `outbound` (`OutboundKind`, password-free), `isProbe` |
| `resolving` | `ServerConnector.dial` / `ShadowsocksOutbound` call the resolver | `dnsStart` |
| `connecting` | first `DialAttempt.startNext` | `connectStart`, `dnsEnd`, `dohIPs` (nil = DoH off or gave nothing) |
| `connected` | `DialAttempt` `.ready` | `connectEnd`, `connectedAddress`; async from `requestEstablishmentReport`: `tcpRTT` (`handshakes` where `definition == NWProtocolTCP.definition`), `systemDNS{duration, source}`, `resolvedIP` (`resolutions.last.successfulEndpoint`, else `currentPath?.remoteEndpoint`) |
| `payloadSent` | first client bytes fully written upstream (§2.2) | `payloadSentAt`, `payloadKind`, `applied` |
| `responding` | first upstream→client chunk (relay observer) | `firstDownAt`, `firstDownPrefix` (first 128 bytes) |
| `ended` | `trace.finish` (first terminal event wins) | `endedAt`, `endReason`, bytes, `stall`, transport-report fields |

All timestamps are monotonic `UInt64` ns (`DispatchTime.now().uptimeNanoseconds`). Only
`startedAt` keeps a wall-clock `Date` for display.

**Dial attempts.** `ServerConnector` races several addresses. The trace keeps every attempt as
`(address, startedAt, outcome: .ready / .failed(NWError) / .cancelled)`, capped at 4. For a
Shadowsocks route the addresses are the Outline server's.

**Terminal events. The first one wins.** One side ending cancels the other, which then fires
its own error (`ECANCELED`); that later event must not overwrite the real cause. Every source
calls `trace.end(_:)`, which only takes the first; `finish` then closes the trace.

| Source | `EndReason` |
|---|---|
| `DialError.allFailed(errors)` | `.connectFailed(ConnectError(errors))`: any `ECONNREFUSED` → `.refused`; any `EHOSTUNREACH` / `ENETUNREACH` → `.unreachable`; all `NWError.dns` → `.dns`; else `.other(code of the last)` |
| `DialError.timeout` | `.connectFailed(.timeout)` |
| `DialError.allFailed` with only `.dns` errors **and** DoH returned nothing | `.dnsFailed` |
| `OutboundError.shadowsocks` | `.outlineConnectFailed` |
| relay: upstream read error `posix(.ECONNRESET)` | `.serverReset` |
| relay: other upstream read error | `.serverError(code)` |
| relay: upstream read `isComplete` | `.serverFin` |
| relay: client read error / `isComplete`, or write-to-client error | `.clientClosed` |
| relay: write-to-upstream error | `.serverError(code)` |
| relay idle timeout | `.idleTimeout` |
| `CloseReason.routeChanged` | `.rerouted` (U13: the user changed rules; never evidence) |
| `CloseReason.proxyStopped` | `.proxyStopped` (never evidence) |
| `CloseReason.deadline`, `.clientClosedBeforeFirstFlight`, client write failures | `.clientClosed` |
| anything else reaching `close` with no earlier event | `.clientClosed` |

`CloseReason.endReason` maps every case; a `switch` without `default` makes the compiler catch
new close reasons.

**Guaranteed finish.** `Session.close` is already the single exit and already idempotent, so
it calls `trace?.finish(fallback: reason.endReason)` once. Nothing else needs wrapping (the old
plan's completion wrapper is obsolete).

**Order inside `close`.** Start the data-transfer report collection (§2.3) *before*
`scope.close()` cancels the connections, and don't wait for it. The trace hands its summary to
the log when the report callback arrives or after 1 s, whichever is first, on the session queue.
The session itself closes at once, as today.

### 2.2 First payload

`trace.payloadSent(kind:applied:)` is called once, when the first client bytes have been fully
written upstream (`.contentProcessed`). That's the moment the DPI saw them.

| Path in `Session` | Called after | `payloadKind` | `applied` |
|---|---|---|---|
| `connected`, `.http(head)` | `write([head + leftover])` | `.http(method, host)` from the parsed request | `.passthrough(.plainHTTP)` |
| `readFirstFlight` → `.clientHello` | `SegmentWriter.writeFirstFlight` completes (the **last** segment) | `.tls(ClientHelloInfo)` / `.tlsOther` | `.desync(parameters)` |
| `readFirstFlight` → `.raw(bytes)` | `writeFirstFlight` completes | `PayloadSniffer.sniff(client: bytes)` | `.passthrough(.notTLS)` |
| `readFirstFlight` → `.empty` | — (nothing sent); the relay sets it later | server greeting or first client chunk | `.passthrough(.clientSilent)` |
| `connected`, tunnel, not desync, `leftover` non-empty | `write([leftover])` | `sniff(client: leftover)` | `.passthrough(.splitNone)` or `.shadowsocks` |
| same, `leftover` empty | relay's first client→upstream send completes | `sniff(client: chunk)` | same |

`ClientHelloInfo` is parsed from the record `FirstFlight.clientHello` already holds, on the
session queue (a few hundred bytes, cheap). Only the parsed summary is kept, never the payload.

### 2.3 Transport reports

- `requestEstablishmentReport(queue: session.queue)` is requested on `.ready`. Its callback fills
  `tcpRTT`, DNS info and `resolvedIP`. If it hasn't arrived by finish time, those fields stay nil
  and the classifier falls back (§4.2).
- `startDataTransferReport()` is started on `.ready` and collected **at most twice**:
  1. when the stall check first suspects a hello blackhole (≥ `helloBlackholeMin` silence after
     the payload, §3), because that's when retransmits are informative;
  2. in `close`, before the cancel (§2.1).

  Fields kept: `retransmittedTransportByteCount`, `transportMinimumRTT`,
  `transportSmoothedRTT`. If (2) comes back empty, (1) still gives us what we need.

The trace holds the upstream `NWConnection` weakly for these. For Shadowsocks that's the
connection under the stream (the one `DialAttempt` reported ready).

### 2.4 `TraceSummary`

Immutable, `Sendable`, everything above plus derived values:

```swift
var rtt: TimeInterval?          // tcpRTT ?? transportMinimumRTT ?? nil
var rttIsPrecise: Bool          // false when only connect duration is available
var tFirstDown: TimeInterval?   // firstDownAt - payloadSentAt
var tEnd: TimeInterval?         // endedAt - payloadSentAt
var bytesUp, bytesDown: Int     // from ConnectionRelay.Stats
var stall: StallInfo?           // §3
var retransmitBytes: UInt64?
var payloadKind: PayloadKind    // §2.5.2
var applied: AppliedStrategy    // §2.5.3
```

### 2.5 Protocol coverage

Spoofy carries a narrow set of protocols, and the scanner has to say so honestly. Otherwise
it shows misleading results: SSH marked "blocked after hello", a SOCKS4 app that looks like
a broken site, or UDP traffic that never shows up and leaves the user guessing. Every trace
records **what came in** (inbound protocol) and **what was inside** (payload kind). The
classifier, the verdicts, the sheet defaults and the fix finder all branch on these two.

#### 2.5.1 What can reach the proxy today

From `InboundProtocol`, `HTTPHeadParser`, `SOCKS5Parser`, `Session` and `ProxyServer`:

| Client traffic | Reaches Spoofy | Today's behaviour | Scanner shows |
|---|---|---|---|
| HTTP `CONNECT host:port` (any port) | yes | dial, `200`, tunnel | host row |
| Absolute-form `GET http://…` | yes | one request per upstream connection (`Connection: close`) | host row, kind `.http` |
| SOCKS5 `CONNECT`, no auth; IPv4 / IPv6 / domain | yes | dial, success reply, tunnel | host row (IP row if the client resolved the name itself, §2.5.5) |
| SOCKS5 username/password auth only | refused | `05 FF`, close | refusal `.socks5AuthRequired` |
| SOCKS5 `BIND` (0x02) | refused | reply `0x07` | refusal `.socks5Bind` |
| SOCKS5 `UDP ASSOCIATE` (0x03): QUIC, DNS, calls, games | refused | reply `0x07` | refusal `.socks5UDP` |
| SOCKS4 / 4a (first byte `0x04`) | **misread** | goes to `HTTPHeadParser`, `400 malformed request line` | refusal `.socks4` (after the §2.5.4 change) |
| Origin-form `GET /path` (app treats the proxy as a web server) | refused | `400` | refusal `.httpOriginForm` |
| `GET https://…` absolute form | refused | `400` | refusal `.httpsAbsoluteForm` |
| HTTP/2 prior knowledge (`PRI * HTTP/2.0`) | refused | `400 malformed request line` | refusal `.http2Preface` |
| Over the 200-session cap | refused | `admit` cancels the connection | refusal `.overCapacity` |
| Router `.reject` (VPN profile without an Outline config, U6) | refused | `502` / SOCKS5 `0x02` | refusal `.routeRejected(profileName)` |
| UDP from apps that don't use SOCKS5 (QUIC, plain DNS, WebRTC) | **never** | — | "can't see" footer (§2.5.6) |
| Apps that ignore the system proxy (custom network stacks: Telegram MTProto, many games) | **never** | — | "can't see" footer |

Browsers drop QUIC when a proxy is configured, so web traffic arrives as TCP. The gap is
non-browser apps.

#### 2.5.2 Payload kind (`Diagnostics/PayloadSniffer.swift`, pure)

```swift
enum InboundKind: String { case connect, httpForward, socks5 }   // from InboundProtocol + InboundRequest.Kind

enum PayloadKind: Equatable {
    case tls(ClientHelloInfo)           // first record is a ClientHello (§5)
    case tlsOther                       // 0x16 0x03 but not a parsable ClientHello
    case http(method: String, host: String?)
    case ssh                            // "SSH-"
    case serverFirst(ServerGreeting)    // client silent; server spoke first
    case unknown(firstBytes: Data)      // ≤ 8 bytes, for the detail view only
    case none                           // nothing sent either way before the end
}
enum ServerGreeting: Equatable { case smtpOrFTP /* "220" */, imap /* "* OK" */, pop3 /* "+OK" */, other }
```

Where the input comes from (the table in §2.2 says when):

| Path | Source | Kind |
|---|---|---|
| plain-HTTP inbound (`InboundRequest.Kind.http`) | parsed request line | `.http` (no sniffing) |
| desync tunnel, `FirstFlight.clientHello` | the record | `.tls(info)`, or `.tlsOther` if `ClientHelloInfo` fails |
| desync tunnel, `FirstFlight.raw(bytes)` | first bytes | `sniff(client:)` |
| desync tunnel, `FirstFlight.empty` | first upstream chunk (relay observer) | `sniff(server:)` → `.serverFirst`, or `.none` |
| direct / Shadowsocks tunnel | pipelined `leftover`, else the first chunk either way in the relay | `sniff(client:)` or `sniff(server:)`, whichever comes first |

`sniff(client:)` rules, first match wins:
1. `0x16 0x03 0x0[0-4]` and `ClientHelloInfo.parse` succeeds → `.tls`. Otherwise `.tlsOther`.
2. An ASCII token from `GET HEAD POST PUT DELETE OPTIONS PATCH CONNECT TRACE`, then a space →
   `.http(method, host)`, with `Host:` read if it's in the same chunk.
3. `SSH-` → `.ssh`.
4. Else `.unknown(prefix(8))`.

`sniff(server:)` matches `220`, `* OK`, `+OK`, else `.other`. The kind is set once per trace, on
the first payload in either direction.

#### 2.5.3 Configured vs applied strategy

`Router` decides before the first flight is read, so a desync route can match a tunnel that
turns out not to be TLS. `SegmentWriter` then forwards it unchanged (`FirstFlight.raw` /
`.empty`). The trace keeps both `outbound` (configured) and:

```swift
enum AppliedStrategy: Equatable {
    case desync(DesyncParameters)
    case passthrough(PassthroughReason)   // .notTLS, .clientSilent, .plainHTTP, .splitNone
    case shadowsocks
}
```

The detail view shows `Split (SNI) configured · not applied: not TLS`. The sheet uses it for
its warning (§2.5.5).

#### 2.5.4 Refused requests

Today these end in `Session.fail(reply:reason:)` with a free-text `String`, before any
routing, so nothing about them reaches a trace. Changes:

1. **Structured failure.** `InboundStep.fail(reply:reason:)` carries `InboundFailure` instead of
   `String`, and `CloseReason.handshakeFailed` wraps it (§1). `description` keeps the existing
   text, so log lines don't change.
   ```swift
   enum InboundFailure: Equatable, CustomStringConvertible {
       case socks5AuthRequired(offered: [UInt8])
       case socks5Command(UInt8)            // 0x02 bind, 0x03 udp associate
       case socks5AddressType(UInt8)
       case socks4
       case httpOriginForm, httpsAbsoluteForm, http2Preface
       case headTooLarge
       case malformed(String)               // everything else keeps its old text
   }
   ```
   `SOCKS5Parser.parseRequest` maps command 2/3 to `.socks5Command`. `HTTPHeadParser` checks
   for the `PRI * HTTP/2.0` line before the generic malformed check (today it fails the
   `HTTP/1.` version check), tells `/path` targets (origin-form) apart from `https://` targets
   (today both are "not an absolute http:// target"), and returns the specific case.
2. **SOCKS4 recognised.** `InboundProtocol(firstByte:)` gets `case socks4` for `0x04`, with a
   `SOCKS4Parser: InboundParser`. It reads `VN CD DSTPORT DSTIP USERID\0 [HOST\0]` (4a when
   `DSTIP` is `0.0.0.x`, x ≠ 0). That's enough to name the target. It then returns
   `.fail(reply: 00 5B 00 00 00 00 00 00, .socks4)` (request rejected). We don't carry SOCKS4;
   the parser exists so the refusal names the right cause and the app gets a reply it
   understands. Supporting it later is a `.request` instead of the `.fail` (§2.5.7).
3. **Logged.** `Session` reports refusals through `observer?.refused(_:)`: handshake failures
   in `handle(.fail)`, route rejects in `begin`. `ProxyServer.admit` reports over-capacity.
   No `ConnectionTrace` is created for them. A client that just closes mid-handshake isn't a
   refusal and isn't logged.
   ```swift
   struct RefusalRecord: Sendable {
       let at: Date
       let inbound: InboundProtocol?        // nil for over-capacity (nothing read yet)
       let reason: RefusalReason            // InboundFailure + .routeRejected(profileName) + .overCapacity
       let target: DialTarget?              // when the request got far enough to name one (UDP ASSOCIATE usually sends 0.0.0.0:0)
   }
   ```
   `ConnectionLog` keeps refusals grouped by `reason.groupKey`: count, first and last seen,
   and the last 5 distinct targets. There's a cap of 32 groups. They're kept apart from host
   records, so they never touch verdicts or the `NetworkState` thresholds.

#### 2.5.5 What the kind changes downstream

| Consumer | `.tls` | `.http` | `.ssh` / `.unknown` / `.tlsOther` | `.serverFirst` | `.none` |
|---|---|---|---|---|---|
| Classifier (§4.4) | all rules | R1–R3 (DNS/connect), C rules (block page), H freeze | R1–R3 only, then `inconclusive` | R1–R3, then `inconclusive` | R1–R3, `clientAborted` |
| Silence after first payload | `helloBlackhole` | `inconclusive` (a slow origin is normal) | `inconclusive` (many protocols wait legitimately) | — | — |
| Verdict (§6.2) | counts | counts | counts only connect-level outcomes | same | ignored |
| Row chip (§7.3) | — (default) | `HTTP` | `SSH` / `TCP` | `SMTP`, `IMAP`… / `TCP` | — |
| Sheet default (§7.4) | as §7.4 | Split+None+DoH, or VPN for C | **VPN** if Master has Outline, else no default with "Split modes only change TLS" | same as left | — |
| Diagnose (§10) | full | D0–D2 + HTTP probe (stretch) | D0–D2 (DNS, TCP connect) | same | — |
| Fix candidates (§11) | all | DoH, VPN | DoH, VPN | DoH, VPN | — |

Freeze (H) is protocol-agnostic: it's a byte-count cut on the TCP flow. It still applies to
`.unknown` and `.ssh`, at low confidence, because a long-lived SSH session can just go quiet.

The log keys hosts by host name. Each entry keeps its port and kind, so one host can carry
`443/TLS` and `5222/unknown` side by side. The verdict comes from the host's TLS and HTTP
entries when it has any, and from all entries otherwise. The detail view lists every
port/kind pair.

**IP targets.** SOCKS clients that resolve names themselves (`curl --socks5`, many games)
send an IP. `Router` matches on `DialTarget.host`, so the rule has to be the IP. A domain
taken from the SNI won't match those connections. The row shows the SNI as the title with the
IP underneath. The sheet adds the **IP** (exact), along with a hint: "Set the app to resolve
names through the proxy (SOCKS5h / remote DNS) to use domain rules." `DomainMatcher` already
matches IPv4 and IPv6 literals exactly, label by label. CIDR isn't supported, which is
acceptable for now.

#### 2.5.6 UI for refusals

At the bottom of `ScannerView` there's a **Couldn't carry** section, one row per refusal
group. It's hidden when empty. It isn't selectable and has no profile actions, because a
rule can't fix any of these.

| Reason | Copy |
|---|---|
| `.socks5UDP` | "An app tried to send UDP (calls, games, QUIC). Spoofy only carries TCP. These apps will connect directly or fail." |
| `.socks5Bind` | "An app asked to accept incoming connections (e.g. FTP active mode). Not supported." |
| `.socks5AuthRequired` | "An app wants to log in to the proxy. Turn off proxy authentication in that app." |
| `.socks4` | "An app uses SOCKS4. Switch it to SOCKS5 or HTTP proxy." |
| `.httpOriginForm` / `.httpsAbsoluteForm` / `.http2Preface` | "An app is talking to Spoofy as if it were a website. Check that it's set to use an *HTTP proxy*, not a server address." |
| `.routeRejected(name)` | "Profile *name* routes through VPN but has no Outline server." Tapping it opens `ProfileEditView(profileID:)`. |
| `.overCapacity` | "More than 200 connections at once; some were refused." |
| `.malformed` | "N requests weren't valid proxy requests." The last reason text appears in the detail view. |

Footer text (always shown): *"Not shown: UDP from apps that don't use SOCKS5 (QUIC, voice
calls), and apps that ignore the system proxy."*

The main-screen summary line (§7.1b) doesn't count refusals.

#### 2.5.7 What this data decides (not built here)

The refusal counts are how we decide which protocol work is worth doing:

- **SOCKS4a**: on top of 2.5.4 it's a `.request` instead of `.fail`, plus SOCKS4 replies in
  `Session.successReply` / `failureReply`. Build it if `.socks4` shows up in user reports.
- **SOCKS5 UDP ASSOCIATE**: a UDP relay with its own session lifetime rules. Desync can't help
  QUIC, so only `direct` and Shadowsocks-UDP routes would make sense. It's a separate plan, and
  only worth it if `.socks5UDP` is common.
- **Routing by SNI for IP targets**: needs the ClientHello before the routing decision. That
  conflicts with dial-before-reply in `Session` (the success reply has to come before the
  client sends its hello, and the dial comes before the reply so failures get real error
  codes). A separate plan, if IP-target rows turn out to be common.

**Found while reading, unrelated to the scanner:** `HTTPHeadParser.rewrite` drops
`Connection` and appends `Connection: close`. That breaks an absolute-form `Upgrade:
websocket` request, which needs `Connection: Upgrade`. Browsers tunnel `ws://` over CONNECT,
so the impact is probably small. File it as its own finding.

## 3. Relay instrumentation

`ConnectionRelay.relay(…, observer: RelayObserver? = nil, …)`. Existing callers and
`ConnectionRelayTests` keep compiling. `Session.relay` passes the trace.

```swift
/// All calls on the relay's queue (the session queue).
protocol RelayObserver: AnyObject {
    func relayed(_ count: Int, fromLeft: Bool, prefix: Data)   // after the write completed; prefix only on the first chunk each way
    func relayEnded(_ event: RelayEndEvent)                    // first terminating event only
    func relayTick(now: UInt64)                                // every idleCheckInterval
}
enum RelayEndEvent { case readError(fromLeft: Bool, NWError), eof(fromLeft: Bool), writeError(toLeft: Bool, NWError), idleTimeout }
```

- `pipe` already knows its direction (`fromLeft`) and the error / `isComplete` / write-error
  branches. Each branch reports `relayEnded` before cancelling; the trace keeps only the first
  (§2.1 maps them to `EndReason`).
- `relayed` is called from the write's `.contentProcessed`, so "first client→upstream chunk sent"
  (§2.2) and "first upstream byte" (`responding`) come from the same hook.
- When an observer is set, `Session` passes `idleCheckInterval: .seconds(2)` (idle timeout stays
  120 s). One 2 s timer per session, ≤200 sessions: negligible. Each tick calls
  `relayTick`, and the trace runs its stall check.
- `RelayActivity` keeps its lock (the idle timer and pipes share it); nothing else changes.

**Stall check** (`ConnectionTrace.relayTick`). It only observes and never kills the connection:
the client app decides when to give up, and long-polls are legitimate.

```
waitingOnServer = payloadSentAt != nil && (lastDownAt == nil || lastUpAt > lastDownAt)
silence        = now - max(lastUpAt, lastDownAt ?? payloadSentAt)
if waitingOnServer && silence >= stallSeconds && stall == nil:
    stall = StallInfo(at: now, bytesDownAtStall: bytesDown, phase: firstDownAt == nil ? .beforeResponse : .midStream)
if firstDownAt == nil && now - payloadSentAt >= helloBlackholeMin && !reportCollectedEarly:
    collect data-transfer report (§2.3 #1)
if stall != nil && bytesDown > stall.bytesDownAtStall:
    stall.resumed = true          // data came back → not a freeze
```

**A desync tunnel with `FirstFlight.empty`** goes to the relay with `firstLeftReceive`
(`FirstFlightReader.inFlightRead`). The observer sees that read like any other.

## 4. Per-connection classifier

`Diagnostics/TraceClassifier.swift`: a pure function `classify(TraceSummary) -> TraceOutcome`.
No state, fully unit-testable.

### 4.1 `DetectionConfig`

```swift
enum DetectionConfig {
    static let earlyRatio = 0.5               // event < 0.5 × RTT after payload ⇒ not from the server
    static let minRTTForTiming = 0.010        // below 10 ms we can't tell injected from real
    static let helloBlackholeMin = 3.0        // s of silence after ClientHello before "blackhole"
    static let stallSeconds = 8.0
    static let freezeWindow = 12_000...40_000 // bytes down at stall for kind H
    static let blockPageStatus: Set<Int> = [301, 302, 303, 307, 403, 451]
    static let blockPageHosts: [String] = []  // seed from community lists; verify before shipping
    static let whitelistSNIs: [String] = []   // phase 2 probe D6; seed from community lists
}
```

### 4.2 Timing helper

```
early(t) = rtt != nil && rtt >= minRTTForTiming && t < earlyRatio * rtt
```

If `rtt` is nil, `early` is always false, so timing-based outcomes downgrade to their
non-early (lower-confidence) variants.

### 4.3 Outcomes

```swift
enum TraceOutcome {
    case ok
    case clientAborted                       // client left before we could judge
    case interrupted                         // rerouted (U13) or proxy stopped: not evidence
    case dnsFailed
    case dnsBogus(ip: String)                // D
    case connectRefused, connectTimeout, connectUnreachable   // B (TCP level)
    case helloReset(early: Bool)             // A: RST after ClientHello, no server bytes
    case helloSilentClose(early: Bool)       // A: FIN after ClientHello, no server bytes
    case helloBlackhole(retransmits: Bool)   // A / B / I: silence after ClientHello
    case injectedResponse(InjectedKind)      // A/C: content that can't be from the server
    case httpBlockPage(status: Int, location: String?)        // C
    case freeze(bytesDown: Int)              // H
    case midStreamReset(bytesDown: Int)      // weak, informational
    case outlineFailed                       // J (route-level)
    case inconclusive
}
enum InjectedKind { case httpOnTLS, earlyAlert, sessionIDMismatch }
```

Each outcome also carries `confidence: .low/.medium/.high` and `echPresent: Bool` (from
`ClientHelloInfo.hasECH`), so the UI can say "may be ECH blocking".

### 4.4 Rules (evaluated in order, first match wins)

Gate first: rules past R3 run only for the payload kinds in the §2.5.5 table. A non-TLS
tunnel that goes quiet is `inconclusive`, never `helloBlackhole`.

```
R-1 endReason ∈ {.rerouted, .proxyStopped}               → interrupted
        (checked first: a session closed by a rule change looks exactly like a blackhole otherwise)

R0  outbound == .shadowsocks:
        endReason == .outlineConnectFailed               → outlineFailed (high)
        endReason == .connectFailed(_)                   → outlineFailed (medium)  // dial to the Outline server
        else                                             → ok / inconclusive
        (DPI sees the Outline server, not the host, so no per-host DPI verdicts on VPN routes.)

R1  endReason == .dnsFailed                              → dnsFailed (medium)
R2  resolvedIP is bogon && !isIPLiteral                  → dnsBogus (high)
        bogon = 0.0.0.0/8, 127/8, 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16,
                ::/128, ::1, fc00::/7, fe80::/10

R3  never connected (endReason == .connectFailed(e)):
        e == .refused                                    → connectRefused (medium)
        e == .unreachable                                → connectUnreachable (low)
        e == .timeout                                    → connectTimeout (medium)

R4  payloadSentAt == nil                                 → clientAborted
        (browser preconnects that never send anything land here; ignored)

R5  firstDownAt == nil (server never sent a byte):
        endReason == .serverReset:
            early(tEnd)                                  → helloReset(early: true)  (high)
            else                                         → helloReset(early: false) (medium)
        endReason == .serverFin:
            early(tEnd)                                  → helloSilentClose(early: true)  (high)
            else                                         → helloSilentClose(early: false) (low)
        endReason ∈ {.clientClosed, .idleTimeout}:
            tEnd >= helloBlackholeMin                    → helloBlackhole(retransmits: retransmitBytes > 0)
                                                           (medium; high if retransmits)
            else                                         → clientAborted
                (client gave up or raced another connection: can't judge)

R6  payloadKind is .tls && firstDownAt != nil:
        prefix starts with "HTTP/"                       → injectedResponse(.httpOnTLS) (high)
        prefix[0] == 0x15 (alert) && early(tFirstDown)   → injectedResponse(.earlyAlert) (high)
        prefix[0] == 0x15 && !early                      → inconclusive (real server rejected us)
        ServerHello parsed && negotiated TLS 1.3
          && serverSessionID != clientHello.sessionID    → injectedResponse(.sessionIDMismatch) (medium)
        → fall through to R8

R7  payloadKind is .http && firstDownAt != nil:
        parse status line + Location from prefix (128 B is enough for both in practice;
        if Location is cut off, treat it as unknown)
        status ∈ {301,302,303,307} && locationHost not same base domain as requestHost
          && (early(tFirstDown) || locationHost ∈ blockPageHosts)  → httpBlockPage (high)
        status ∈ {403, 451} && early(tFirstDown)         → httpBlockPage (medium)

R8  firstDownAt != nil, streaming:
        stall != nil && !stall.resumed && stall.phase == .midStream
          && stall.bytesDownAtStall ∈ freezeWindow
          && endReason ∈ {.clientClosed, .idleTimeout}   → freeze (medium; low for non-TLS/HTTP)
        endReason == .serverReset && bytesDown < 64_000  → midStreamReset (low)

R9  bytesDown > 0                                        → ok
    else                                                 → inconclusive
```

Why a TLS 1.3 session-ID check: in TLS 1.3 the ServerHello echoes the client's
`legacy_session_id`. A TLS 1.2 server may return any ID, so we only compare when the
ServerHello's `supported_versions` says `0x0304`. A smart injector could echo it, so this is
medium confidence.

## 5. TLS parsing additions

`TLS/TLSParser.swift`. Generalize the extension walk in `TLSMessage.extractSNIOffset` into one
parser and keep `extractSNIOffset` as a thin wrapper, so `ClientHelloReader` and `TLSDesyncer`
don't change:

```swift
struct ClientHelloInfo: Equatable, Sendable { let sni: String?; let sessionID: Data; let hasECH: Bool; let alpn: [String] }
extension ClientHelloInfo { static func parse(record: Data) -> ClientHelloInfo? }

struct ServerHelloInfo: Equatable, Sendable { let sessionID: Data; let negotiatedVersion: UInt16? /* 0x0304 if supported_versions ext seen */ }
extension ServerHelloInfo { static func parse(prefix: Data) -> ServerHelloInfo? }  // tolerant of truncation
```

- `hasECH`: extension type `0xfe0d` present.
- ServerHello layout: 5 record + 4 handshake + 2 version + 32 random + 1 + ≤32 session ID =
  76 bytes before cipher/extensions, so a 128-byte prefix covers the session ID. The
  `supported_versions` extension may lie beyond 128 bytes. If it's not visible,
  `negotiatedVersion` is nil and the session-ID rule is skipped.
- Tests use the captured Go hellos in `Fixtures.swift` and extend the test-only
  `ClientHelloBuilder` with ECH / ALPN extensions via `extensionsBefore:`.

## 6. Connection log + host aggregation

### 6.1 `ConnectionLog` (`Diagnostics/ConnectionLog.swift`)

Core class, implements `ConnectionObserver`. Owned by `ProxyManager` (`let connectionLog =
ConnectionLog()`) and passed to every `ProxyServer` it creates. It **survives stop/start**, so a
user can stop the proxy and then look at what failed. It's cleared by a **Clear** button and on
app exit (memory only).

```swift
final class ConnectionLog: ConnectionObserver {
    func begin(_ start: TraceStart, queue: DispatchQueue) -> ConnectionTrace?
    func refused(_ record: RefusalRecord)
    func snapshot() -> LogSnapshot                  // copy under lock; cheap
    func clear()
    // called by ConnectionTrace on its session queue:
    func updateActive(_ entry: ActiveEntry)
    func complete(_ summary: TraceSummary)
}
```

Storage (all under one `NSLock`; every critical section is a dictionary update or a copy, so a
session queue never waits long):
- `active: [UInt64: ActiveEntry]` keyed by session id: `host`, `port`, phase, `startedAt`.
  For the live count and active rows. Removed in `complete`.
- `hosts: [String: HostRecord]`. Key = lowercased host.
  `HostRecord { host, firstSeen, lastSeen, ports: Set<UInt16>, ips: [String] (≤4), snis: Set<String> (≤4, for IP-literal hosts), connectionCount, bytesUp, bytesDown, recent: Ring<(TraceSummary, TraceOutcome)>(8) }`.
  The outcome is computed once in `complete`.
- Cap **500 hosts**. When full, evict the least recently seen host.
- `recentGlobal: Ring<(host, outcome, endedAt, outbound, isProbe)>(300)` for network-state
  detection (§6.3).
- `refusals: [RefusalGroupKey: RefusalGroup]` (§2.5.4), cap 32.

Memory: ~300 B per summary × 8 × 500 ≈ 1.2 MB worst case.

`LogSnapshot` is a value type (`Sendable`) of the above, so `ScannerSnapshot` (§7.1) can run off
the main thread.

### 6.2 Host verdict

`Diagnostics/HostVerdict.swift`, also pure:

```swift
enum BlockKind { case sni, ip, dns, httpBlockPage, freeze, injected, whitelist, outline }
enum HostStatus { case unknown, working, suspicious(BlockKind), blocked(BlockKind), ruleChanged }
struct HostVerdict { status; confidence; echSeen: Bool; evidence: [TraceSummary] }

func verdict(for record: HostRecord, currentFingerprint: String, network: NetworkState, now: Date) -> HostVerdict
```

Outcome → kind:
- `helloReset`, `helloSilentClose`, `helloBlackhole` → `.sni`. A blackhole could also be IP or
  whitelist; passively we can't tell, and phase 2 resolves it. The UI says "Blocked after TLS
  hello".
- `connectRefused` / `connectTimeout` / `connectUnreachable` → `.ip`
- `dnsBogus` / `dnsFailed` → `.dns`
- `httpBlockPage` → `.httpBlockPage`
- `injectedResponse` → `.injected`, shown as "Blocked by injected response"
- `freeze` → `.freeze`
- `outlineFailed` → `.outline` (feeds network state, not host status)

Algorithm:
1. `window` = `record.recent` where `!isProbe`, outcome ∉ {`clientAborted`, `interrupted`,
   `inconclusive`}, ended within 15 min, **and `fingerprint == currentFingerprint`**.
2. If `window` is empty: `.ruleChanged` if the record has recent traces under a different
   fingerprint, else `.unknown`.
3. Score per kind: high-confidence outcomes count **2**, medium **1**, low **0.5**.
4. **Freeze first:** `score(.freeze) >= 2` → `.blocked(.freeze)`, even if other connections
   are `ok`. Small requests succeed under H, which is the whole point.
5. If the two most recent outcomes are `ok` → `.working`.
6. Take the top kind `k`. Require **network healthy** for at least one trace of `k`: some
   *other* host had an `ok` outcome ending within ±60 s of that trace (from `recentGlobal`).
   - `score >= 2` and healthy → `.blocked(k)`. Confidence high if any high outcome, else
     medium.
   - `score > 0` → `.suspicious(k)` (low).
7. If `network == .whitelistMode` and `k ∈ {.sni, .ip}` → `.blocked(.whitelist)`.

### 6.3 Network state (global banner)

Computed in the snapshot from `recentGlobal` over the last 90 s, using each host's latest
non-probe, non-`interrupted` outcome:

| State | Condition | Banner |
|---|---|---|
| `.offline` | ≥3 distinct hosts, zero `ok`, all `connect*` / `dns*` | "No connectivity. Results paused." Host verdicts are not updated |
| `.whitelistMode` | ≥6 distinct hosts with `helloBlackhole`/`connectTimeout`, ≥1 host `ok`, fail ratio ≥ 0.7 | "Network looks like it's in whitelist mode: only approved sites work." |
| `.outlineDown(profileName)` | ≥3 `outlineFailed` for one VPN profile, no Shadowsocks `ok` in that window | "Outline server for <profile> is unreachable or blocked." |
| `.normal` | otherwise | none |

### 6.4 Profile fingerprint and live rule badge

The badge is computed **at display time** from the current `ProxyConfig`, not stored, so it
updates as soon as a host is added to a profile.

- Matching: `ProxyConfig.profile(for:)`. It already returns the resolved profile (Master's DoH /
  Outline inheritance applied) and uses compiled `DomainMatcher`s. The snapshot takes
  `settings.snapshot` **once** per refresh on the main actor and matches all ≤500 hosts against
  it off the main thread. (The old plan's static `AppSettings.matchingProfile` and the
  "decode on every access" concern are gone: `SettingsStore` decodes once, U4.)
- `SpoofProfile.routingFingerprint` (core, `Shared/SpoofProfile.swift`): a string of the
  routing fields of a **resolved** profile: `routeMode`, `splitMode`, `chunkSize`,
  `tlsRecordFragmentation`, `dohEnabled`, `dohServerURL`, `outlineConfig?.host:port`. The trace
  stores it from `RouteDecision.profile`. After a rule change, old evidence stops counting
  (§6.2 step 1) and the row shows **"Rule changed: reload to retest"** instead of a stale red
  badge.
- U13 helps here: live sessions whose route changed are closed (`.rerouted`, ignored), so the
  client reconnects under the new rule and fresh evidence arrives quickly.
- Badge text: the profile name. If Master matched (`isDefault`), show a muted **"Default"**
  badge.

## 7. UI

### 7.1 Entry points

There are three ways in. All of them push the same `ScannerView(initialFilter:)`.

**a) Toolbar icon (permanent).** `ContentView` toolbar, `.topBarLeading`:
`NavigationLink { ScannerView(initialFilter: .all) }` with an SF Symbol like
`list.bullet.rectangle`. Always visible, even with the proxy stopped (the log survives
stop/start). When the log is empty: *"Start the proxy and use your apps. Hosts appear here."*

**b) Summary line on the main screen (primary path for "why doesn't this site work?").**
Under the "Configure Wi-Fi proxy…" text in `ContentView`, shown only while the proxy is
running **and** the log has at least one host:

```
         Running
 Configure Wi-Fi proxy to
     127.0.0.1:8090

   42 hosts · 3 blocked  ›
```

- It's a `NavigationLink` styled as a capsule (`.callout`, secondary background).
- The "· N blocked" part (red) appears only when `blockedCount > 0`. It counts hosts with
  `.blocked`. `.suspicious` hosts aren't counted, so the line doesn't cry wolf.
- `ScannerView(initialFilter: blockedCount > 0 ? .problems : .all)`
- If the network state isn't `.normal`, the line shows the banner text instead, e.g.
  `⚠︎ Whitelist mode ›` or `⚠︎ Outline server unreachable ›`. This takes priority over
  counts.
- Accessibility label: "42 hosts seen, 3 blocked. Open network scanner."

Data source: the main screen must not run the full scanner pipeline every second.
- `ProxyManager` gets `@Published private(set) var logSummary: LogSummary?` (`hostCount`,
  `blockedCount`, `network: NetworkState`).
- It's refreshed by a **2 s timer** that runs only while `status == .running`. The timer starts
  where `status` becomes `.running` and is invalidated in `stop()` and `fail(with:)`.
- Each tick: `connectionLog.snapshot()` + `settings.snapshot` (both taken on main) →
  `ScannerSnapshot.build` on a private serial utility queue owned by `ProxyManager` → publish on
  main. Skip publishing if the value didn't change, so `ContentView` doesn't re-render for
  nothing.
- After `stop()`, keep the last summary but hide the line. The toolbar icon remains the way in
  while stopped.

The verdict pass is shared with `ScannerModel`: both call
`ScannerSnapshot.build(log: LogSnapshot, config: ProxyConfig, now: Date) -> ScannerSnapshot`
(rows + network state + counts + refusal groups), in `Diagnostics/ScannerSnapshot.swift`. It's
pure core code, so it's unit-tested under `swift test`. The summary just reads
`snapshot.counts`. The cost is fine at 2 s: ≤500 hosts × ≤8 summaries.

**c) Settings link (where users already go to edit domains).** In `SettingsView`'s
"Profiles" section, after the "Add Profile" button:

```swift
NavigationLink {
    ScannerView(initialFilter: .problems)
} label: {
    Label("Find Hosts to Add", systemImage: "list.bullet.rectangle")
}
```

- If the Problems filter is empty when the screen opens, `ScannerView` falls back to **All**
  (rule: an initial `.problems` with zero matches → `.all`). The user never lands on an empty
  list when there are hosts to show.
- Coming back from the scanner, `SettingsView` already shows profiles added through the sheet,
  because it observes `SettingsStore`.

`ScannerView(initialFilter:)` stores the filter in `@State` initialised from the parameter,
so the user can still switch freely after opening.

### 7.2 `ScannerModel` (`Spoofy/ScannerModel.swift`)

`@MainActor final class ScannerModel: ObservableObject`, created by `ScannerView` with the
`ProxyManager` (for `connectionLog`) and `SettingsStore` from the environment.
- `@Published rows: [HostRow]`, `refusals: [RefusalRow]`, `network: NetworkState`,
  `activeCount: Int`.
- 1 s `Timer` runs only while the screen is visible (`start()`/`stop()` from
  `onAppear`/`onDisappear`). Each tick: take `connectionLog.snapshot()` and `settings.snapshot`
  on main, `ScannerSnapshot.build(...)` on a private serial utility queue → publish on main.
- **While in selection (edit) mode, refresh pauses** so rows don't jump under the user's
  finger. Show a small "Paused" label; resume on Done.
- Sort: blocked → suspicious → rule changed → others; within a group by `lastSeen` desc.

`HostRow` (core, in `ScannerSnapshot.swift`): `{ id: host, host, ports, ips, sni (if IP literal and differs), kinds: Set<PayloadKindTag>, connectionCount, lastSeen, profileID, profileName, isDefaultProfile, verdict }`.

### 7.3 `ScannerView` (`Spoofy/ScannerView.swift`)

- `.searchable` (substring on host / IP / SNI).
- Segmented filter: **All · Problems · No rule** (No rule = matched Master).
- Optional banner section for `NetworkState`.
- `List(selection: $selection)` with `EditButton`. Row layout:
  ```
  rr3---sn-abc.googlevideo.com                 [YouTube]
  443 · 12 conn · 2m ago            ● Blocked after TLS hello  ECH
  ```
  Verdict colours: blocked red, suspicious orange, rule changed gray, working none.
- Protocol chip on non-TLS rows (`HTTP`, `SSH`, `SMTP`, `TCP`). The **Couldn't carry**
  section and the "not shown" footer go at the end of the list (§2.5.6).
- Bottom toolbar when `selection` isn't empty: **Add to Profile…** · **New Profile…** (both
  open §7.4 with a different default target).
- Context menu: Copy host · Add to profile… · Hide.
  - Hide adds a pattern to a persisted `scannerHiddenHosts` list (UserDefaults key
    `scannerHiddenHosts`, `[String]`, owned by `SettingsStore` with `setHiddenHosts(_:)`; it
    isn't part of export). Matching uses `DomainMatcher`, so the same wildcard syntax works for
    noise like telemetry.
  - The list footer shows "Hidden (N)", which opens an editable list.
- Toolbar menu: Clear log.

### 7.4 `AddPatternsSheet` (`Spoofy/AddPatternsSheet.swift`)

Input: selected `HostRow`s. Sections:

1. **Patterns**: one row per selected host, with a picker **exact** (`host`) / **wildcard**
   (`*.base`). Default is wildcard unless the host is an IP literal (always exact). Identical
   results are deduped.
   - For an IP-literal host whose ClientHello had an SNI: the note and hint from §2.5.5.
2. **Target**: `Picker` of `settings.customProfiles` + "New profile". Master is excluded because
   it already matches everything.
   - New profile shows a name field (default: base domain of the first host), route mode, and
     split mode.
   - Defaults come from the dominant verdict kind (and payload kind, §2.5.5):
     - `.sni`/`.injected` → Split + SNI;
     - `.dns` → Split + None + DoH on;
     - `.ip`/`.freeze` → VPN if Master has an Outline config (`inheritOutlineConfig = true`),
       else Split + SNI with a warning "IP blocks usually need VPN";
     - otherwise Split + SNI.
3. **Warnings**, computed by simulating the save: build
   `ProxyConfig(profiles: simulatedProfiles, port:, allowLANAccess:)` and call `profile(for:)`
   for each pattern's host:
   - pattern already in target → skipped;
   - "`host` will still match **X** first (X is above this profile)" when the simulated match
     isn't the target;
   - a target profile that is disabled → "Profile is off; enable it to apply".

Save goes through `SettingsStore`, which writes through and calls `onChange`, so the running
server picks the new rules up via `server.update` (U13 closes live sessions whose route
changed; the next connection uses the new rule):
- New store API (core, unit-tested in `SettingsStoreTests`):
  - `SpoofProfile.makeCustom(name:domainPatterns:routeMode:splitMode:dohEnabled:)`; today's
    `addProfile()` literal moves into it with the current defaults.
  - `SettingsStore.addProfile(_ profile: SpoofProfile)` inserts in front of Master (the existing
    `addProfile()` calls it with `makeCustom(name: "", domainPatterns: [])`).
  - `SettingsStore.addPatterns(_ patterns: [String], to id: UUID) -> Int` appends the ones not
    already present (case-insensitive) and returns how many were added. One commit, so one
    `onChange`.
- Then dismiss, leave edit mode, and show a confirmation ("Added 3 patterns to YouTube").

`Diagnostics/BaseDomain.swift`: `suggestWildcard(for host:) -> String?`. It returns nil for IPs
and uses the last 2 labels, or the last 3 when the last two form a known 2-level suffix (small
embedded list: `co.uk`, `com.au`, `co.jp`, `com.br`, `com.tr`, `com.ua`, `org.ru`, `msk.ru`,
`spb.ru`, `co.il`, …). Wildcards are editable after saving anyway.

### 7.5 `HostDetailView` (`Spoofy/HostDetailView.swift`)

- **Status**: verdict title, one-paragraph explanation, suggested fix (table §7.6), confidence.
- **Rule**: matched profile → `NavigationLink` to `ProfileEditView(profileID:)`.
- **Addresses**: IPs, ports, SNIs seen; port/kind pairs (§2.5.5).
- **Recent connections** (latest 8, probes marked): time, inbound, outcome label and a compact
  timeline, e.g.
  `CONNECT · TLS h2 · DNS 12 ms · RTT 48 ms · hello→RST 3 ms (early) · ↑517 B ↓0 B`, plus
  `Split (SNI) configured · not applied: not TLS` when `applied` differs from `outbound`.
- **Actions**: Add to profile… · Diagnose (phase 2) · Find a fix (phase 3).

### 7.6 Verdict copy

| Kind | Title | Explanation | Suggested fix |
|---|---|---|---|
| sni | Blocked after TLS hello | The connection opened, but after the browser sent the site name the reply was cut (reset or silence). Typical DPI SNI blocking. | Add to a profile with SNI split |
| sni + ECH | Blocked after TLS hello (ECH) | Same, and the hello used Encrypted Client Hello, which is itself blocked in Russia. | Disable ECH in the browser; Diagnose to confirm |
| injected | Fake response | A reply arrived faster than the server could physically answer, or wasn't valid TLS. | SNI split |
| ip | Address unreachable | TCP connection to the server's IP fails. Splitting can't fix this. | VPN profile |
| dns | DNS spoofed | The name resolved to a non-public address. | Enable DoH |
| httpBlockPage | HTTP block page | Plain-HTTP request was answered by a block page. | Use HTTPS or a split/VPN profile |
| freeze | Stalls after ~16 KB | The connection works, then stops after a few KB. Typical for foreign hosting on mobile networks. | VPN profile |
| whitelist | Network whitelist | Only approved sites work on this network right now. | VPN through an allowed endpoint |
| ruleChanged | Rule changed | Evidence was collected under different settings. | Reload the app/page to retest |

## 8. Project / housekeeping (phase 1)

- `Package.swift`: add `"Diagnostics"` to `sources:`. CLAUDE.md: add `Diagnostics/` to the
  structure and to the core-boundary rule.
- New core files (package picks them up; **add each to the app target in `project.pbxproj`**,
  new `Diagnostics` group):
  - `Diagnostics/{ConnectionObserver, ConnectionTrace, ConnectionLog, PayloadSniffer, TraceClassifier, HostVerdict, NetworkState, ScannerSnapshot, BaseDomain, DetectionConfig}.swift`
  - `Proxy/SOCKS4Parser.swift`
- New app files (pbxproj): `Spoofy/{ScannerModel, ScannerView, HostDetailView, AddPatternsSheet}.swift`
- Modified core:
  - `Session`: `CloseReason`, trace begin / payload / finish hooks, refusal reports, relay
    observer + 2 s tick.
  - `SessionScope`: `trace`.
  - `ServerConnector` / `DialAttempt`: DNS and attempt events via `session.trace`.
  - `Outbound` (`ShadowsocksOutbound`): DoH and `.outlineConnectFailed` events.
  - `ConnectionRelay`: `RelayObserver`.
  - `ProxyServer`: `observer` parameter, over-capacity refusal, `CloseReason` at its call sites.
  - `Inbound` / `HTTPHeadParser` / `SOCKS5Parser`: `InboundFailure`, `socks4`.
  - `TLSParser`: `ClientHelloInfo`, `ServerHelloInfo`.
  - `SpoofProfile`: `routingFingerprint`, `makeCustom`. `SettingsStore`: `addProfile(_:)`,
    `addPatterns(_:to:)`, hidden hosts.
- Modified app: `ProxyManager` (owns the log, passes it to `ProxyServer`, `logSummary` + 2 s
  timer while running), `ContentView` (toolbar entry + summary line), `SettingsView` ("Find
  Hosts to Add" link).
- Logging: classifier outcomes at `.debug` with `privacy: .private` for host names. The existing
  session close line stays as is.
- README: short "Network scanner" section with a screenshot.

---

# Phase 2: Diagnose (active probes)

Passive data says *that* a host fails and roughly *where*. It can't separate SNI from IP from
whitelist. Diagnose runs a short probe sequence for one host on user request.

## 9. Building blocks

### 9.1 `SyntheticClientHello` (`TLS/SyntheticClientHello.swift`)

Named so it doesn't collide with the test-only `ClientHelloBuilder` in
`Tests/SpoofyCoreTests/Support` (the test module's type would shadow a core type of the same
name).

`static func build(sni: String?, includeFakeECH: Bool = false) -> Data`. It produces a
realistic browser-like TLS 1.3 ClientHello as one record:
- `legacy_version 0x0303`, 32 random bytes, 32-byte random `legacy_session_id`.
- Cipher suites: GREASE, `1301 1302 1303 c02b c02f c02c c030 cca9 cca8`.
- Extensions (in order):
  - GREASE
  - `server_name` (omitted when `sni == nil`)
  - `extended_master_secret`
  - `renegotiation_info`
  - `supported_groups` [GREASE, `001d`, `0017`, `0018`]
  - `ec_point_formats` [0]
  - `session_ticket`
  - ALPN [`h2`, `http/1.1`]
  - `status_request`
  - `signature_algorithms` [`0403 0804 0401 0503 0805 0501 0806 0601`]
  - `key_share` (x25519 public key from `Curve25519.KeyAgreement.PrivateKey()` in CryptoKit)
  - `psk_key_exchange_modes` [1]
  - `supported_versions` [GREASE, `0304`, `0303`]
  - optional fake ECH `0xfe0d`: outer type 0, KDF `0001`, AEAD `0001`, random config_id,
    32-byte random enc, ~200 random payload bytes, i.e. GREASE-ECH shape
  - `padding` to a total of 517 bytes
- Must round-trip through `ClientHelloReader` (→ `.clientHello` with the right `sniOffset`) and
  `ClientHelloInfo.parse`, so `TLSDesyncer` splits it exactly like a real hello.

We never complete the handshake. A **ServerHello (or a server alert) arriving is the success
signal**, because it proves the hello got past the DPI and the server answered.

### 9.2 `TLSProbe` (`Diagnostics/TLSProbe.swift`)

```swift
struct TLSProbeRequest { ip: String; port: UInt16; sni: String?; fakeECH: Bool; desync: DesyncParameters? /* nil = unsplit */ }
enum TLSProbeResult {
    case serverHello(tls13: Bool), alert(code: UInt8, early: Bool), httpText, otherData
    case reset(t: TimeInterval, early: Bool), closed(t: TimeInterval, early: Bool), silence
    case connect(ConnectError)
}
final class TLSProbe {
    init(dialer: Dialing, observer: ConnectionObserver, target: DispatchQueue)
    func run(_ r: TLSProbeRequest, timeout: TimeInterval = 5,
             completion: @escaping (TLSProbeResult, TraceSummary) -> Void)
}
```

- Each probe gets its own `SessionScope` (id from a probe counter in a separate range, so it
  never collides with session ids) targeting the probe engine's queue. The scope carries an
  `isProbe` trace from `observer.begin`, so DNS/connect/RTT recording and the classifier are
  reused unchanged.
- Connects **by IP** through `dialer.dial(…, resolver: nil, session: scope)` (IP literals skip
  DNS, N10).
- Sends the hello unsplit, or `TLSDesyncer.split(...)` segments through
  `SegmentWriter.write`, exactly like a desync session.
- Reads up to 2 KB with the same `RelayObserver` hooks feeding the trace (a one-sided read
  loop, not a relay), then maps the trace outcome + prefix to the result. `scope.close()` at
  the end.
- Probe traces appear in the host's detail view and are excluded from passive verdicts.
- Unit-testable over `FakeConnection` with a fake `Dialing`; loopback-tested against the
  origin behaviours in §14.

### 9.3 System DNS for comparison

`getaddrinfo` on a dedicated serial queue owned by the probe engine (blocking is fine there; no
`DispatchQueue.global()`), plus `DoHResolver` against the Master DoH URL and a second fixed
endpoint (`https://dns.google/dns-query`) in case the first is blocked.

## 10. Diagnose sequence

`Diagnostics/ProbeEngine.swift`, `diagnose(host:port:progress:completion:)`. Steps run
**sequentially** with 1 s gaps (parallel probes confound results and look like scanning).
Each step has a 5 s timeout, and the engine stops as soon as the verdict is determined. The
engine is a state machine on its own serial queue: `idle → running(step) → done(report)`, with
`cancel()` moving any state to `done(.cancelled)` and closing the current probe scope.

```
D0  Control: TCP connect to a known-reachable domestic host (configurable, default "ya.ru:443").
        fail → abort: "No network / everything blocked"
D1  DNS: systemIPs (getaddrinfo), dohIPs (DoH ×2). Note bogons and whether the sets intersect.
D2  TCP: connect to systemIPs[0]:port (and dohIPs[0] if disjoint).
D3  Control SNI: TLSProbe(ip, sni: "<10 random letters>.com")   // a name no blacklist contains
D4  Real SNI, unsplit: TLSProbe(ip, sni: host)
D5  if D4 blocked: real SNI, SNI split → quick hint that splitting helps
D6  if D3 failed: whitelist SNI: TLSProbe(ip, sni: DetectionConfig.whitelistSNIs[0...])
D7  if D4 passed, or passive traces showed ECH: TLSProbe(ip, sni: host, fakeECH: true)
D8  if D1 sets disjoint: D4 against dohIPs[0]
```

For non-TLS hosts only D0–D2 run (§2.5.5).

### 10.1 Decision table

| Evidence | Diagnosis |
|---|---|
| D1 system IP bogon, or D4 fails on system IP but D8 passes on DoH IP | **D: DNS spoofing** (fix: DoH) |
| D2 refused/timeout on every IP | **B: IP blocked (TCP)** |
| D2 ok, D3 fail, D6 ok | **I: whitelist mode** |
| D2 ok, D3 fail, D6 fail/none | **B: IP blocked (TLS dropped for any name)** |
| D3 ok, D4 fail | **A: SNI blocked**, subtyped by D4 result (early RST / blackhole / injected). D5 tells whether splitting already helps |
| D4 ok, D7 fail | **G: ECH blocked** |
| D4 ok, D7 ok, passive `freeze` evidence | **H: 16–20 KB freeze** (handshake passes, bulk data doesn't) |
| D4 ok, D7 ok, no freeze evidence | **Handshake not blocked**. Problem is elsewhere (throttling, app-level, server) |

The report lists each step with its result and timing, and is stored on the `HostRecord`
(latest one only). It overrides the passive verdict's kind until the rule fingerprint changes.

### 10.2 Residual blocking

Some DPI keeps state after a trigger. New source ports avoid per-flow state, but per-IP state
may survive. If D3 *and* D4 fail right after a passive SNI block, re-run D3 once after a 15 s
cool-down before declaring B/I.

### 10.3 UI

"Diagnose" button in `HostDetailView` (disabled unless the app is in the foreground and the
network state isn't `.offline`). It shows a step list with spinners/✓/✗ and then the
diagnosis card. It doesn't need the proxy to be running, because probes don't go through the
listener. `ProxyManager` owns the `ProbeEngine` (one at a time).

### 10.4 Throttling (stretch)

Only if the host serves something ≥256 KB at `/` (we don't know resource URLs otherwise):
download via the phase 3 confirm path with unsplit vs SNI-split overrides and compare
throughput. If it's ≥5× faster split → **E: throttled**. Otherwise don't claim anything.

---

# Phase 3: Find a fix + auto-config

## 11. Strategy space

```swift
struct FixStrategy: Hashable {
    var routeMode: RouteMode
    var desync: DesyncParameters?   // nil = split mode .none
    var dohEnabled: Bool
    var fingerprint: String         // same scheme as SpoofProfile.routingFingerprint
}
```

Candidate order (cheapest / least invasive first):
1. If the diagnosis is DNS: `doh+none`, then `doh+sni`
2. `sni`, `sni+rec`
3. `firstByte`, `firstByte+rec`
4. `chunk(1)`, `chunk(5)+rec`, `chunk(20)`
5. `random`, `random+rec`
6. `vpn` (only if Master has an Outline config)

For IP/whitelist diagnoses, skip straight to `vpn` (splitting can't help). For non-TLS
payload kinds only DoH and `vpn` are candidates (§2.5.5).

## 12. Two-stage search

**Stage 1, screen (fast, in-process):** `TLSProbe` with the real SNI against the target IP
(DoH IP if the diagnosis is DNS) using each candidate's `DesyncParameters`. Passing =
`serverHello`. Stop after the first **2** passing candidates. VPN skips stage 1.

**Stage 2, confirm (real client):** the synthetic hello isn't byte-identical to the user's
browser, so confirm with a real TLS client through the actual proxy path:

- `ProbeOverrides` (`Diagnostics/ProbeOverrides.swift`): `[host: SpoofProfile]` under a lock,
  entries expire after 30 s. It plugs into the existing `Router(profileForHost:)` seam:
  `ProxyServer` builds each session's router as
  `Router { overrides.profile(for: $0) ?? config.profile(for: $0) }` when it has overrides
  (`ProxyServer.init(…, overrides: ProbeOverrides? = nil)`).
  `RouteDecision` gets `isOverride: Bool`, and `Session.begin` marks the trace `isProbe` when
  it's set. Adding or expiring an override doesn't reroute live sessions.
- `URLSession(.ephemeral)` with `connectionProxyDictionary = ["HTTPEnable": 1, "HTTPProxy":
  "127.0.0.1", "HTTPPort": port, "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort":
  port]`, `GET https://host/`, 10 s timeout.
- Success = any `HTTPURLResponse` (any status) **and** the proxy-side probe trace classifies
  as `ok`. Run twice; both must pass.
- Requires the proxy to be running (the button says so). Real user traffic to the same host
  during the ~20 s confirm window also uses the override. That's acceptable and documented
  in the UI ("testing…").

**Spike first:** a loopback test under `swift test` shows whether `URLSession` honours those
keys on macOS (CONNECT reaching `LoopbackOrigin` through `ProxyServer`). iOS still needs a
device check. If iOS doesn't honour them, fall back to stage-1-only results labelled "likely
works".

If every candidate fails: wait 30 s (residual state) and re-run stage 1 for the top 3 before
reporting "No working strategy found".

## 13. From results to profiles

`FixFinder.run(hosts: [String])` works on a single host from the detail view or on a
multi-selection from the scanner (cap 10 hosts per run). Hosts are processed sequentially with
progress shown.

Each host gets `FixResult { host, winner: FixStrategy?, attempts: [(strategy, stage1, stage2)] }`.

Proposals:
1. Group hosts by `winner.fingerprint`.
2. For each group: if a **custom profile with the same routing fingerprint** exists, propose
   "Add N patterns to *<profile>*". Otherwise propose "Create profile *<base domain>* (SNI
   split)".
3. Hosts without a winner are listed separately with their diagnosis.

Proposals open in `AddPatternsSheet` in a **multi-target** mode (one section per proposal,
each toggleable). **Nothing is applied without the user confirming.** Saving goes through
`SettingsStore.addProfile(_:)` / `addPatterns(_:to:)`. The fingerprint changes, so passive
verdicts reset to "rule changed" and the next real traffic re-validates them.

---

## 14. Testing

Everything core runs under `make test` (`swift test`, macOS). Each step in §16 starts with a
failing test (CLAUDE.md loop). The `xcodebuild` check runs whenever `Spoofy/` or the file list
changes.

**Unit (pure, fixture-driven):**
- `TraceClassifier`: one fixture `TraceSummary` per rule R-1–R9, including timing edge cases
  (rtt nil, rtt < 10 ms, exactly at 0.5×), first-event-wins end reasons, ECH flag propagation,
  `.rerouted` / `.proxyStopped` → `interrupted`.
- `CloseReason.endReason` for every case; `ConnectError(errors)` precedence.
- `HostVerdict`: scoring, freeze-beats-ok, two-recent-ok → working, healthy-network
  requirement, fingerprint filtering → `ruleChanged`, whitelist override, `interrupted`
  ignored.
- `NetworkState`: offline / whitelist / outlineDown thresholds.
- `ClientHelloInfo` (SNI, ECH, session ID, ALPN) on the captured Go hellos plus builder-made
  ones; `ServerHelloInfo` on TLS 1.2 / 1.3 / truncated prefixes.
- `PayloadSniffer`: each kind from real first bytes (TLS hellos, HTTP methods, `SSH-2.0`,
  `220 `, `* OK`, random bytes, truncated TLS header).
- Refusals (§2.5.4): `SOCKS5Parser` commands 2/3, auth-only greeting, address type; SOCKS4 and
  4a requests; origin-form, `https://`, `PRI *` and over-long heads in `HTTPHeadParser`. Each
  split at every byte boundary, as the existing parser tests do.
- `ScannerSnapshot`, `BaseDomain`, `SpoofProfile.routingFingerprint`, `makeCustom`,
  `SettingsStore.addProfile(_:)` / `addPatterns(_:to:)` (dedupe, one `onChange`), AddPatterns
  simulation warnings via `ProxyConfig`.
- `SyntheticClientHello` (phase 2): 517 bytes, `ClientHelloReader` finds the right
  `sniOffset`, splits with every `SplitMode`.

**Fake connection (`SessionTests` style, with a `RecordingObserver`):**
- Each path in the §2.2 table calls `payloadSent` once with the right kind and `applied`
  (desync + hello, desync + raw → `.passthrough(.notTLS)`, desync + silent client, direct with
  and without pipelined leftover, plain HTTP, Shadowsocks).
- Each refusal reaches `observer.refused` exactly once; a client closing mid-handshake reaches
  nothing.
- First end event wins: upstream reset followed by the client's `ECANCELED` keeps
  `.serverReset`.
- `reroute` closing a session → `.rerouted`; `ProxyServer.stop()` → `.proxyStopped`.
- With `observer == nil`, behaviour and the existing tests are unchanged.

**Loopback harness (`LoopbackHarnessTests`).** Replaces the old plan's Python test server. New
`LoopbackOrigin.Behaviour` cases:
- `.resetAfterFirstChunk` (close with linger 0 / `NWConnection.forceCancel`)
- `.silent` (same as `.recordAll`, named for intent)
- `.closeAfterFirstChunk` (FIN)
- `.replyAfterFirstChunk(Data)` (e.g. `HTTP/1.1 302` on a TLS tunnel)
- `.sendThenStall(bytes: Int)` (16 KB, then nothing)

Point the proxy at each by IP via CONNECT and SOCKS5 with a `ConnectionLog` attached, and check
the outcome per behaviour and the stall check (with `stallSeconds` / `helloBlackholeMin`
injectable through `DetectionConfig` overrides for test speed). "Early" timing can't be
simulated on loopback (RTT < 10 ms, so no timing verdicts by design); unit fixtures cover it.
Refused requests over the real listener: SOCKS4, UDP ASSOCIATE, origin-form, over-capacity
(the existing 200-cap test plus a refusal assertion).

**Manual device checklist** (per release, for the user):
- The scanner fills while browsing in Safari; badges match Settings; adding a host from the
  scanner changes the badge within a second and the site reloads through the new rule.
- Stop / start keeps the log; Clear empties it.
- Field matrix in Russia (record results in the PR):
  - **Networks:** home ISP, plus mobile (MTS / Beeline / MegaFon / T2), including a region with
    whitelist mode.
  - **Targets:** known SNI-blocked sites; an IP-blocked address; a Cloudflare site with ECH
    enabled in Firefox; a ≥1 MB file on a Hetzner/DigitalOcean VPS for H; a plain-HTTP blocked
    site for C.
  - Tune `DetectionConfig` from the results.
- Regression: each split mode, plus VPN, SOCKS5 and HTTP, on the same blocked sites, with the
  scanner on. The observer must not change bypass behaviour.

## 15. Risks / open questions

- **Timing reliability.** "Early" needs a trustworthy RTT. With `tcpRTT` from the
  establishment report it should be fine. Servers inside Russia (< 10 ms) get no timing
  verdicts by design.
- **HTTP/2 connection coalescing.** Browsers reuse one connection for several hosts sharing
  an IP/cert, so those extra hosts never reach the proxy and never appear. Say so in an
  info footnote.
- **Noise.** Preconnects and connection racing produce aborted connections. R4/R5 send them
  to `clientAborted`, and verdicts need repeated evidence plus a healthy network. Rule changes
  (U13) and Stop produce closes that would look like blocks; R-1 removes them.
- **`.waiting` error codes.** N11 now fails an attempt on `.waiting`, so a refused connect
  returns quickly. Verify on an iOS 16 device that the error is `posix(ECONNREFUSED)` (not a
  generic code), or B shows as `connectFailed(.other)`.
- **Data-transfer report after cancel** may be empty. Mitigated by the early collection in
  the stall check and by starting the final collection before `scope.close()`.
- **Observer on the hot path.** Per-chunk calls run on the session queue and only update
  counters; the log lock is taken on phase changes and at finish, not per chunk. Measure a
  100 MB download with the scanner on vs off (same method as refactor §10).
- **Synthetic hello vs. real hello.** DPI may treat them differently (fingerprinting). Stage
  2 exists for this. If the URLSession spike fails on iOS, results are marked "likely".
- **Lists that go stale.** `blockPageHosts`, `whitelistSNIs` and the control host need
  maintenance. Keep them in `DetectionConfig` and consider fetching them remotely later.
- **Protocol blind spots.** UDP from apps that don't use SOCKS5 and apps that ignore the
  system proxy never reach Spoofy. The footer says so; nothing more can be done without a
  packet tunnel.
- **Privacy.** The log holds host names and SNIs in memory only. Never written to disk or
  included in export, and Clear wipes it. Payloads aren't kept beyond a 128-byte server
  prefix. Probe traces and refusals follow the same rule.

## 16. Order of work

Continues the refactor numbering. One step = one commit (`Step 5c: …`), red → green → refactor,
`make test`, plus `xcodebuild` when `Spoofy/` or the file list changes. Each leaves the app
shippable: until step 5h nothing is visible to users.

**Phase 1**

| Step | Change | Tests | Manual |
|---|---|---|---|
| 5a | `CloseReason` and `InboundFailure` replace the free-text reasons; same log text | unit: `description` matches the old strings; existing suite green | — |
| 5b | `InboundProtocol.socks4` + `SOCKS4Parser` (refuse with `5B`); origin-form / `https://` / `PRI *` cases in `HTTPHeadParser` | parser tests at every byte boundary; loopback: SOCKS4 client gets `00 5B` | — |
| 5c | `ClientHelloInfo`, `ServerHelloInfo`, `PayloadSniffer`; `Diagnostics/` folder in `Package.swift` and pbxproj | unit | xcodebuild |
| 5d | `ConnectionObserver`, `ConnectionTrace` (lifecycle, end reasons), `SessionScope.trace`, `Session` begin/finish hooks, `ServerConnector` and `ShadowsocksOutbound` events, `ProxyServer(observer:)` | fake-connection + loopback with a `RecordingObserver` | — |
| 5e | `RelayObserver`, payload hooks (§2.2), `AppliedStrategy`, stall check, transport reports | fake-connection; loopback origin behaviours | — |
| 5f | `ConnectionLog` (hosts, active, refusals, eviction) + `TraceClassifier` | unit fixtures; loopback outcome per behaviour | — |
| 5g | `HostVerdict`, `NetworkState`, `routingFingerprint`, `ScannerSnapshot`, `BaseDomain`; `SettingsStore.addProfile(_:)` / `addPatterns` / hidden hosts, `makeCustom` | unit | — |
| 5h | `ProxyManager` owns the log; `ScannerModel`, `ScannerView`, `HostDetailView`; toolbar entry | xcodebuild | browse, see hosts, badges, stop/start keeps the log, Clear |
| 5i | `AddPatternsSheet` | xcodebuild | add to existing / new profile; warnings; badge flips; site reloads on the new rule |
| 5j | `logSummary` + main-screen summary line; Settings "Find Hosts to Add" | xcodebuild | line appears while running, opens Problems/All correctly |
| 5k | Field test in Russia, tune `DetectionConfig`, README. **Release phase 1.** | — | field matrix §14 |

**Phase 2**

| Step | Change |
|---|---|
| 6a | `SyntheticClientHello` + tests |
| 6b | `TLSProbe` (probe scopes, one-sided read loop) + fake/loopback tests |
| 6c | System DNS comparison + `ProbeEngine` state machine + decision table tests |
| 6d | Diagnose UI. Field test. **Release phase 2.** |

**Phase 3**

| Step | Change |
|---|---|
| 7a | URLSession proxy spike (macOS loopback test, then a device check) |
| 7b | `ProbeOverrides` via `Router(profileForHost:)`, `RouteDecision.isOverride` |
| 7c | `FixFinder` (two stages) + tests with fake probes |
| 7d | Multi-target `AddPatternsSheet`. **Release phase 3.** |
