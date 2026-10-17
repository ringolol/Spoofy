# Plan: Network scanner, block detection and auto-fix

Status: draft · 3 phases. Phase 1 (scanner + passive classifier) is shippable on its own.
Phase 2 (active diagnosis) and phase 3 (fix finder / auto-config) build on it.

## Goal

A new **Network** screen that lists every host/IP that went through the proxy. It shows:

- which profile (rule) each host currently matches, as a badge;
- whether the host looks **blocked**, and **how** (SNI, IP, DNS, HTTP block page, 16–20 KB
  freeze, ECH, whitelist mode), with confidence and evidence;
- multi-select → add to an existing profile or create a new one.

Later phases add a per-host **Diagnose** (active probes that tell SNI vs IP vs DNS vs whitelist
apart) and **Find a fix** (try every strategy Spoofy has, then propose profiles automatically).

Non-goals:
- Raw packet inspection (TTL / IP-ID / late "real" answers). iOS gives a normal app no raw
  sockets, and the kernel TCP stack hides those packets from us. Revisit only if a
  `NEPacketTunnelProvider` mode ever ships.
- QUIC / UDP. The proxy only carries TCP, so QUIC blocking is invisible (browsers fall back
  to TCP through the proxy anyway).
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

- `ProxyServer.readRequest` dispatches to `HTTPHandler`, `HTTPSHandler` (CONNECT) and
  `SOCKS5Handler`. Each calls `settings.matchingProfile(for: host)` once per connection
  (`HTTPHandler.swift:26`, `HTTPSHandler.swift:26`, `SOCKS5Handler.swift:250`).
- All three handlers hold **identical copies** of `resolveAndConnect` /
  `createServerConnection` / `waitForReady` (DoH or system DNS, `noDelay`,
  `preferNoProxies`, 10 s connect timeout). `waitForReady` ignores `.waiting(error)`, so a
  refused connect sits in `.waiting` until the 10 s timeout and the reason is lost.
- ClientHello handling: when `splitMode != .none`, handlers read the full ClientHello
  record, split it with `TLSDesyncer.split`, send the segments with `sendSegments`, then start
  `ConnectionRelay.relay`. With `.none` (or VPN) they blind-relay from the start.
- `ConnectionRelay.relay(left:right:label:queue:completion:)`: `left` is always the client and
  `right` always the server (or `ShadowsocksStream`). It has a 120 s idle timeout checked every
  15 s. It doesn't count bytes or record why it ended.
- `TLSMessage` parses records and finds the SNI offset by walking extensions. The other
  extensions and the session ID are skipped.
- `AppSettings.profiles` **JSON-decodes from UserDefaults on every access**.
  `matchingProfile` returns the first enabled profile whose patterns match. A profile with
  **empty** `domainPatterns` matches everything (that's how Master works, but it also applies
  to an enabled custom profile with no domains, see §11).
- `SettingsView` and `ProfileEditView` reload from `AppSettings` in `.onAppear`, so profile
  edits made elsewhere show up when you navigate back. No extra plumbing needed.
- Deployment target **iOS 16** (rules out `ProxyConfiguration`, which needs iOS 17). The
  project uses `objectVersion = 56` with no synchronized folders, so every new file must be
  registered in `project.pbxproj`. There's **no test target** yet.
- Verified in the iOS 26.5 SDK (all available since iOS 13/14):
  `NWConnection.requestEstablishmentReport` → `resolutions[].{source, duration,
  successfulEndpoint, dnsProtocol}`, `handshakes[].{definition, handshakeRTT}`;
  `startDataTransferReport().collect` → `aggregatePathReport.{transportMinimumRTT,
  transportSmoothedRTT, retransmittedTransportByteCount, receivedApplicationByteCount, …}`.

---

# Phase 1: scanner + passive classifier

## 1. Shared server connector (refactor, no behaviour change)

New `Proxy/ServerConnector.swift`, replacing the three copies:

```swift
final class ServerConnector {
    init(queue: DispatchQueue)

    /// Resolve (DoH if given, else system via NWConnection) and connect.
    /// Identical behaviour to today's per-handler code, plus trace hooks.
    func connect(host: String, port: UInt16, dohResolver: DoHResolver?,
                 trace: ConnectionTrace?, completion: @escaping (NWConnection?) -> Void)
}
```

Trace hooks inside:
- DoH path: `trace?.dnsStarted()` / `trace?.dnsFinished(ips:source: .doh)`.
- `.waiting(let error)`: `trace?.connectWaiting(error)`. **Still keep waiting** (don't change
  retry behaviour). We only remember the last error so a timeout can be attributed to
  `ECONNREFUSED` / `ENETUNREACH` / `EHOSTUNREACH`.
- `.ready`: `trace?.connected(conn)`, which calls `requestEstablishmentReport` and
  `startDataTransferReport()` (§2.3).
- `.failed(error)` / 10 s timeout: `trace?.connectFailed(error or .timeout)`.

`ProxyServer` creates one `ServerConnector` and passes it to the handlers (like `resolverCache`
today). The Shadowsocks path is unchanged apart from trace calls around
`ShadowsocksStream.connect` (`outlineConnectFailed` on nil).

Do this first and ship-test it on its own. It touches every connection path.

## 2. Connection trace

New `Diagnostics/ConnectionTrace.swift`. One reference-type object per proxied connection,
mutated from the concurrent proxy queue under an `NSLock`. On finish it produces an
immutable `TraceSummary` (value type) for the log.

### 2.1 Lifecycle state machine

```
created ──► resolving ──► connecting ──► connected ──► payloadSent ──► responding ──► ended
   │            │              │             │              │              │
   └────────────┴──────────────┴─────────────┴──────────────┴──────────────┴──► ended
```

| Phase | Entered by | Recorded |
|---|---|---|
| `created` | handler entry, right after profile lookup | `id`, `startedAt` (wall `Date` + mono ns), `host` (lowercased), `port`, `isIPLiteral`, `proto` (`.http`/`.connect`/`.socks5`), `profileID`, `profileName`, `profileFingerprint` (§6.4), `route` (`.split(mode)`/`.vpn`), `isProbe` |
| `resolving` | DoH lookup starts (system DNS has no separate phase; it happens inside `NWConnection` and comes back via the establishment report) | `dnsStart` |
| `connecting` | `ServerConnector` starts the `NWConnection` | `connectStart`, `dnsEnd`, `dohIPs` |
| `connected` | `.ready` | `connectEnd`; async: `tcpRTT` (`handshakes` where `definition == NWProtocolTCP.definition` → `handshakeRTT`), `systemDNS{duration, source}`, `resolvedIP` (`resolutions.last.successfulEndpoint`, or `conn.currentPath?.remoteEndpoint` as a fallback) |
| `payloadSent` | first client→server payload fully sent (`.contentProcessed`) | `payloadSentAt`, `payload: FirstPayloadInfo` (§2.2) |
| `responding` | first server→client byte | `firstDownAt`, `firstDownPrefix` (first 128 bytes) |
| `ended` | first terminal event (below) | `endedAt`, `endReason`, totals, `stall` info, data-transfer report fields |

All timestamps are monotonic `UInt64` ns (`DispatchTime.now().uptimeNanoseconds`). Only
`startedAt` keeps a wall-clock `Date` for display.

**Terminal events. The first one wins** (`LockedFlag`-style guard, later ones ignored). This
matters because one side closing cancels the other, which then fires its own error
(`ECANCELED`). That later event must not overwrite the real cause.

| Source | `EndReason` |
|---|---|
| connect `.failed` / timeout | `.connectFailed(ConnectError)` where `ConnectError = .refused / .timeout / .unreachable / .dns / .other(code)` (from the failure error or the last `.waiting` error) |
| DoH returned nil **and** system connect failed with `NWError.dns` | `.dnsFailed` |
| `ShadowsocksStream.connect` → nil | `.outlineConnectFailed` |
| server→client read: `NWError.posix(.ECONNRESET)` | `.serverReset` |
| server→client read: other error | `.serverError(code)` |
| server→client read: `isComplete` | `.serverFin` |
| client→server read error / `isComplete`, or write-to-client error | `.clientClosed` |
| write-to-server error | `.serverError(code)` |
| relay idle timeout | `.idleTimeout` |
| handler bailed before connecting (bad ClientHello read, etc.) | `.clientClosed` |

**Guaranteed finish:** at the top of each handler, wrap the completion:

```swift
let trace = log.begin(...)
let completion = { trace.finish(fallback: .clientClosed); completion() }
```

`finish` is idempotent and keeps an earlier specific reason. The handlers have many
early-return paths (`clientConn.cancel(); completion()`). This keeps every one of them covered
without editing each.

### 2.2 First payload parsing

`trace.didSendFirstPayload(_ data: Data)` is called by whoever sends the first client bytes:

- `HTTPSHandler.processClientHello` / `SOCKS5Handler.processClientHello`: after
  `sendSegments` completes (with `tlsMsg.raw`). The send time is what the DPI saw, so we
  record it after the **last** segment.
- `connectAndForward` / non-TLS forward paths: after the raw send completes.
- `HTTPHandler`: after `request.rawData` is sent.
- Blind-relay paths (`.none`, VPN): the relay records the first up-chunk (§3), so no handler
  change is needed.

`FirstPayloadInfo`:
- `isTLS`: `data[0] == 0x16 && data[5] == 0x01`
- for TLS: `ClientHelloInfo { sni: String?, sessionID: Data, hasECH: Bool, alpn: [String] }`
  (§5)
- for HTTP: `method`, `requestHost` (from the parsed request line)

Only this parsed summary is kept, never the payload itself.

### 2.3 Transport reports

- `requestEstablishmentReport` is fired on `.ready`. Its callback fills `tcpRTT`, DNS info and
  `resolvedIP`. If it hasn't arrived by finish time, those fields stay nil and the classifier
  falls back (§4.2).
- `PendingDataTransferReport` is started on `.ready` and collected **at most twice**:
  1. when the stall detector first suspects a hello blackhole (≥ `helloBlackholeMin` silence
     after payload, §3), because that's when retransmits are informative;
  2. best-effort at finish, with a 1 s timeout, before handing the summary to the log.

  Fields kept: `retransmittedTransportByteCount`, `transportMinimumRTT`,
  `transportSmoothedRTT`. If the report comes back empty after cancel, (1) still gives us
  what we need.

### 2.4 `TraceSummary`

Immutable, `Sendable`, everything above plus derived values:

```swift
var rtt: TimeInterval?          // tcpRTT ?? transportMinimumRTT ?? nil
var rttIsPrecise: Bool          // false when only connect duration is available
var tFirstDown: TimeInterval?   // firstDownAt - payloadSentAt
var tEnd: TimeInterval?         // endedAt - payloadSentAt
var bytesUp, bytesDown: Int
var stall: StallInfo?           // §3
var retransmitBytes: UInt64?
```

## 3. Relay instrumentation

`ConnectionRelay.relay(... trace: ConnectionTrace? = nil ...)`. Existing call sites keep
compiling, and all 3 handlers pass their trace.

- `pipe` gets a `direction: .up / .down` and reports to the trace:
  - data: `trace.didRelay(direction, data)`. Up: `bytesUp += n`, `lastUpAt = now`, and the
    first up-chunk becomes the first payload if none was recorded yet (blind-relay case).
    Down: `bytesDown += n`, `lastDownAt = now`, and the first chunk sets `firstDownAt` +
    `firstDownPrefix`.
  - read error / `isComplete` / write error: `trace.didEnd(reason)` per the table in §2.1.
- The idle timer interval drops from 15 s to **2 s** (idle timeout stays 120 s; one timer per
  connection, ≤200 connections, negligible). Each tick, if there's a trace:
  `trace.checkStall(now:)`.

**Stall detector** (`checkStall`). It only observes and never kills the connection: the client
app decides when to give up, and long-polls are legitimate.

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

## 4. Per-connection classifier

New `Diagnostics/TraceClassifier.swift`: a pure function `classify(TraceSummary) ->
TraceOutcome`. No state, fully unit-testable.

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
`payload.hasECH`), so the UI can say "may be ECH blocking".

### 4.4 Rules (evaluated in order, first match wins)

```
R0  route == .vpn:
        endReason == .outlineConnectFailed               → outlineFailed (high)
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

R6  payload.isTLS && firstDownAt != nil:
        prefix starts with "HTTP/"                       → injectedResponse(.httpOnTLS) (high)
        prefix[0] == 0x15 (alert) && early(tFirstDown)   → injectedResponse(.earlyAlert) (high)
        prefix[0] == 0x15 && !early                      → inconclusive (real server rejected us)
        ServerHello parsed && negotiated TLS 1.3
          && serverSessionID != payload.sessionID        → injectedResponse(.sessionIDMismatch) (medium)
        → fall through to R8

R7  !payload.isTLS (plain HTTP) && firstDownAt != nil:
        parse status line + Location from prefix (128 B is enough for both in practice;
        if Location is cut off, treat it as unknown)
        status ∈ {301,302,303,307} && locationHost not same base domain as requestHost
          && (early(tFirstDown) || locationHost ∈ blockPageHosts)  → httpBlockPage (high)
        status ∈ {403, 451} && early(tFirstDown)         → httpBlockPage (medium)

R8  firstDownAt != nil, streaming:
        stall != nil && !stall.resumed && stall.phase == .midStream
          && stall.bytesDownAtStall ∈ freezeWindow
          && endReason ∈ {.clientClosed, .idleTimeout}   → freeze (medium)
        endReason == .serverReset && bytesDown < 64_000  → midStreamReset (low)

R9  bytesDown > 0                                        → ok
    else                                                 → inconclusive
```

Why a TLS 1.3 session-ID check: in TLS 1.3 the ServerHello echoes the client's
`legacy_session_id`. A TLS 1.2 server may return any ID, so we only compare when the
ServerHello's `supported_versions` says `0x0304`. A smart injector could echo it, so this is
medium confidence.

## 5. TLS parsing additions

`TLS/TLSParser.swift`. Generalize the extension walk in `extractSNIOffset` into one parser and
keep `extractSNIOffset` as a thin wrapper so `TLSDesyncer` callers don't change:

```swift
struct ClientHelloInfo { let sni: String?; let sessionID: Data; let hasECH: Bool; let alpn: [String] }
extension TLSMessage { func clientHelloInfo() -> ClientHelloInfo? }

struct ServerHelloInfo { let sessionID: Data; let negotiatedVersion: UInt16 /* 0x0304 if supported_versions ext */ }
enum ServerHelloInfo { static func parse(prefix: Data) -> ServerHelloInfo? }  // tolerant of truncation
```

- `hasECH`: extension type `0xfe0d` present.
- ServerHello layout: 5 record + 4 handshake + 2 version + 32 random + 1 + ≤32 session ID =
  76 bytes before cipher/extensions, so a 128-byte prefix covers the session ID. The
  `supported_versions` extension may lie beyond 128 bytes. If it's not visible, treat the
  version as unknown and skip the session-ID rule.

## 6. Connection log + host aggregation

### 6.1 `ConnectionLog` (`Diagnostics/ConnectionLog.swift`)

Owned by `ProxyManager` (`let connectionLog = ConnectionLog()`), passed to `ProxyServer` →
handlers alongside `resolverCache`. It **survives stop/start**, so a user can stop the proxy
and then look at what failed. It's cleared by a **Clear** button and on app exit (memory
only).

```swift
final class ConnectionLog {
    func begin(host:port:proto:profile:fingerprint:isProbe:) -> ConnectionTrace
    func complete(_ summary: TraceSummary)          // called by trace.finish
    func snapshot() -> LogSnapshot                  // copy under lock; cheap
    func clear()
}
```

Storage (all under one `NSLock`):
- `active: [UUID: ConnectionTrace]`, for the "live" count and for active rows.
- `hosts: [String: HostRecord]`. Key = lowercased host.
  `HostRecord { host, firstSeen, lastSeen, ports: Set<UInt16>, ips: [String] (≤4), snis: Set<String> (≤4, for IP-literal hosts), connectionCount, bytesUp, bytesDown, recent: Ring<(TraceSummary, TraceOutcome)>(8) }`.
  The outcome is computed once in `complete`.
- Cap **500 hosts**. When full, evict the least recently seen host.
- `recentGlobal: Ring<(host, outcome, endedAt, route, isProbe)>(300)` for network-state
  detection (§6.3).

Memory: ~300 B per summary × 8 × 500 ≈ 1.2 MB worst case.

### 6.2 Host verdict

New `Diagnostics/HostVerdict.swift`, also pure:

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
1. `window` = `record.recent` where `!isProbe`, outcome ∉ {`clientAborted`, `inconclusive`},
   ended within 15 min, **and `profileFingerprint == currentFingerprint`**.
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
non-probe outcome:

| State | Condition | Banner |
|---|---|---|
| `.offline` | ≥3 distinct hosts, zero `ok`, all `connect*` / `dns*` | "No connectivity. Results paused." Host verdicts are not updated |
| `.whitelistMode` | ≥6 distinct hosts with `helloBlackhole`/`connectTimeout`, ≥1 host `ok`, fail ratio ≥ 0.7 | "Network looks like it's in whitelist mode: only approved sites work." |
| `.outlineDown(profileName)` | ≥3 `outlineFailed` for one VPN profile, no VPN `ok` in that window | "Outline server for <profile> is unreachable or blocked." |
| `.normal` | otherwise | none |

### 6.4 Profile fingerprint and live rule badge

The badge is computed **at display time**, not stored, so it updates as soon as a host is
added to a profile.

- Add `static func matchingProfile(for host: String, in profiles: [SpoofProfile]) -> SpoofProfile`
  to `AppSettings`, and make the instance method call it. The snapshot loads
  `settings.profiles` **once** per refresh (it's a JSON decode) and matches all 500 hosts
  against that array.
- `SpoofProfile.fingerprint`: a string of the fields that change routing behaviour (resolved
  via `resolvedProfile`): `routeMode`, `splitMode`, `chunkSize`, `tlsRecordFragmentation`,
  `dohEnabled`, `dohServerURL`, `outlineConfig?.host:port`. Traces store the fingerprint
  they ran under. After a rule change, old evidence stops counting (§6.2 step 1) and the row
  shows **"Rule changed: reload to retest"** instead of a stale red badge.
- Badge text: the profile name. If Master matched, show a muted **"Default"** badge.

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
- `ProxyManager` gets `@Published var logSummary: LogSummary?` (`hostCount`, `blockedCount`,
  `network: NetworkState`).
- It's refreshed by a **2 s timer** that runs only while `status == .running`. The timer starts
  in `start()`'s success path and is invalidated in `stop()`.
- Each tick: `log.snapshot()` + one `settings.profiles` load → verdicts on a utility queue →
  publish on main. Skip publishing if the value didn't change, so `ContentView` doesn't
  re-render for nothing.
- After `stop()`, keep the last summary but hide the line. The toolbar icon remains the way in
  while stopped.

The verdict pass is shared with `ScannerModel`: both call
`ScannerSnapshot.build(log:profiles:now:) -> ScannerSnapshot` (rows + network state + counts),
in `Diagnostics/ScannerSnapshot.swift`. The summary just reads `snapshot.counts`. The cost is
fine at 2 s: ≤500 hosts × ≤8 summaries, pure computation.

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
- Coming back from the scanner, `SettingsView.onAppear { reload() }` already picks up any
  profiles added through the sheet. Nothing extra needed.

`ScannerView(initialFilter:)` stores the filter in `@State` initialised from the parameter,
so the user can still switch freely after opening.

### 7.2 `ScannerModel` (`Spoofy/ScannerModel.swift`)

`@MainActor final class ScannerModel: ObservableObject`
- `@Published rows: [HostRow]`, `network: NetworkState`, `activeCount: Int`.
- 1 s `Timer` runs only while the screen is visible (`start()`/`stop()` from
  `onAppear`/`onDisappear`). Each tick: `ScannerSnapshot.build(...)` (§7.1) on a utility
  queue → publish on main.
- **While in selection (edit) mode, refresh pauses** so rows don't jump under the user's
  finger. Show a small "Paused" label; resume on Done.
- Sort: blocked → suspicious → rule changed → others; within a group by `lastSeen` desc.

`HostRow { id: host, host, ports, ips, sni (if IP literal and differs), connectionCount, lastSeen, profileName, isDefaultProfile, verdict }`

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
- Bottom toolbar when `selection` isn't empty: **Add to Profile…** · **New Profile…** (both
  open §7.4 with a different default target).
- Context menu: Copy host · Add to profile… · Hide.
  - Hide adds the host to a persisted `scannerHiddenHosts` list (UserDefaults, supports the
    same wildcard syntax via `matchesPatterns`) for noise like telemetry.
  - The list footer shows "Hidden (N)", which opens an editable list.
- Toolbar menu: Clear log.

### 7.4 `AddPatternsSheet` (`Spoofy/AddPatternsSheet.swift`)

Input: selected `HostRow`s. Sections:

1. **Patterns**: one row per selected host, with a picker **exact** (`host`) / **wildcard**
   (`*.base`). Default is wildcard unless the host is an IP literal (always exact). Identical
   results are deduped.
   - For an IP-literal host whose ClientHello had an SNI, the note says *"Rules match the
     address the app connected to (IP), not the SNI"*. `matchingProfile` uses the CONNECT /
     SOCKS host.
2. **Target**: `Picker` of custom profiles + "New profile". Master is excluded because it
   already matches everything.
   - New profile shows a name field (default: base domain of the first host), route mode, and
     split mode.
   - Defaults come from the dominant verdict kind:
     - `.sni`/`.injected` → Split + SNI;
     - `.dns` → Split + None + DoH on;
     - `.ip`/`.freeze` → VPN if Master has an Outline config (`inheritOutlineConfig = true`),
       else Split + SNI with a warning "IP blocks usually need VPN";
     - otherwise Split + SNI.
3. **Warnings** (computed by simulating the save with the static matcher):
   - pattern already in target → skipped;
   - "`host` will still match **X** first (X is above this profile)" when the simulated match
     isn't the target.

Save: mutate `settings.profiles`.
- New profiles are inserted before Master, the same way as `SettingsView.addProfile`. Move that
  construction into `SpoofProfile.makeCustom(name:domainPatterns:)` and use it from both
  places.
- Then dismiss, leave edit mode, and show a confirmation ("Added 3 patterns to YouTube").
- New rules apply to new connections immediately because the handlers read `settings` per
  connection.

`Diagnostics/BaseDomain.swift`: `suggestWildcard(for host:) -> String?`. It returns nil for IPs
and uses the last 2 labels, or the last 3 when the last two form a known 2-level suffix (small
embedded list: `co.uk`, `com.au`, `co.jp`, `com.br`, `com.tr`, `com.ua`, `org.ru`, `msk.ru`,
`spb.ru`, `co.il`, …). Wildcards are editable after saving anyway.

### 7.5 `HostDetailView` (`Spoofy/HostDetailView.swift`)

- **Status**: verdict title, one-paragraph explanation, suggested fix (table §7.6), confidence.
- **Rule**: matched profile → `NavigationLink` to `ProfileEditView`.
- **Addresses**: IPs, ports, SNIs seen.
- **Recent connections** (latest 8, probes marked): time, outcome label and a compact
  timeline, e.g.
  `DNS 12 ms · RTT 48 ms · hello→RST 3 ms (early) · ↑517 B ↓0 B`.
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

- New files, all registered in `project.pbxproj` (file ref + group + Sources build phase), with
  a new `Diagnostics` group:
  - `Proxy/ServerConnector.swift`
  - `Diagnostics/{ConnectionTrace, ConnectionLog, TraceClassifier, HostVerdict, ScannerSnapshot, BaseDomain}.swift`
  - `Spoofy/{ScannerModel, ScannerView, HostDetailView, AddPatternsSheet}.swift`
- Modified:
  - `ConnectionRelay`: trace param, 2 s timer, stall check.
  - The three handlers: trace begin/finish, connector, first-payload hooks.
  - `ProxyServer`: owns the connector, passes the log.
  - `ProxyManager`: owns the log, `logSummary` + 2 s timer while running.
  - `AppSettings`: static matcher, `fingerprint`, `makeCustom`.
  - `TLSParser`: info parsers.
  - `ContentView`: toolbar entry + summary line.
  - `SettingsView`: use `makeCustom`, "Find Hosts to Add" link.
- Logging: classifier outcomes at `.debug` with `privacy: .private` for host names.
- README: short "Network scanner" section with a screenshot.

---

# Phase 2: Diagnose (active probes)

Passive data says *that* a host fails and roughly *where*. It can't separate SNI from IP from
whitelist. Diagnose runs a short probe sequence for one host on user request.

## 9. Building blocks

### 9.1 `ClientHelloBuilder` (`TLS/ClientHelloBuilder.swift`)

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
- Must round-trip through `TLSMessage.parse` + `extractSNIOffset`, so `TLSDesyncer` can split
  it exactly like a real hello.

We never complete the handshake. A **ServerHello (or a server alert) arriving is the success
signal**, because it proves the hello got past the DPI and the server answered.

### 9.2 `TLSProbe` (`Diagnostics/TLSProbe.swift`)

```swift
struct TLSProbeRequest { ip: String; port: UInt16; sni: String?; fakeECH: Bool; strategy: FixStrategy? /* nil = unsplit */ }
enum TLSProbeResult {
    case serverHello(tls13: Bool), alert(code: UInt8, early: Bool), httpText, otherData
    case reset(t: TimeInterval, early: Bool), closed(t: TimeInterval, early: Bool), silence
    case connect(ConnectError)
}
static func run(_ r: TLSProbeRequest, connector: ServerConnector, log: ConnectionLog, timeout: 5s,
                completion: (TLSProbeResult, TraceSummary) -> Void)
```

- Connects **by IP** (no DNS) via `ServerConnector` with an `isProbe` trace, so the
  classifier, timing and RTT logic are reused.
- Sends the built hello: unsplit, or `TLSDesyncer.split(...)` segments via the same sequential
  send as the handlers.
- Reads up to 2 KB, and maps the trace outcome + prefix to the result.
- Probe traces appear in the host's detail view and are excluded from passive verdicts.

### 9.3 System DNS for comparison

`getaddrinfo` on a dedicated serial queue (blocking is fine there), plus `DoHResolver` against
the Master DoH URL and a second fixed endpoint (`https://dns.google/dns-query`) in case the
first is blocked.

## 10. Diagnose sequence

`Diagnostics/ProbeEngine.swift`, `diagnose(host:port:progress:completion:)`. Steps run
**sequentially** with 1 s gaps (parallel probes confound results and look like scanning).
Each step has a 5 s timeout, and the engine stops as soon as the verdict is determined.

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
listener.

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
    var splitMode: SplitMode
    var chunkSize: Int
    var tlsRecordFragmentation: Bool
    var dohEnabled: Bool
    var fingerprint: String   // same scheme as SpoofProfile.fingerprint
}
```

Candidate order (cheapest / least invasive first):
1. If the diagnosis is DNS: `doh+none`, then `doh+sni`
2. `sni`, `sni+rec`
3. `firstByte`, `firstByte+rec`
4. `chunk(1)`, `chunk(5)+rec`, `chunk(20)`
5. `random`, `random+rec`
6. `vpn` (only if Master has an Outline config)

For IP/whitelist diagnoses, skip straight to `vpn` (splitting can't help).

## 12. Two-stage search

**Stage 1, screen (fast, in-process):** `TLSProbe` with the real SNI against the target IP
(DoH IP if the diagnosis is DNS) using each candidate's segmentation. Passing = `serverHello`.
Stop after the first **2** passing candidates. VPN skips stage 1.

**Stage 2, confirm (real client):** the synthetic hello isn't byte-identical to the user's
browser, so confirm with a real TLS client through the actual proxy path:

- `ProbeOverrides` (`Diagnostics/ProbeOverrides.swift`): `[host: SpoofProfile]` under a lock,
  entries expire after 30 s. Handlers look up
  `overrides.profile(for: host) ?? settings.matchingProfile(for: host)`, and mark the trace
  `isProbe` when an override is used.
- `URLSession(.ephemeral)` with `connectionProxyDictionary = ["HTTPEnable": 1, "HTTPProxy":
  "127.0.0.1", "HTTPPort": port, "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort":
  port]`, `GET https://host/`, 10 s timeout.
- Success = any `HTTPURLResponse` (any status) **and** the proxy-side probe trace classifies
  as `ok`. Run twice; both must pass.
- Requires the proxy to be running (the button says so). Real user traffic to the same host
  during the ~20 s confirm window also uses the override. That's acceptable and documented
  in the UI ("testing…").

**Spike first:** verify on a real device that iOS `URLSession` honours the HTTPS proxy keys
above. If it doesn't, fall back to stage-1-only results labelled "likely works".

If every candidate fails: wait 30 s (residual state) and re-run stage 1 for the top 3 before
reporting "No working strategy found".

## 13. From results to profiles

`FixFinder.run(hosts: [String])` works on a single host from the detail view or on a
multi-selection from the scanner (cap 10 hosts per run). Hosts are processed sequentially with
progress shown.

Each host gets `FixResult { host, winner: FixStrategy?, attempts: [(strategy, stage1, stage2)] }`.

Proposals:
1. Group hosts by `winner.fingerprint`.
2. For each group: if a **custom profile with the same fingerprint** exists, propose "Add N
   patterns to *<profile>*". Otherwise propose "Create profile *<base domain>* (SNI split)".
3. Hosts without a winner are listed separately with their diagnosis.

Proposals open in `AddPatternsSheet` in a **multi-target** mode (one section per proposal,
each toggleable). **Nothing is applied without the user confirming.** After saving, the
fingerprint changes, so passive verdicts reset to "rule changed" and the next real traffic
re-validates them.

---

## 14. Testing

There's no test target today. Add a `SpoofyTests` unit-test target (simulator, no signing
needed) in phase 1.

Unit tests (pure code, fixture-driven):
- `TraceClassifier`: one fixture `TraceSummary` per rule R0–R9, including timing edge cases
  (rtt nil, rtt < 10 ms, exactly at 0.5×), first-event-wins end reasons, ECH flag
  propagation.
- `HostVerdict`: scoring, freeze-beats-ok, two-recent-ok → working, healthy-network
  requirement, fingerprint filtering → `ruleChanged`, whitelist override.
- `NetworkState`: offline / whitelist / outlineDown thresholds.
- `TLSParser`: `clientHelloInfo` (SNI, ECH, session ID, ALPN) on captured real hellos
  (Safari, Chrome, Firefox); `ServerHelloInfo` on TLS 1.2 / 1.3 / truncated prefixes.
- `ClientHelloBuilder`: parses back, 517 bytes, SNI offset correct, splits with every
  `SplitMode` without crashing.
- `BaseDomain`, `AppSettings.matchingProfile(for:in:)`, AddPatterns simulation warnings.

Local behaviour tests (no Russia needed): a small Python test server (kept out of the repo)
with modes:
- RST right after the ClientHello (`SO_LINGER 0` + close)
- silence after the hello
- FIN after the hello
- `HTTP/1.1 302` on TLS
- send 16 KB then stall

Point the proxy at it by IP via CONNECT and check each outcome and the stall detector. "Early"
timing can't be simulated without an in-path injector, so that stays covered by unit fixtures.

Field matrix in Russia (record results in the PR):
- **Networks:** home ISP, plus mobile (MTS / Beeline / MegaFon / T2), including a region with
  whitelist mode.
- **Targets:**
  - known SNI-blocked sites;
  - an IP-blocked address;
  - a Cloudflare site with ECH enabled in Firefox;
  - a ≥1 MB file on a Hetzner/DigitalOcean VPS (the Outline server's host works) for H;
  - a plain-HTTP blocked site for C.
- Tune `DetectionConfig` from the results.

Regression: the phase 1 refactor (`ServerConnector`, relay changes) must not change bypass
behaviour. Run a before/after with each split mode, plus VPN, SOCKS5 and HTTP, on the same
blocked sites.

## 15. Risks / open questions

- **Timing reliability.** "Early" needs a trustworthy RTT. With `tcpRTT` from the
  establishment report it should be fine. Servers inside Russia (< 10 ms) get no timing
  verdicts by design.
- **HTTP/2 connection coalescing.** Browsers reuse one connection for several hosts sharing
  an IP/cert, so those extra hosts never reach the proxy and never appear. Say so in an
  info footnote.
- **Noise.** Preconnects and connection racing produce aborted connections. R4/R5 send them
  to `clientAborted`, and verdicts need repeated evidence plus a healthy network.
- **`.waiting` semantics.** Make sure `ECONNREFUSED` really surfaces as `.waiting(.posix)`
  on iOS 16 so B can be told apart from a plain timeout. If not, B shows as `connectTimeout`
  only.
- **Data-transfer report after cancel** may be empty. Mitigated by the early collection in
  the stall detector.
- **Existing quirk, surfaced by badges:** an enabled custom profile with empty
  `domainPatterns` matches all traffic (`AppSettings.matchingProfile` treats empty patterns as
  "match everything"). A freshly added profile in `SettingsView` does exactly that until
  domains are typed in. The scanner's badges will make this visible. Consider restricting
  "empty matches all" to `isDefault` in a separate change.
- **Synthetic hello vs. real hello.** DPI may treat them differently (fingerprinting). Stage
  2 exists for this. If the URLSession spike fails, results are marked "likely".
- **URLSession HTTPS proxy keys on iOS.** Unverified, spike before building phase 3 UI.
- **Lists that go stale.** `blockPageHosts`, `whitelistSNIs` and the control host need
  maintenance. Keep them in one file and consider fetching them remotely later.
- **Privacy.** The log holds host names and SNIs in memory only. Never written to disk or
  included in export, and Clear wipes it. Payloads aren't kept beyond a 128-byte server
  prefix.

## 16. Order of work

1. `ServerConnector` refactor + `AppSettings` static matcher / `fingerprint` /
   `makeCustom`. Regression-test bypass behaviour.
2. `SpoofyTests` target. `TLSParser` info parsers + tests.
3. `ConnectionTrace` + `ConnectionLog` + handler hooks + relay instrumentation (stall
   detector, reports).
4. `TraceClassifier`, `HostVerdict`, `NetworkState` + fixture tests.
5. `ScannerSnapshot`, `ScannerModel`, `ScannerView`, `HostDetailView`, `AddPatternsSheet`,
   hidden-hosts list. Then the entry points: toolbar icon, `ProxyManager.logSummary` + main
   screen summary line, and the Settings link.
6. Local test server pass, then field test in Russia. Tune `DetectionConfig`. **Release
   phase 1.**
7. `ClientHelloBuilder` + `TLSProbe` + `ProbeEngine.diagnose` + Diagnose UI. **Release
   phase 2.**
8. URLSession proxy spike → `ProbeOverrides` → `FixFinder` → multi-target AddPatterns.
   **Release phase 3.**
