# Plan: Test harness, bug fixes and proxy-core refactor

Status: Proposed (2026-10-17). Nothing implemented yet.

## Goal

1. Fix the crashes and correctness bugs found in the code review (§2).
2. Put the networking core under test **before** restructuring it. This means pure-logic unit tests, a fake connection for handshake and relay tests, and a loopback integration harness.
3. Refactor the proxy core into inbound handshake → router → outbound → relay, on serial per-connection queues, with one shared dialer and pure, testable parsers.
4. Do this in small steps that each leave the app shippable. Each step is guarded by the tests from the previous phase.

Non-goals: new features (WebSocket transport, network scanner, new split modes). They are tracked in their own plans (§9). This plan should make them cheaper.

## 1. Current state

```
ProxyServer (NWListener, concurrent proxyQueue)
  └─ readRequest: one receive(≤8192)
       ├─ 0x05 → SOCKS5Handler   (greeting, request, addr parse, dial, VPN, desync, relay)
       ├─ CONNECT → HTTPSHandler (200, ensureFullTLSRecord, dial, VPN, desync, relay)
       └─ else → HTTPHandler     (dial, VPN, forward first chunk, relay)
ConnectionRelay.relay(left,right)   — two pipes, idle timer 120 s / 15 s tick
TLSParser / TLSDesyncer / PatternMask — pure, already mostly testable
DoHResolver + DNSCache + DoHResolverCache
ShadowsocksStream / ShadowsocksCrypto / OutlineAccessKey
AppSettings (singleton, UserDefaults.standard, JSON profiles)
ProxyManager + BackgroundAudioPlayer (silent audio keep-alive)
```

Structural problems:

- **Each handler is a vertical slice.** Every handler re-implements dialing, VPN connect, ClientHello buffering, segment sending and error handling. Duplicated code:
  - dial helpers ×3: `HTTPSHandler.swift:309-374`, `HTTPHandler.swift:95-152`, `SOCKS5Handler.swift:492-555`
  - `ensureFullTLSRecord` ×2 (HTTPS, SOCKS5)
  - `sendSegments` ×2: `HTTPSHandler.swift:~260`, `SOCKS5Handler.swift:473`
  - VPN connect ×3
  - base64url padding ×2: `OutlineAccessKey`, `ShadowsocksStream.swift:293-308`
- **Shared concurrent queue.** All callbacks run on a concurrent `DispatchQueue` (`ProxyServer.swift:17`). Per-connection state is therefore guarded ad hoc (`LockedFlag`, `LastActivity`) or not at all.
- **Parsing is inside I/O callbacks.** The SOCKS5 and HTTP parsing can only be exercised over a real socket. They also assume one `receive` returns a whole message.
- **Global mutable settings.** The network code reads `AppSettings.shared` on every connection, and decodes the profiles JSON each time.
- **No tests at all.**

## 2. Findings

Severity: **P0** crash, **P1** user-visible misbehaviour or leak, **P2** protocol robustness, **P3** minor.
Each finding has an ID that later phases refer to.

### 2.1 Crashes (P0)

| ID | Where | Problem | Fix |
|----|-------|---------|-----|
| C1 | `TLS/PatternMask.swift:15,21,25,35,39,43` | `seed = UInt(arc4random()) \| UInt(arc4random()) << 32`. Then `Int(seed)` traps whenever bit 63 is set, which is about 50% of calls. Verified: 37 of 40 runs crashed (each run makes several conversions). Go's `int(seed)` wraps silently, so the port kept the expression but lost the semantics. | Replace with `Int(truncatingIfNeeded: seed)`, or better, do the arithmetic in `UInt` and take `% n` there. Inject the RNG (`var rng: some RandomNumberGenerator`) so tests can force a high-bit seed. |
| C2 | `DNS/DoHResolver.swift:101` | `UInt8(label.count)` traps for labels over 255 characters. It also counts `Character`s, not UTF-8 bytes, so a non-ASCII label produces a malformed query. | Use `label.utf8.count`. Reject a label over 63 bytes or a name over 253 bytes with `DNSError.invalidName` before building the query. |
| C3 | `Shadowsocks/ShadowsocksStream.swift:329` | `UInt8(domainBytes.count)` traps for a domain over 255 bytes. The target comes straight from the client's CONNECT or SOCKS5 request, so any local app can crash the proxy. | Validate in the inbound parser: a target host over 255 bytes is rejected (SOCKS5 can't even express it; HTTP gets 400). Add a `precondition`-free guard in `ShadowsocksStream` too. |

### 2.2 User-facing bugs (P1)

| ID | Where | Problem | Fix |
|----|-------|---------|-----|
| U1 | `Spoofy/SettingsView.swift:192` (`addProfile`) + `Shared/AppSettings.swift:231` (`matchingProfile`) | A new profile is created **enabled with empty patterns** and inserted before Master. Empty patterns match everything, so adding a profile silently re-routes all traffic. | An empty pattern list matches nothing, and Master is the only catch-all. Also create new profiles disabled. |
| U2 | `AppSettings.swift:231` | The fallback is `profiles.last`. That is only correct while Master happens to stay last, and import or reorder can break it. | Master is identified by `id`/`isMaster`, not by position. `matchingProfile` returns `master` explicitly. |
| U3 | `AppSettings.swift:275` (`matchesPatterns`) | `*.x.*` is implemented as `host.contains(middle)`, so `*.google.*` matches `notgoogle.community.org`. | Use label-aware matching (§6.6 `DomainMatcher`), as SpoofDPI's trie does. |
| U4 | `AppSettings.swift:186` (`profiles` getter) | When decoding fails, it **overwrites stored profiles with defaults**. A bad migration or partial write therefore loses the user's config. It also decodes JSON on every access, including once per connection. | Decode once into the store. On failure, keep the raw blob under `profiles.backup.<timestamp>`, fall back to defaults in memory only, and surface the error in the UI. |
| U5 | `AppSettings.swift:257-265` (`importJSON`) | No validation: duplicate IDs, a missing or duplicate Master, bad chunk sizes and unknown modes are all accepted. | `ProfileValidator` returns `[ValidationError]`. Import only succeeds when the list is empty, and it never replaces Master's identity. |
| U6 | `HTTPSHandler.swift:44`, `HTTPHandler.swift:32`, `SOCKS5Handler.swift:254` | Route = VPN with `outlineConfig == nil` **falls through to a direct connection**. A user who expects tunnelling gets a direct, DPI-visible connection. | Fail closed: HTTP 502 or SOCKS5 reply `0x01`, plus a log line. The router (§6.5) makes this a single decision point. |
| U7 | `HTTPSHandler.swift:143-192` (`ensureFullTLSRecord`) | There is no `0x16` content-type check. A non-TLS protocol over CONNECT (for example SSH over port 443, or a server-first protocol) waits for a "record length" read from arbitrary bytes, or for data that never comes, until the idle timeout. SOCKS5 has the check (`SOCKS5Handler.swift:343`); HTTPS does not. | Use one `ClientHelloReader` (§6.3) for both: if the first byte isn't `0x16`, pass through. Add a 2-second first-byte timeout so server-first protocols get passthrough (the bytes are forwarded unmodified). |
| U8 | `TLS/TLSDesyncer.swift:21-25` | `.sni` mode splits `raw` instead of `inputs`, so **TLS record fragmentation is silently ignored** in SNI mode. Every other mode honours it. | Split each fragmented record at the SNI offset translated into that record's coordinates. Test: `split(.sni, recordFragmentation: true)` yields more than one TLS record header. |
| U9 | `Spoofy/ProxyManager.swift:40-44` | When the proxy fails to start, the silent audio player keeps running. The app then sits in the background draining battery for nothing. | Stop the audio in the error path. Make `ProxyManager` a small state machine: `idle → starting → running(port) → stopping → idle`, plus `failed(error)`. |
| U10 | `ProxyServer.swift:46` | The `start` completion is called on **every** listener state change. That includes `.ready` after a network change and `.failed` later on, so `ProxyManager` flips state. | Call the completion once, on the first `.ready` or `.failed`. Report later failures through a separate `onFailure` handler. |
| U11 | `Spoofy/BackgroundAudioPlayer.swift` | No `AVAudioSession.interruptionNotification` or `mediaServicesWereResetNotification` handling. After a phone call or Siri, the audio stays stopped and iOS suspends the proxy. | Observe both notifications. Resume on `.ended` (ignore `shouldResume`, because the session is silent), and rebuild the player after a media-services reset. |
| U12 | `Spoofy/ContentView.swift:27` | Shows `settings.proxyPort`, not the port that is actually listening. After the user edits the port without restarting, the UI is wrong. | Display `ProxyManager.state.running(port)`. |

### 2.3 Network and protocol robustness (P2)

| ID | Where | Problem | Fix |
|----|-------|---------|-----|
| N1 | `ShadowsocksStream.swift:89-116` | `connect` has no timeout. An unreachable Outline server hangs the client connection until the client gives up. | Use the shared `Dialer` with a 10-second timeout (§6.2). |
| N2 | `ShadowsocksStream.swift:141-143` | If the prefix is longer than the salt, the salt is extended rather than the prefix truncated, and the server derives the wrong subkey. | Validate when parsing the access key: `prefix.count <= saltSize`, otherwise reject the key with a clear error. Outline itself limits the prefix to the salt length. |
| N3 | `ShadowsocksStream.swift:70` | The comment says Outline uses a base64 PSK. It doesn't: classic AEAD ciphers use EVP_BytesToKey(password). It only seems right because Outline passwords look like base64. | Fix the comment and pin the behaviour with the KAT in §5.1. |
| N4 | `ShadowsocksStream` (send path) | The address header goes out only with the first **client** data. Server-first protocols (SMTP, some game and chat protocols) therefore hang over VPN, because the server never learns the target. | Use outline-sdk's `ClientDataWait` behaviour: wait up to 10 ms for the first client data and coalesce, then flush the header alone. |
| N5 | `ShadowsocksStream` salt generation | The `SecRandomCopyBytes` status is ignored. On failure, the salt is all zeros, so nonces are reused across connections. | Check the status and fail the connection on error. Alternatively, `SystemRandomNumberGenerator` fills the salt, and it cannot fail. |
| N6 | `SOCKS5Handler.processGreeting` / `parseAddress` | Bytes after the greeting or request in the same read are dropped. A client that pipelines (greeting + request, or request + ClientHello) breaks. Short reads are also not handled. | Use an incremental parser with a leftover buffer (§6.4.2). |
| N7 | `HTTPSHandler.swift:276`, `SOCKS5Handler.swift:473` (`sendSegments`) | A send error is logged, and then the relay **still starts**. | On error, cancel both sides and don't relay. |
| N8 | All handshakes | No timeout before the relay starts. A client that opens a socket and sends nothing (or one byte) holds a slot forever, out of only 200 slots. | Use a session-level handshake deadline: 10 s from accept until the relay starts. |
| N9 | `ProxyServer.readRequest`, `HTTPHandler` | A single `receive(≤8192)` is assumed to hold the whole request head. Long cookies or a split read cause a 400. A plain-HTTP keep-alive connection that then asks for a **different host** is forwarded to the first host. | Use an incremental head parser up to 64 KB (§6.4.1). Rewrite the absolute-form request to origin-form, strip `Proxy-*` headers, and force `Connection: close` upstream, so there is one request per upstream connection. |
| N10 | `DoHResolver` | Queries A records only, so IPv6-only hosts fail. It sends DoH queries for IP literals. Callers use only `ips.first`, so a single dead IP fails the connection. | Skip DoH for IP literals. Query A and AAAA in parallel. Return all addresses; the `Dialer` tries them in order with a 250 ms stagger (SpoofDPI `DialFastest`). |
| N11 | `HTTPSHandler.waitForReady` (all 3 copies) | `.waiting(error)` is ignored, so an unreachable host waits the full 10 seconds. This was also noted in network-scanner §1. | The `Dialer` treats `.waiting` as a failure for that address and moves to the next one. |
| N12 | `ConnectionRelay.pipe` | EOF on one side cancels the other immediately, so there is no half-close. This matches SpoofDPI but breaks request/response protocols that half-close (rare over 443). | **Keep the current behaviour** in the refactor, behind a `RelayPolicy.closeOnFirstEOF` default. Note half-close as a possible follow-up. Don't change two things at once. |
| N13 | `OutlineAccessKey.urlDecodeBytes` | Found in Phase 2. The `prefix=` value is percent-decoded into raw bytes. outline-sdk (`configurl.parseStringPrefix`) instead percent-decodes it into a UTF-8 **string** and maps each code point ≤ 0xFF to one byte. So `%C2%A8` must become the single byte `0xA8`, but Spoofy produces `c2 a8`. Every prefix with a byte ≥ 0x80 is wrong, including the TLS-ClientHello prefix from Outline's prefixing guide (`%16%03%01%00%C2%A8%01%01`). | Percent-decode, UTF-8-decode, then map each scalar to a byte. Reject scalars above 0xFF, as outline-sdk does. Test: `OutlineAccessKeyTests.testPrefixCodePointsBecomeBytes`. |
| N14 | `ConnectionRelay.pipe` (send error path) | Found in Phase 2. On a write error the pipe cancels only its **source**. The opposite pipe stays parked in `receive` on the destination, so the relay doesn't complete and the slot stays held until the 120-second idle timeout. A failed `NWConnection` usually also fails its pending receive, which hides this. A `ShadowsocksStream` destination doesn't. | Cancel both sides on a write error, as the read-error path already does. Test: `ConnectionRelayTests.testWriteErrorStopsTheRelay`. |
| N15 | `HTTPSHandler.readClientHello`, `SOCKS5Handler.readClientHello` | Found in Phase 3. The first client read uses `minimumIncompleteLength: 5`, so a client whose first write is under 5 bytes and then waits for a reply (a short line-based protocol, a 1-byte keepalive) stalls until the idle timeout. SOCKS5's `0x16` check runs only after those 5 bytes arrive. | `ClientHelloReader` (§6.3) decides on the first byte, so reads use `minimumIncompleteLength: 1`. Test: `LoopbackHarnessTests.testShortFirstClientWriteIsForwarded`. |

### 2.4 Minor (P3)

| ID | Where | Problem | Fix |
|----|-------|---------|-----|
| M1 | `ProxyServer.swift:76-82` | The max-200 check and the increment are not atomic, so with a concurrent queue the limit can overshoot. | Make the admission decision on the server's serial queue (§6.1). |
| M2 | `ProxyServer.stop()` | The listener is cancelled but active sessions keep running, so "Stop" doesn't stop traffic. | The server keeps a session registry, and `stop()` cancels all sessions. |
| M3 | `ConnectionRelay` | Logs at debug level on every packet: CPU cost, and it leaks hostnames into the unified log. | Log per session (open, close, bytes, duration) only. Gate the per-packet log behind `#if DEBUG_TRACE`. |
| M4 | `AppSettings.proxyPort` | `UInt16(defaults.integer)` traps on out-of-range values, for example after an import. | `UInt16(exactly:) ?? 8080`, and validate in the UI. |
| M5 | `TLSParser` `Data.readUInt16(at:)` | Assumes zero-based indices and breaks on a `Data` slice. `splitFirstByte` returns `dropFirst` slices, which aren't zero-based. | Index from `startIndex`, or normalise with `Data(slice)` at module boundaries. Add a test that parses a slice. |
| M6 | `ProfileEditView` | Saves on every keystroke, which re-encodes all profiles each time. | Use a local edit buffer and save on disappear or Done. With §6.7 the store debounces writes anyway. |
| M7 | `SOCKS5Handler.sendReply` | Always replies BND.ADDR 0.0.0.0:0. That is legal, but some clients log warnings. | Keep it. Document it in a comment. |

## 3. SpoofDPI comparison (what to port, what not)

| SpoofDPI | Spoofy | Action |
|----------|--------|--------|
| `int(seed)` wraps silently | `Int(seed)` traps | C1 |
| `ReadTLSMessage` aborts if the first message isn't a ClientHello | HTTPS path has no check | U7 |
| Domain trie: label-aware, priority exact > `*` > `**` | substring `contains` | U3. Port the semantics and the `trie/domain_test.go` cases. |
| `DialFastest`: races resolved IPs | `ips.first` | N10 |
| `custom` split mode (`applySegmentPlans`): offsets relative to the SNI, with noise | not present | Out of scope. The new `Desyncer` interface (§6.5) makes it a drop-in later. |
| `TunnelConns` closes both sides on the first EOF | same | Keep (N12). |
| `disorder` (TTL tricks), fake packets | n/a | Not possible without raw sockets on iOS. Don't port. |
| `desync/tls_test.go`, `trie/domain_test.go`, config tests | none | Port them as XCTest vectors (§5.1). |

## 4. Phase 0 — hotfixes (ship before anything else)

These are small and local, so ship them as v1.5.9 before the test target exists. Each is verified by a throwaway script or by hand, and gets a real test in Phase 2.

1. C1: `Int(truncatingIfNeeded:)` in `PatternMask`.
2. C2, C3: length guards in `DoHResolver.buildDNSQuery` and `ShadowsocksStream`.
3. U1: empty patterns match nothing, and new profiles start disabled.
4. U6: VPN without a config fails closed.
5. U9 and U10: stop audio on error, and call the start completion once.

**Done (2026-10-17).** Regression tests are in `Tests/SpoofyCoreTests/`. `PatternMaskTests` checks the port against masks produced by SpoofDPI's Go implementation.
- **U1 deviation:** new profiles stay enabled when created. With empty patterns now matching nothing, they are harmless, and starting them disabled would only add a step for the user.
- **U2 fixed early:** the fallback is now Master by its `isDefault` flag.
- **Extra fix:** `ProxyManager` now ignores a late start result from a server that was stopped while it was still starting.
- **Not covered by tests:** U9 and U10 live in app-only code, so they were only build-checked.

## 5. Phase 1–2 — test target and unit tests

### 5.0 Test target setup: a macOS Swift package (no simulator)

The core folders (`Proxy/`, `TLS/`, `DNS/`, `Shadowsocks/`, `Shared/`) import only Foundation, Network, CryptoKit, CommonCrypto and os.log. They have no UIKit, SwiftUI or AVFoundation. That means they can be compiled and tested as a plain macOS Swift package with `swift test`: no simulator, no Xcode scheme, no signing.

**Verified 2026-10-17:** the unchanged sources build this way with Swift 6.3.3 (in Swift 5 language mode), and a smoke test passes in about 4 seconds. That test is the `masterKey` known-answer vector from §5.1.

- Add `Package.swift` at the repo root. It points at the existing folders, so **no files move and the Xcode project is not touched**:
  ```swift
  // swift-tools-version:5.9
  import PackageDescription
  let package = Package(
      name: "SpoofyCore",
      platforms: [.macOS(.v13), .iOS(.v16)],
      targets: [
          .target(name: "SpoofyCore", path: ".",
                  exclude: [/* every non-core root entry: Spoofy, Spoofy.xcodeproj, Tests, Docs, … */],
                  sources: ["Proxy", "TLS", "DNS", "Shadowsocks", "Shared"]),
          .testTarget(name: "SpoofyCoreTests", dependencies: ["SpoofyCore"],
                      path: "Tests/SpoofyCoreTests"),
      ]
  )
  ```
  **Done (Phase 1):** see the repo's `Package.swift`. When ClientHello hex captures are added in Phase 2, add `resources: [.copy("Fixtures")]` to the test target. When a new file appears at the repo root, add it to `exclude` to silence SwiftPM's "unhandled files" warning.
  - The app target keeps compiling the same files directly, as today. The package is a second, test-only build of them.
  - Tests use `@testable import SpoofyCore`, so nothing needs to become `public`.
  - Tools version 5.9 keeps Swift 5 language mode, which matches `SWIFT_VERSION = 5.0` in the app. The Swift 6 toolchain prints Sendable warnings in `ConnectionRelay` but no errors; step 4a removes their cause.
  - Possibly needed: SwiftPM warns about "unhandled files" because the package root is the repo root. If that is noisy, add `exclude:` entries.
- Makefile:
  ```make
  test:
  	swift test
  ```
  It also runs in CI on any macOS runner, and Xcode can open `Package.swift` to run tests from the IDE.
- **Boundary rule, enforced by the package build:** files in the five core folders must not import UIKit, SwiftUI or AVFoundation. A violation breaks `make test` immediately. That is the module boundary the refactor wants anyway. App-only code stays in `Spoofy/`: views, `ProxyManager`, and `BackgroundAudioPlayer`, which needs AVAudioSession and is iOS/Catalyst only.
- **Not covered by `swift test`:** the `Spoofy/` app layer (U9–U12, §6.9). Keep that layer thin, and verify it by hand on the device. Its logic, such as the `ProxyManager` state transitions, can move into `Shared/` as a pure state machine and be tested there.
- **Optional later step (after 4e):** have the app target depend on the package instead of compiling the files twice. That requires `public` on the API the app uses (`ProxyServer`, `SettingsStore`, profile types). Do it only if the double-membership becomes annoying, for example forgetting to add a new file to the app target.
- **Alternative, not chosen:** a hosted XCTest target run on Mac Catalyst (`-destination 'platform=macOS,variant=Mac Catalyst'`). Ad-hoc signing (`CODE_SIGN_IDENTITY=-`) works without a paid account. But it needs pbxproj and scheme edits and launches the whole app as the test host. It is also slower, for no benefit to the core tests.
- Make these `internal` (currently `private`) so tests can reach them:
  - `DoHResolver.buildDNSQuery` and `parseDNSResponse`
  - `ShadowsocksStream`'s frame encoder and decoder (extracted, §6.8)
  - `AppSettings.matchesPatterns` (replaced later by `DomainMatcher`)
- **Known-bug tests.** Each P1/P2 finding gets a test asserting the *correct* behaviour, wrapped in `XCTExpectFailure("U3: substring match")` until it is fixed. The test suite stays green, and the fix commit removes the wrapper. Crashes (C*) cannot be expected-failures, because a trap kills the test process. They are fixed in Phase 0 first.

### 5.1 Unit tests (pure logic, no I/O)

**Status (Phase 2, 2026-10-17): done for everything that the current code can be tested on.** The suite has 103 tests. Fixtures are real ClientHellos captured from Go's `crypto/tls`, plus a `ClientHelloBuilder` for edge cases. The AEAD known-answer values come from Go: `x/crypto/chacha20poly1305` and stdlib GCM, with no AAD. Shadowsocks has no AAD, so the RFC 8439 vector can't go through `aeadEncrypt`. Production seams added: `DNSCache(now:)`; `parseDNSResponse` made internal; `ConnectionRelay.relay(idleTimeout:idleCheckInterval:)`.

Expected-failure ledger. Each item flips to a passing test when its fix lands; remove the `XCTExpectFailure` or `XCTSkipIf` at that point.

| Finding | Test | Mechanism |
|---------|------|-----------|
| U3 | `DomainMatcherTests.testBothWildcardsAreLabelAware` | `XCTExpectFailure` |
| U4 | `SettingsStoreTests.testCorruptedProfilesBlobIsPreserved` | `XCTExpectFailure` |
| U5 | `SettingsStoreTests.testImportRejectsMissingMaster`, `testImportRejectsDuplicateIDs` | `XCTExpectFailure` |
| U8 | `TLSDesyncerTests.testSNIModeHonoursRecordFragmentation` | `XCTExpectFailure` |
| N2 | `OutlineAccessKeyTests.testPrefixLongerThanSaltIsRejected` | `XCTExpectFailure` |
| N13 | `OutlineAccessKeyTests.testPrefixCodePointsBecomeBytes` | `XCTExpectFailure` |
| U7 | `LoopbackHarnessTests.testServerFirstBannerReachesClientInSplitMode`, `testNonTLSClientFirstBytesPassThroughInSplitMode` | `XCTExpectFailure` |
| U8 | `LoopbackHarnessTests.testSNIModeWithRecordFragmentationSendsSeveralRecords` (end-to-end twin of the unit test) | `XCTExpectFailure` |
| N9 | `LoopbackHarnessTests.testPlainHTTPIsRewrittenToOriginForm` | `XCTExpectFailure` |
| N15 | `LoopbackHarnessTests.testShortFirstClientWriteIsForwarded` | `XCTExpectFailure` |
| M4 | `SettingsStoreTests.testOutOfRangePortFallsBack` | `XCTSkipIf`, because it traps |
| M5 | `TLSParserTests.testParsesFromDataSlice` | `XCTSkipIf`, because it traps |

These items need the seams from later phases, so they are deferred:
- `ShadowsocksFramingTests` (§6.8).
- The §5.2 SOCKS5 and CONNECT session tests (§6.4/6.5).

**`TLSParserTests`**
- `TLSMessage.parse` on a real Chrome ClientHello and a real Firefox ClientHello (captured hex in `Fixtures/`). Checks: `isClientHello`, record length, SNI offset pointing at the hostname bytes.
- ClientHello without SNI → `nil` offset. Truncated record → `.needMoreData`. Content type `0x17` → not a ClientHello.
- Parse from a `Data` slice with non-zero `startIndex` (M5).
- Port the cases from SpoofDPI `desync/tls_test.go`.

**`TLSDesyncerTests`**
- For every mode, `segments.joined() == input`: the invariant that matters most.
- `.firstByte`: first segment has 1 byte. `.chunk(n)`: every segment has ≤ n bytes. `.sni`: some segment boundary falls strictly inside the hostname.
- Record fragmentation: each output record has a valid 5-byte header. Concatenating the record payloads equals the original payload.
- U8 (expected failure until fixed): `.sni` + record fragmentation produces more than one record.

**`PatternMaskTests`**
- Inject a seeded RNG returning `UInt64.max` (C1 regression: must not trap).
- 10,000 random seeds: no trap, output length invariant.

**`DNSWireTests`**
- `buildDNSQuery("example.com", .A)` equals a golden byte string (header with RD=1, QDCOUNT=1, labels, QTYPE=1, QCLASS=1).
- Label of 64 bytes → throws. Name of 254 bytes → throws. `"bücher.de"` → throws, or punycode if we add it (C2).
- `parseDNSResponse`: golden responses with A, AAAA, CNAME chain, compression pointers, NXDOMAIN and truncated data. A pointer loop must terminate.
- IP literal `"1.2.3.4"` and `"[::1]"` short-circuit without a query (N10).

**`DNSCacheTests`** need an injected clock, `init(now: @escaping () -> Date = Date.init)`. Cases: TTL expiry, the 500-entry cap, and eviction order.

**`ShadowsocksCryptoTests`** (known-answer vectors, computed for this plan)
- `masterKey("password", 32)` = `5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08`. The first 16 bytes are `md5("password")`, a sanity anchor.
- `deriveSubkey(master: ↑, salt: 00 01 … 1f)` = `ee187aed3f87574907a39db98606f60a526114831288097cac66054b33a9464f`. This is HKDF-SHA1 with info `"ss-subkey"`.
- ChaCha20-Poly1305: RFC 8439 §2.8.2 vector through `aeadEncrypt`.
- AES-256-GCM: round-trip, plus a tampered tag that must fail.
- `incrementNonce`: `00…00 → 01 00…`, `ff 00… → 00 01 …` (little-endian carry), and the all-`ff` wraparound.

**`ShadowsocksFramingTests`** (after the codec extraction in §6.8)
- Encode then decode a payload of 0, 1, 0x3FFF and 0x3FFF+1 bytes. The last one must produce two chunks.
- Feed the decoder the stream one byte at a time, and in random chunk sizes. Output must be identical.
- Corrupt a length tag → `.authenticationFailed`, with no output.
- A length above 0x3FFF in a decrypted length frame → protocol error.
- Address header: IPv4, IPv6, domain. A domain over 255 bytes → error (C3).
- Prefix handling (N2): the salt starts with the prefix and keeps its full salt length.

**`OutlineAccessKeyTests`**
- SIP002 `ss://base64url(method:password)@host:port/?outline=1#tag`, and the legacy `ss://base64(method:password@host:port)`.
- Padded and unpadded base64. The `prefix=` query with percent-encoding. An IPv6 host in brackets.
- Rejects: unknown cipher, prefix longer than the salt (N2), port out of range.

**`DomainMatcherTests`** (characterization first, then the new semantics)
- Step 1: table-driven tests that capture **current** `matchesPatterns` behaviour for `example.com`, `*.example.com` and `*.google.*`, plus an empty pattern. Tests that encode a bug are marked expected-failure with the finding ID.
- Step 2: port `trie/domain_test.go` and its priority rules.

**`ProfileRoutingTests`**
- Empty patterns match nothing (U1). Master is the fallback by identity, not by position (U2).
- A disabled profile is skipped. The first matching enabled profile wins.

**`SettingsStoreTests`** (an injected `UserDefaults(suiteName: UUID().uuidString)`)
- A corrupted blob is preserved under a backup key and not overwritten (U4).
- Import validation (U5). An out-of-range port (M4). The migration from the current format round-trips.

### 5.2 Handshake and relay tests with a fake connection

`FakeConnection: ConnectionProtocol` (in `Tests/SpoofyCoreTests/Support/`):

```swift
final class FakeConnection: ConnectionProtocol {
    enum Event { case data(Data), eof, error(NWError) }
    private(set) var sent: [Data] = []           // one entry per send() call — asserts segmentation
    private(set) var sentEOF = false
    private(set) var cancelled = false
    var script: [Event]                          // delivered to receive() in order
    let queue: DispatchQueue                     // callbacks always delivered async on this queue
    func send(content:, contentContext:, isComplete:, completion:)   // appends, optional injected error
    func receive(minimumIncompleteLength:, maximumLength:, completion:) // pops next event; if script empty, parks the callback until push()
    func push(_ e: Event)                        // feed more input later (timeouts, slowloris)
    func cancel()
}
```

The fake operates at the `send` level, so it verifies segmentation exactly. Loopback TCP coalesces segments and can't do that.

Tests:
- **Relay.** Bytes flow both ways. EOF on the left cancels the right (current policy). The idle timeout fires, using an injected clock or a short timeout.
- **SOCKS5 session over fakes.** Greeting+request pipelined in a single chunk (N6). Greeting split byte-by-byte. Request immediately followed by a ClientHello: the leftover bytes reach the outbound unmodified. Unsupported command → reply `0x07`.
- **CONNECT session.** Non-TLS first bytes are passed through (U7). Silence → handshake timeout cancels both sides (N8). A send error during segments → no relay, both cancelled (N7).
- **VPN route with a nil config** → 502 / `0x01`, and no dial attempted (U6).

These tests need the seams from §6.1 to §6.5. Write the characterization subset that is possible against the current handlers first (relay; `TLSDesyncer` through `sendSegments`), and add the rest as the seams appear.

### 5.3 Loopback integration harness (Phase 3)

```
Test ──NWConnection──▶ ProxyServer(127.0.0.1:0) ──▶ LoopbackOrigin(127.0.0.1:0)
                             │
                       FakeResolver (maps names → 127.0.0.1)
```

- `ProxyServer` must expose `var port: UInt16?` once the listener is ready (port 0 = ephemeral). It also needs injectable `ProxyConfig`, `Resolver` and `Dialer` (§6).
- `LoopbackOrigin` is an `NWListener` with a pluggable behaviour: `.echo`, `.recordAll` (captures the full byte stream for an exact-equality check) and `.serverFirst(Data)` (sends a banner on accept).
- Scenarios:
  1. CONNECT + fake ClientHello in each split mode → the origin received exactly the original bytes.
  2. SOCKS5 with domain, IPv4 and IPv6 targets → echo works.
  3. Plain HTTP absolute-form → the origin sees origin-form, no `Proxy-Connection`, and `Connection: close`.
  4. Server-first origin over CONNECT → the client receives the banner (U7 passthrough).
  5. 250 concurrent idle clients → the 201st is refused; `stop()` closes all of them (M1, M2).
  6. **Opt-in Shadowsocks interop.** Gated on `SPOOFY_SS_TEST_KEY`, against `docker-compose up` (outline shadowbox, port 8082): VPN route to a loopback origin, echo round-trip; plus a server-first origin (N4).
- Every test has a hard 5-second timeout, and fails with the session log attached.

**Phase 3 status: done** (`Tests/SpoofyCoreTests/LoopbackHarnessTests.swift`, 17 tests, about 6 s).
- Seam: `ProxyServer.port` returns the bound port, so tests start it with port 0. Config is injected via `AppSettings(defaults:)` with a throwaway suite, as in Phase 2.
- **Resolver and `Dialer` injection deferred to 4b.** The current handlers construct `DoHResolver` and `NWConnection` inline, and there is no seam short of the §6.2 `Dialer`. The harness doesn't need one: DoH is off, and targets are `127.0.0.1`, `::1` and `localhost`, which the system resolver answers locally. `FakeResolver` arrives with the `Dialer` and is needed only for DoH-path scenarios.
- Support: `LoopbackOrigin` (listener bound to the loopback interface, v4 and v6, with `.echo`, `.recordAll`, `.serverFirst`; it records every byte) and `TestClient` (blocking reads with deadlines: `read(count:)`, `read(through:)`, `waitForClose`). Each wait is at most 5 s; the session log isn't attached yet (os.log only), which is worth adding with the §6.1 session object.
- Scenario 1: every split mode delivers the TLS 1.3 hello plus trailing data byte-exact; with record fragmentation the records re-assemble to the original handshake for chunk, firstByte and random (SNI is U8). Echo round-trip, 400 for garbage, refused dial (N11).
- Scenario 2: SOCKS5 echo for domain (`localhost`), IPv4 and IPv6 targets; the hello is delivered unchanged; `0x07` for BIND; `0xFF` with no acceptable method. The client waits for the method reply before sending the request (N6 is a §5.2 fake-connection test).
- Scenario 3: the absolute-form request reaches the origin and the response comes back; the origin-form rewrite is N9 (expected failure).
- Scenario 4: the banner arrives in mode `none`; in split modes it doesn't, and non-TLS first bytes stall (U7). A first write under 5 bytes stalls in both CONNECT and SOCKS5 (N15).
- Scenario 5 landed with 4a: `testConnectionCapAdmitsExactly200` (250 clients, exactly 50 refused, freed slots re-admit), `testStopClosesSessionsInEveryPhase` (relaying, idle and mid-SOCKS5 sessions all close, and so does the upstream), `testSessionSlotIsReleasedWhenClientCloses`. Scenario 6 (Shadowsocks interop) comes with 4f.

## 6. Phase 4 — refactor design

Order: 6.1 → 6.2 → 6.3 → 6.4 → 6.5 → 6.6/6.7 → 6.8. After each step the full test suite passes and the app is usable.

### 6.1 Concurrency model: a serial queue per session

```swift
let ioRoot = DispatchQueue(label: "spoofy.io", qos: .userInitiated, attributes: .concurrent)
let serverQueue = DispatchQueue(label: "spoofy.server", target: ioRoot)              // listener, admission, registry
// per accepted connection:
let sessionQueue = DispatchQueue(label: "spoofy.session.\(id)", target: ioRoot)      // serial
```

- Everything a session owns runs on `sessionQueue`: inbound, outbound and relay connections, timers, and parser state. That includes `start(queue:)` for its `NWConnection`s and `ShadowsocksStream`'s callbacks. Mutable state therefore needs **no locks**, so `LockedFlag` and the locking in `LastActivity` go away.
- The pool is still concurrent across sessions, because the serial queues target the concurrent root.
- `ProxyServer` admission (`activeCount < 200`), the registry (`[SessionID: Session]`) and `stop()` all run on `serverQueue` (M1, M2). A session reports `onClose` back to the server with `serverQueue.async`.
- Rule enforced by review: no `DispatchQueue.global()`, and no captured state touched off its owner queue. Add `dispatchPrecondition(condition: .onQueue(queue))` at the session's entry points in debug builds.

**Step 4a status: done.**
- `ProxyServer`: `ioRoot` (concurrent) → `serverQueue` (serial: listener, admission, `[UInt64: SessionScope]` registry, `stop()`). `AtomicCounter` is gone; the count is `sessions.count`, read and written only on `serverQueue` (M1). `stop()` cancels the listener synchronously, then closes every session on its own queue (M2). `activeSessionCount` is exposed for tests.
- `SessionScope` (`Proxy/SessionScope.swift`) is the interim session object: a serial queue plus the connections the session opened. Handlers are now created per session, start every `NWConnection` and `ShadowsocksStream` on its queue, and `adopt` each one; adopting into a closed scope cancels at once, which covers `stop()` during a dial. It's folded into `Session` in 4d.
- `DoHResolver.resolve(domain:on:)` delivers on the session queue, so the code after a DoH lookup no longer runs on a URLSession thread.
- N14 fixed in `ConnectionRelay.pipe`.
- **Not done in 4a**, deliberately: removing `LockedFlag` / `LastActivity` locking, and `dispatchPrecondition` at handler entry points. The handlers still have paths the plan deletes in 4d, and the locks are harmless on a serial queue, so they go with the handlers. `ShadowsocksStream.connect` still ignores `.waiting` and has no timeout; that is the `Dialer` (4b).

### 6.2 `Dialer` (shared with network-scanner §1 `ServerConnector`)

This is the single implementation of the three copied dial helpers. It is the `ServerConnector` that network-scanner §1 plans, with the same signature extended. Whichever plan lands first creates it, and the other one uses it.

```swift
struct DialTarget: Hashable { let host: String; let port: UInt16 }   // host: name or IP literal

enum DialError: Error { case resolveFailed(Error?), noAddresses, allFailed([NWError]), timeout, cancelled }

protocol Resolver { func resolve(_ host: String, completion: @escaping (Result<[IPAddress], Error>) -> Void) }
// DoHResolver (+ DNSCache) conforms; SystemResolver for "no DoH"; FakeResolver in tests.

protocol Dialing {
    func dial(_ target: DialTarget, on queue: DispatchQueue, trace: ConnectionTrace?,
              completion: @escaping (Result<NWConnection, DialError>) -> Void) -> Cancellable
}

final class ServerConnector: Dialing {
    init(resolver: Resolver?, connectTimeout: TimeInterval = 10, stagger: TimeInterval = 0.25)
}
```

Algorithm (one dial runs entirely on the caller's session queue):
1. If `host` is an IP literal (`IPv4Address(host) ?? IPv6Address(host)`), skip resolution (N10). Otherwise call `resolver.resolve`, or use `NWEndpoint.hostPort` with the system resolver when there is no DoH.
2. Order the addresses: interleave IPv6 and IPv4, starting with IPv4 (RFC 8305-lite).
3. Start attempt 0. Every `stagger` seconds, start the next one if none is ready yet. The first `.ready` wins, and all others are cancelled.
4. Each attempt's `stateUpdateHandler`:
   - `.ready` → win
   - `.failed(e)` or `.waiting(e)` → record `e`, cancel that attempt, and start the next one immediately (N11)
   - `.cancelled` → ignore
5. If all attempts fail → `.allFailed(errors)`. If the overall deadline (`connectTimeout`) passes → `.timeout`.
6. A `completed` flag on the session queue guarantees exactly one completion. Late `.ready`s from losing attempts are cancelled.
7. `trace?.record(.dnsResolved / .tcpConnecting / .tcpReady / .failed)`. The hooks are network-scanner §1's `ConnectionTrace`, unchanged.

TCP options: `noDelay = true` on the outbound. It matters for desync, because otherwise Nagle can merge the segments we split on purpose. The current code sets it in some copies; make sure it is always set.

**Step 4b status: done.**
- `Proxy/ServerConnector.swift` holds `DialTarget`, `DialError`, `Resolver`, `Dialing` and `ServerConnector`. The three `createServerConnection` / `waitForReady` copies are gone; each handler's `resolveAndConnect` is now a five-line call to `dialer.dial`. `ShadowsocksStream.connect` dials the Outline server through it too, so N1 (no timeout, `.waiting` ignored) is fixed.
- Algorithm as above: IP literals skip the resolver; addresses interleave IPv4-first; attempts start every 250 ms or immediately after a failure; `.waiting` counts as a failure (N11); the first `.ready` wins and the rest are cancelled; a 10 s overall deadline. Every attempt is adopted by the session, and a session that closes mid-dial completes with `.cancelled`.
- `DoHResolver` (N10): IP literals (bracketed too) answer themselves; A and AAAA go out in parallel and merge IPv4-first; one failed query doesn't discard the other's answer. The transport is injected (`DoHResolver.Transport`), so the lookup path has unit tests (`DoHResolverTests`).
- `DoHResolverCache` takes a resolver factory, and `ProxyServer` takes the cache and a `Dialing`. `FakeResolver` (tests) maps names to loopback addresses and records lookups; harness scenario 1b covers the DoH path, IPv6-only answers, fallback past a refused address, literals skipping DoH, and an unresolved name.
- **Deviations from the sketch above:**
  - `dial` takes `resolver:` per call and `session: SessionScope` rather than `on queue:`. The resolver depends on the matched profile, and the session is what owns (and cancels) the attempts. A probe in network-scanner §8 creates its own `SessionScope`.
  - `Resolver` returns `[String]?`, not `Result<[IPAddress], Error>`. nil keeps today's behaviour: fall back to the system resolver, so `DialError` has no `resolveFailed` / `noAddresses`.
  - No `trace:` parameter yet: `ConnectionTrace` doesn't exist. network-scanner §2 adds it to `dial` and `DialAttempt`.
  - The system-resolver path (DoH off) is a single attempt to the hostname; `NWConnection` does its own happy eyeballs there.
- Not covered by tests: the 10 s overall timeout. A loopback dial is refused or accepted at once; a blackhole would need a non-loopback address.

### 6.3 `ClientHelloReader` (replaces both `ensureFullTLSRecord`s)

This is a pure, incremental state machine. The session drives it with `receive` results.

```swift
struct ClientHelloReader {
    enum State { case awaitingHeader, awaitingBody(recordLength: Int), done }
    enum Output {
        case needMore                                   // call receive() again
        case clientHello(record: Data, sniOffset: Int?) // full first record; offset relative to record start
        case passthrough(Data)                          // not TLS / not a ClientHello / too big: forward as-is
    }
    static let maxRecord = 16_384 + 256
    private(set) var state: State = .awaitingHeader
    private var buffer = Data()

    mutating func feed(_ chunk: Data) -> Output
    mutating func finishOnEOF() -> Output    // EOF before complete → .passthrough(buffer)
}
```

Transitions:

```
awaitingHeader:
  buffer += chunk
  buffer.count >= 1 && buffer[0] != 0x16           → done, .passthrough(buffer)        (U7)
  buffer.count < 5                                 → .needMore
  version major (buffer[1]) != 0x03                → done, .passthrough(buffer)
  len = UInt16(buffer[3..<5]); len == 0 || len > maxRecord → done, .passthrough(buffer)
  else → awaitingBody(len), fall through
awaitingBody(len):
  buffer.count < 5 + len                           → .needMore
  record = buffer[0 ..< 5+len]; rest = buffer[5+len...]
  record[5] != 0x01 (handshake type ClientHello)   → done, .passthrough(buffer)
  else → done, .clientHello(record: record, sniOffset: TLSParser.extractSNIOffset(record))
         and `rest` is exposed as `reader.leftover` (forwarded after the segments, never dropped)
done: feed() is a programming error (assertionFailure, then .passthrough(chunk))
```

The session adds a **first-byte timer** (2 s) while in `awaitingHeader` with an empty buffer. When it fires, the session starts relaying without desync, which covers server-first protocols over CONNECT. The overall handshake deadline (N8, 10 s) covers `awaitingBody`.

Scope note: a ClientHello split across several TLS records (very large post-quantum key shares) is passed through after the first record. That is a known limitation; today's code has the same one.

### 6.4 Inbound handshakes

Every inbound type has the same contract, and none of them touch the network themselves:

```swift
struct InboundRequest {
    let target: DialTarget
    let kind: Kind            // .tunnel (CONNECT / SOCKS5 CONNECT) | .http(rewrittenHead: Data)
    let leftover: Data        // bytes received after the handshake — MUST be forwarded
}
enum InboundStep {
    case needMore
    case reply(Data, then: InboundStep)    // bytes to write to the client before continuing
    case request(InboundRequest)           // handshake complete
    case fail(reply: Data?, reason: String) // write reply (if any), then close
}
protocol InboundParser { mutating func feed(_ chunk: Data) -> InboundStep }
```

The session decides what to do with the first chunk:
- first byte `0x05` → `SOCKS5Parser`
- otherwise → `HTTPHeadParser`, which handles both CONNECT and absolute-form

The success reply ("200 Connection established", or the SOCKS5 success reply) is **not** produced by the parser. The session sends it only after the outbound is connected. That fixes the current CONNECT path, which sends 200 before dialing, so a dial failure looks like a reset rather than a 502.

#### 6.4.1 `HTTPHeadParser`

```
States: readingHead → done
feed(chunk):
  buffer += chunk
  if buffer.count > 65_536                        → .fail(431)
  guard let end = buffer.range(of: "\r\n\r\n")    → .needMore
  head = buffer[..<end.upperBound]; leftover = buffer[end.upperBound...]
  parse request line "METHOD SP target SP HTTP/1.x":
    malformed                                     → .fail(400)
    METHOD == CONNECT:
      target = authority "host:port" | "[v6]:port"; port required, 1...65535; host ≤ 255 → else .fail(400)
      → .request(.tunnel, target, leftover)
    target starts with "http://":
      parse URL → host, port (default 80), path+query (default "/")
      rebuild head: "METHOD path HTTP/1.1", keep headers except Proxy-Connection, Proxy-Authorization,
                    Connection, Keep-Alive; append "Connection: close"                       (N9)
      → .request(.http(rewrittenHead), target, leftover)   // leftover = start of request body, forwarded as-is
    other (origin-form without CONNECT, https:// absolute) → .fail(400)
    unsupported method token chars                        → .fail(501)
```

`Connection: close` means one request per upstream connection. That removes the cross-host keep-alive bug outright, at the cost of TCP reuse for plain-HTTP traffic. Plain HTTP is rare and isn't the app's purpose, so that cost is acceptable.

#### 6.4.2 `SOCKS5Parser`

```swift
struct SOCKS5Parser: InboundParser {
    enum State {
        case greeting            // need VER NMETHODS METHODS...
        case request             // need VER CMD RSV ATYP ...
        case done
    }
}
```

```
greeting:
  need 2 bytes; VER != 5                         → .fail(nil)                     (close, no reply possible)
  n = buf[1]; need 2+n bytes
  methods contains 0x00 → consume 2+n; state = request;
       → .reply([05 00], then: feed(Data()))      // re-run on remaining buffer: pipelined request (N6)
  else → .fail(reply: [05 FF])
request:
  need 4 bytes; VER != 5                         → .fail(reply(0x01))
  CMD != 1 (CONNECT)                             → .fail(reply(0x07))
  ATYP = 1 → need 4+4+2;  host = IPv4 dotted
  ATYP = 4 → need 4+16+2; host = IPv6 compressed form
  ATYP = 3 → need 5; L = buf[4]; L == 0 → .fail(reply(0x01)); need 5+L+2; host = ASCII (non-ASCII → .fail(0x01))
  else                                           → .fail(reply(0x08))
  port = BE16; port == 0 → .fail(reply(0x01))
  consume header; leftover = rest of buffer; state = done
  → .request(.tunnel, target, leftover)
```

`reply(code)` is `[05 code 00 01 00 00 00 00 00 00]`. The session builds the success reply (`code 00`) after connecting, and maps failures as follows: `DialError.resolveFailed` → `0x04`, `.allFailed` with ECONNREFUSED → `0x05`, `.timeout` → `0x06`, a route policy failure (U6) → `0x02`, anything else → `0x01`.

All "need N" checks return `.needMore` without consuming, so the byte-by-byte tests in §5.2 work by construction.

### 6.5 Router, outbound and session pipeline

```swift
struct RouteDecision {
    let profile: ResolvedProfile          // snapshot, see 6.7
    let outbound: OutboundKind
}
enum OutboundKind {
    case direct                                           // no desync (split mode .none or plain HTTP)
    case desync(DesyncParameters)                         // mode, chunkSize, recordFragmentation
    case shadowsocks(OutlineConfig, inner: DesyncParameters?)   // inner desync is not used today; keep nil
    case reject(reason: String)                           // U6: VPN route without config
}
struct Router { let config: ProxyConfig; func route(_ target: DialTarget, kind: InboundRequest.Kind) -> RouteDecision }
```

`Router.route` is pure and table-tested. It is the **only** place that checks the profile route and the Outline config, so U6 becomes a single `case`.

```swift
protocol Outbound {
    /// Connects and returns a stream ready for relay. `firstFlight` is written before returning,
    /// using whatever transformation the outbound applies (segmentation, SS encryption).
    func open(_ target: DialTarget, firstFlight: FirstFlight, on queue: DispatchQueue,
              completion: @escaping (Result<ConnectionProtocol, Error>) -> Void)
}
enum FirstFlight { case none, raw(Data), clientHello(record: Data, sniOffset: Int?, leftover: Data) }
```

Implementations:
- `DirectOutbound(dialer)`: dial, then write `raw`.
- `DesyncOutbound(dialer, params, desyncer: Desyncer)`:
  - dial, then `desyncer.segments(record, sniOffset)`
  - `SegmentWriter.write(segments, to: conn)`: sequential sends, each waits for its completion, and the first error aborts (N7)
  - then `leftover`
- `ShadowsocksOutbound(dialer, config)`: dial the server, wrap the connection in `ShadowsocksStream`, then write the first flight as payload.

`Desyncer` is a protocol with the current `TLSDesyncer` as its only implementation. SpoofDPI's `custom` mode slots in later.

Session pipeline (all steps on `sessionQueue`):

```
accepted
  → handshaking(parser)            [deadline 10 s]  receive → parser.feed → reply/needMore/fail/request
  → routing                        Router.route(request)
      .reject                      → send failure reply, close
  → (tunnel & .desync)             reply success FIRST (client won't send ClientHello before it)
                                   → readingClientHello(ClientHelloReader) [first-byte 2 s]
  → connecting(outbound)           outbound.open(target, firstFlight)
      tunnel & !desync             → open first, then reply success / failure code (fixes 200-before-dial)
      http                         → open, firstFlight = .raw(rewrittenHead + leftover)
  → relaying                       ConnectionRelay.relay(client, upstream, idle 120 s)
  → closed                         cancel both, report to server registry, log one summary line
```

Ordering detail for the desync tunnel: the client must get "200" or the SOCKS success reply before it sends the ClientHello. Because of that, failures in this path after the reply surface as a reset, which is unavoidable and the same as today. The non-desync and VPN tunnels can dial first and give a proper failure reply.

`Session` is a `final class` holding `state` (an enum with associated values: parser, reader, connections). Each transition is a method that asserts the expected prior state. Wrong-state callbacks, such as a late timer after close, are ignored once `state == .closed`.

### 6.6 `DomainMatcher`

This is SpoofDPI's trie semantics, specified exactly so it can be tested:
- Patterns are lowercased, with trailing dots stripped, and are compared label by label from the right.
- `example.com` matches exactly that host. **Open question:** does today's code also match subdomains? Settle it with the characterization tests in §5.1, and keep whatever users rely on. If a change is needed, migrate existing patterns (`example.com` → `example.com` + `*.example.com`).
- `*.example.com` matches exactly one or more labels in front of `example.com`, per the characterization, and not `example.com` itself.
- `*.google.*` matches `google` as a whole label with any one label after it (fixes U3).
- Priority when several profiles match: the first enabled profile in user order wins, as now. Inside a matcher, specificity doesn't matter, because only a boolean is needed per profile.

Build once per config snapshot. A trie is only worth it with hundreds of patterns; a linear scan over pre-split labels is fine and simpler. Choose the simpler one, behind the `DomainMatcher` type.

### 6.7 Settings: store for the UI, snapshot for the network

```swift
@MainActor final class SettingsStore: ObservableObject {
    init(defaults: UserDefaults = .standard)
    @Published private(set) var profiles: [SpoofProfile]   // decoded once (U4)
    @Published var proxyPort: UInt16                         // validated (M4)
    @Published var dohURL: URL?
    func update(_ profile: SpoofProfile) throws              // validates (U5), debounced write (M6)
    func importJSON(_ data: Data) throws                     // ProfileValidator
    var snapshot: ProxyConfig { get }
}

struct ProxyConfig: Sendable {          // immutable, built from SettingsStore
    let port: UInt16
    let profiles: [ResolvedProfile]     // enabled only, with prebuilt DomainMatcher
    let master: ResolvedProfile
    let doh: URL?
    let limits: Limits                  // maxSessions 200, handshake 10 s, firstByte 2 s, idle 120 s
}
```

- `ProxyServer.init(config: ProxyConfig, dialer:, resolver:)`. When settings change while running, `ProxyManager` calls `server.update(config)`, which swaps the config on `serverQueue`. New sessions use the new snapshot; existing ones keep theirs.
- `AppSettings.shared` stays as a thin deprecated forwarder until every call site has moved, then it is deleted.
- Migration: keep the current UserDefaults keys and JSON shape. The store reads the same format, so no user data migration is needed. Add `isMaster` with a decode default: the profile whose `id` equals today's master id, or the last profile, which matches today's implicit behaviour, once.

### 6.8 Shadowsocks restructuring

- Extract `ShadowsocksAEADCodec`. It has no I/O.
  - `Encoder` (salt, subkey, nonce): `mutating func seal(_ payload: Data) -> Data`. It splits at 0x3FFF and emits `[enc len][tag][enc payload][tag]` per chunk.
  - `Decoder`: the existing state machine `awaitingSalt → awaitingLengthFrame → awaitingPayloadFrame`, moved verbatim out of `ShadowsocksStream` and changed to `mutating func feed(_ data: Data) throws -> [Data]` with an internal buffer. This is the part the §5.1 byte-by-byte tests target.
- `ShadowsocksStream(underlying: ConnectionProtocol, …)` takes the protocol rather than a concrete `NWConnection`, so the fake works. The stream uses the `Dialer` for connect (N1).
- N2 (prefix validation) belongs in `OutlineAccessKey`. N4 is the 10 ms header flush timer on the session queue. N5 checks the RNG status.
- Unify the base64 helpers into `Data(base64URLEncodedLenient:)` in `Shared/`.

This is also where `plans/outline-websocket-transport.md` attaches: the WebSocket transport becomes another `ConnectionProtocol` under `ShadowsocksStream` (§9).

### 6.9 App layer

- `ProxyManager` state machine (U9, U10, U12): `idle | starting | running(port: UInt16) | stopping | failed(Error)`. Audio starts on entering `running` and stops on leaving it.
- `BackgroundAudioPlayer` handles interruptions (U11).
- `ContentView` reads the `ProxyManager` state for the port.

## 7. Phase ordering and deliverables

| Phase | Deliverable | Gate |
|-------|-------------|------|
| 0 | Hotfixes C1–C3, U1, U6, U9, U10 → release v1.5.9 | Manual check; throwaway script for C1 |
| 1 | Root `Package.swift` (`SpoofyCore` + `SpoofyCoreTests`) and `make test` = `swift test` | Smoke KAT passes on macOS; the Xcode app build is unchanged |
| 2 | §5.1 unit tests (with expected failures for open bugs) and `FakeConnection` relay tests. **Done**: see the §5.1 status | Green |
| 3 | Loopback harness (§5.3). `ProxyServer` exposes its port; config injected (resolver with 4b). **Done**: see the §5.3 status | Scenarios 1–4 green against the **current** handlers |
| 4a | Serial session queues (§6.1), M1, M2, N14. **Done**: see the §6.1 status | All tests green |
| 4b | `ServerConnector` (§6.2) replaces the 3 dial helpers, plus `FakeResolver`; N10, N11. **Done**: see the §6.2 status | Green; network-scanner §1 is unblocked |
| 4c | `ClientHelloReader` + `SegmentWriter`; U7, N7, U8, N15 | Expected-failures for U7, N7, U8 and N15 removed |
| 4d | Inbound parsers, `Router`, `Outbound`, `Session`; delete the 3 handlers; N6, N8, N9, M7 | §5.2 session tests and harness scenarios 1–5 green |
| 4e | `SettingsStore`, `ProxyConfig`, `DomainMatcher`; U2–U5, M4, M6 | Characterization tests decide U3 semantics |
| 4f | Shadowsocks codec extraction, N2–N5 and N13 (N1 landed with 4b) | Codec KATs and opt-in interop scenario 6 green |
| 4g | App layer U11, U12, M3 | Manual: call interruption test on device |

Each row is one PR-sized change. Steps 4a–4c are mechanical and low-risk. Step 4d is the big one, and it lands only when the harness is green against the old handlers, so the harness is the contract.

## 8. Testing (summary)

- **Unit:** parsers, desync, DNS wire format, crypto KATs, codec, matcher, router, settings store. Fast, no I/O.
- **Fake connection:** sessions, segmentation, timeouts and error paths. Deterministic.
- **Loopback:** the end-to-end contract for refactor step 4d. Ephemeral ports, a fake resolver, and a 5-second per-test limit.
- **Opt-in interop:** Shadowsocks against the local `docker-compose` shadowbox.
- **Manual device checklist** after 4d and 4g:
  - Safari over the proxy with each split mode
  - a VPN route
  - background for 10 minutes
  - a phone-call interruption
  - Stop actually drops connections

## 9. Interaction with other plans

- **`plans/network-scanner.md` §1.** The `ServerConnector` here (§6.2) *is* that one. The signature is extended with `on queue:` and a `Result` error, and it keeps the optional `ConnectionTrace`. Whichever lands first owns it. The scanner's relay instrumentation goes into `ConnectionRelay` after step 4a, so it doesn't need its own locking: `ConnectionTrace` is then only touched on the session queue. Its lock stays because the scanner reads traces from the UI.
- **`plans/outline-websocket-transport.md`.** It is easier after step 4f: `WebSocketStream` conforms to `ConnectionProtocol` and slots under `ShadowsocksStream` through `ShadowsocksOutbound`, with transport selected in `OutboundKind.shadowsocks(config)`. Its MiniYAML and `OutlineAccessKey` tests go into `SpoofyCoreTests` from Phase 1, so MiniYAML must live in one of the core folders, not in `Spoofy/`. If that plan is implemented first, do 4f's codec extraction as part of it.
- New split modes (SpoofDPI `custom`) only add a `Desyncer` implementation and a `DesyncParameters` case.

## 10. Risks

- **Behaviour drift in step 4d.** Replacing three handlers at once is the riskiest step. Mitigation: the loopback harness runs against the old code first, and the session tests must pass on both implementations. Optionally keep the old handlers behind a debug toggle for one release.
- **Serial queues slow throughput.** Unlikely, because each session is serial and sessions stay parallel. Measure with a 100 MB download through the proxy before and after 4a.
- **Domain-matching semantics change (U3) breaks user patterns.** The characterization tests come first. Any semantic change ships with an automatic pattern migration and a release note.
- **Failing closed on a missing VPN config (U6)** may look like "the internet broke" to users with a half-configured profile. Show the reason in the UI log and on the profile row.
- **`Connection: close` for plain HTTP (N9)** loses keep-alive for HTTP/1.1 sites. Acceptable for a DPI tool whose traffic is about 99% TLS.
- **ClientDataWait (N4)** sends a header-only first chunk for server-first protocols. That is a fixed-size first packet, a mild fingerprint, but it is the same as outline-sdk's behaviour.
- **Tests run on macOS, the app runs on iOS.** Network.framework, CryptoKit and CommonCrypto behave the same for what the core uses. Differences that could matter:
  - iOS background suspension: not testable in a package anyway; covered by the manual checklist.
  - Loopback socket behaviour and timer jitter: harness timeouts are generous (5 s).
  
  Before each release, keep the manual device checklist (§8).
- **Double membership.** Every core file is compiled by both the app target and the package. A new core file that is added to the package (automatic, by folder) but not to the app target fails the Xcode build, which is loud and easy to fix. The reverse case can't happen, because the package picks up files by folder.
- **The package root is the repo root**, so SwiftPM sees the whole repo. If `swift build` gets slow or noisy, add `exclude:` for `Spoofy/`, `build/`, `altstore/` and `Docs/`.
