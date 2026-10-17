# Spoofy

## Idea

A DPI bypass tool for iOS and macOS (Mac Catalyst).
It is a local HTTP/SOCKS5 proxy. It fragments the TLS ClientHello (TCP segments and/or TLS records) so DPI can't read the SNI. It resolves names over DoH and can route selected domains through an Outline (Shadowsocks) server.
Per-domain profiles pick the strategy; the Master profile covers everything else.

Not on the App Store and there is no paid developer account. Releases are unsigned IPAs sideloaded via AltStore. NetworkExtension (system-wide VPN) is not an option.

## Stack

- Swift 5 language mode (`SWIFT_VERSION = 5.0`), iOS 16+, Mac Catalyst
- SwiftUI for the app; Network.framework (`NWListener`/`NWConnection`), CryptoKit, CommonCrypto for the core
- No third-party dependencies
- Tests: XCTest through a test-only Swift package (`Package.swift`, target `SpoofyCore`), run on macOS with `swift test`. No simulator, no signing.

## Structure

```
Proxy/              proxy core
  ProxyServer.swift   listener, admission (≤200 sessions), session registry, stop(); serverQueue
  Session.swift       one client connection: handshake → route → connect → first flight → relay
  SessionScope.swift  serial queue + connections a session owns
  Inbound.swift       InboundRequest / InboundParser; first byte picks SOCKS5 or HTTP
  HTTPHeadParser.swift, SOCKS5Parser.swift   pure, incremental inbound parsers
  Router.swift        the only place that decides direct / desync / Shadowsocks / reject
  Outbound.swift      DirectOutbound, ShadowsocksOutbound
  ServerConnector.swift  the shared dialer (DoH, A+AAAA, timeouts)
  FirstFlightReader.swift, SegmentWriter.swift   read the ClientHello, write desync segments
  ConnectionRelay.swift  two pipes with an idle timeout
TLS/                ClientHello parsing, ClientHelloReader, TLSDesyncer (split modes), PatternMask
DNS/                DoHResolver (wire format), DNSCache
Shadowsocks/        AEAD crypto, ShadowsocksStream, OutlineAccessKey (ss:// parsing)
Shared/             settings and config
  SpoofProfile.swift  profile model (UserDefaults JSON shape; keep it compatible)
  SettingsStore.swift @MainActor store for the UI
  ProxyConfig.swift   immutable snapshot the network code reads
  DomainMatcher.swift label-wise domain patterns (`example.com`, `*.example.com`, `*.google.*`)
Spoofy/             app layer (SwiftUI): views, ProxyManager, BackgroundAudioPlayer (keep-alive)
Tests/SpoofyCoreTests/   unit, fake-connection and loopback tests
  Support/            FakeConnection, FakeResolver, LoopbackOrigin, TestClient, ClientHelloBuilder
plans/              work plans; code comments cite them (`plan §6.5`, finding IDs `U13`, `N8`)
altstore/           AltStore sources (*.json tracked) and release builds (ignored)
Docs/               README screenshots
docker-compose.yml, config.yml   local Outline/shadowbox server for interop testing
```

### Rules that the build enforces or relies on

- **Core boundary.** `Proxy/`, `TLS/`, `DNS/`, `Shadowsocks/` and `Shared/` import only Foundation, Network, CryptoKit, CommonCrypto and os.log. No UIKit, SwiftUI or AVFoundation; `swift test` breaks if you add one. UI-only code goes in `Spoofy/`.
- **Double membership.** The Xcode app target compiles the core files directly (it does not depend on the package), and the project has no synchronized folders. A new core file is picked up by the package automatically but **must be added to the app target in `project.pbxproj`** by hand. A new file at the repo root goes into `exclude:` in `Package.swift`.
- Tests use `@testable import SpoofyCore`, so `internal` is enough; don't make things `public` for tests.
- **Concurrency** (plan §6.1): everything a session owns runs on its serial queue, so session state needs no locks. Server state lives on `serverQueue`. No `DispatchQueue.global()`, and no state touched off its owner queue.
- The network code never reads settings directly. It gets a `ProxyConfig` snapshot.

## Commands

### Basic checks

```bash
make test        # swift test: the whole core suite, ~10 s
swift test --filter SessionTests          # narrow to one class (or Class/testMethod)
xcodebuild build -project Spoofy.xcodeproj -scheme Spoofy \
  -destination 'generic/platform=iOS' -derivedDataPath build/ios-check \
  CODE_SIGNING_ALLOWED=NO -quiet          # does the app target still compile
```

`swift test` doesn't compile `Spoofy/`, and it doesn't catch a core file missing from the app target. Run the `xcodebuild` check whenever you touch `Spoofy/`, add or rename a file, or change an API the app uses.

### Running the app

- `make install-macos`: Catalyst build into `/Applications` (signs with the team from the project).
- The proxy can be checked from a shell when it's running: `curl -x http://127.0.0.1:<port> https://example.com` or `curl --socks5-hostname 127.0.0.1:<port> …`.
- iOS needs a real device and is checked by the user.
- Outline interop: `docker-compose up -d` starts a local shadowbox.

### Releases

`make release VERSION=x.y.z DESCRIPTION="…"` (or `release-alpha`) bumps the version, builds the IPA and the macOS zip, commits, pushes, and creates a GitHub release. It publishes; run it only when asked.

# How we work

**Loop for each step:**

1. **Red**: write a failing test for the step's behaviour. Pure logic gets unit tests. Session and relay behaviour goes over `FakeConnection`. End-to-end behaviour goes into the loopback harness (`LoopbackHarnessTests`).
2. **Green**: the minimal code that makes it pass.
3. **Refactor**: clean up while the tests stay green.
4. **Checks**: `make test`, plus the `xcodebuild` check if the app layer or the file list changed.
5. **Manual check**: whatever the tests can't reach (the UI, background behaviour, a real network with DPI) goes on a short checklist for the user to run on the device. Say exactly what to try.
6. **Commit**: one step = one commit, titled like `Step 4e: SettingsStore, ProxyConfig and DomainMatcher`.

**Step size:** one meaningful change that can be checked, half a day at most. Each step leaves the app shippable.

**Compatibility:** keep the UserDefaults keys and profile JSON shape readable; users carry settings across updates. If domain-matching semantics change, existing patterns are migrated.
