# Plan: Outline over WebSocket (wss://) transport

Status: draft · Phase 1 of 2 (system TLS). Phase 2 (own TLS over raw TCP, so the
ClientHello to the wss server can be fragmented) is out of scope; see the last section.

## Goal

Let a VPN-mode profile reach the Outline server via **Shadowsocks-over-WebSocket-over-TLS**
instead of raw TCP. The target is the `outline-ss-server` `websocket-stream` listener, usually
behind a CDN (Cloudflare) or a reverse proxy (Caddy/nginx).

On the wire it looks like: TLS to the CDN/proxy (SNI = config host) → HTTP/1.1 Upgrade →
binary WS messages whose concatenated payload is the ordinary Shadowsocks AEAD TCP stream
(salt, then [enc len][enc payload] frames). Message boundaries mean nothing: the server
reassembles a byte stream from them, and so do we.

Non-goals for phase 1:
- UDP (`websocket-packet`). Spoofy doesn't relay UDP over Outline today.
- Fragmenting the ClientHello to the wss host. `NWProtocolTLS` owns the handshake.
- `first-supported` / multi-hop configs beyond what's needed to extract one TCP transport.

## Current state (what we build on)

- `ShadowsocksStream` (`Shadowsocks/ShadowsocksStream.swift`) owns a concrete `NWConnection`
  (`underlying`). Its static `connect(...)` builds a raw TCP `NWConnection` to `config.host:port`
  and has **no connect timeout**.
- `ConnectionRelay` works over `ConnectionProtocol` (send/receive/cancel), so
  any stream type can be relayed.
- Three callers use `ShadowsocksStream.connect(config:targetHost:targetPort:queue:)`:
  `HTTPHandler`, `HTTPSHandler`, `SOCKS5Handler`. Their signatures don't need to change.
- `OutlineServerConfig { host, port, password, cipher, prefix }` is stored as JSON inside
  `SpoofProfile` in UserDefaults. **`AppSettings.profiles` silently resets to defaults if
  decoding fails**, so every model change must decode old data (`decodeIfPresent`).
- `OutlineAccessKey.parse` handles `ss://` only. The UI is one text field in
  `SettingsView.swift:305` → `parseAccessKey`.
- The Xcode project is `objectVersion = 56` (no synchronized folders), so new `.swift` files
  must be registered in `project.pbxproj` (file ref + group + Sources build phase), or added
  through Xcode.

## 1. Model

`Shared/AppSettings.swift`:

```swift
enum OutlineTransport: Codable, Equatable {
    case tcp                                   // host/port from OutlineServerConfig
    case webSocket(WebSocketEndpoint)
}

struct WebSocketEndpoint: Codable, Equatable {
    var url: URL                // wss://proxy.example.com/<secret>/tcp  (ws:// allowed for local tests)
    var sni: String?            // optional TLS server name override; nil = url.host
    var hostHeader: String?     // optional Host header override; nil = url.host (+port if non-default)
    var connectAddress: String? // optional IP/host to dial instead of url.host (manual "pinned IP")
}

struct OutlineServerConfig: Codable, Equatable {
    var host: String            // tcp: server host. ws: url.host (kept so the existing UI/labels still work)
    var port: UInt16            // tcp: server port. ws: url port or 443
    var password: String
    var cipher: ShadowsocksCipher
    var prefix: Data?
    var transport: OutlineTransport = .tcp   // NEW
    var sourceURL: String?                   // NEW: ssconf:// / https:// it was fetched from, for "Refresh"
}
```

- Custom `init(from:)` for `OutlineServerConfig`:
  `transport = decodeIfPresent(...) ?? .tcp`, `sourceURL = decodeIfPresent(...)`.
  Without it, old settings would stop decoding and every profile would be wiped.
- Synthesized `Codable` for an enum with associated values gives
  `{"tcp":{}}` / `{"webSocket":{"_0":{...}}}`. That's acceptable, but encode explicitly
  (`{"type":"websocket","url":...}`) so exported settings JSON stays readable. Decide once and
  add a round-trip check (see Testing).
- `sni` / `hostHeader` / `connectAddress` exist for CDN tricks and pinning. Phase 1 UI only
  displays them when a config sets them. No editing UI.

## 2. Transport layer

New file `Shadowsocks/OutlineDialer.swift`. It's the one place that turns a config into a
ready byte stream.

```swift
enum OutlineDialer {
    /// Opens the transport to the Outline server and calls completion exactly once
    /// with a ready stream, or nil on failure or timeout (10 s, same as the direct paths).
    static func dial(_ config: OutlineServerConfig, queue: DispatchQueue,
                     completion: @escaping (ConnectionProtocol?) -> Void)
}
```

- `.tcp`: today's code moved out of `ShadowsocksStream.connect` (TCP noDelay,
  `preferNoProxies`), plus the `LockedFlag` + `asyncAfter(10)` timeout pattern copied from
  `HTTPSHandler.waitForReady`. This also fixes the existing missing timeout.
- `.webSocket`: `WebSocketStream.connect(endpoint, queue:, completion:)` (section 3), wrapped
  with the same timeout.

`ShadowsocksStream` changes:
- `underlying: NWConnection` → `underlying: ConnectionProtocol`.
- `connect(config:targetHost:targetPort:queue:completion:)` keeps its signature. Its body
  derives `masterKey` (unchanged), calls `OutlineDialer.dial`, and wraps the result. The
  callers (`HTTPHandler`, `HTTPSHandler`, `SOCKS5Handler`) stay untouched.
- The crypto, send path and receive state machine don't change. One behavioural detail
  matters, see 3.3.

## 3. `WebSocketStream: ConnectionProtocol`

New file `Shadowsocks/WebSocketStream.swift`. It presents a WS connection as a plain byte
stream.

### 3.1 Connection setup

```swift
let tls = NWProtocolTLS.Options()
if let sni = endpoint.sni {
    sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, sni)
}
// ALPN must be http/1.1. WS-over-h2 (RFC 8441) isn't supported by NWProtocolWebSocket.
sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")

let tcp = NWProtocolTCP.Options(); tcp.noDelay = true
let params = NWParameters(tls: url.scheme == "wss" ? tls : nil, tcp: tcp)
params.preferNoProxies = true

let ws = NWProtocolWebSocket.Options()
ws.autoReplyPing = true
ws.maximumMessageSize = 1 << 20
var headers = [("User-Agent", <browser-like UA>)]
if let h = endpoint.hostHeader { headers.append(("Host", h)) }
ws.setAdditionalHeaders(headers)
params.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)

let conn = NWConnection(to: .url(endpoint.url), using: params)
```

- `connectAddress` set: dial `NWEndpoint.hostPort(connectAddress, port)` instead of `.url`.
  The path still has to reach the WS upgrade request. Verify whether
  `NWProtocolWebSocket` takes the request path from `.url` only. If it does, build the
  endpoint as `.url` with the IP and force SNI and the `Host` header via the overrides above.
  **Spike this first** (see Risks). If it can't be made to work, drop `connectAddress` from
  phase 1.
- Don't use `URLSessionWebSocketTask`. It's message/async based and harder to fit
  `ConnectionProtocol`. It also ignores `preferNoProxies`-style control, so with Spoofy set as
  the system proxy it could route through Spoofy itself.
- **Proxy loop:** `preferNoProxies = true` is essential. Otherwise, with Spoofy configured as
  the system proxy on macOS, the WS connection would go back into Spoofy.
- **DoH:** phase 1 resolves the wss host with system DNS. If the profile has DoH enabled,
  resolve `url.host` through the profile's `DoHResolver` first and dial the IP with SNI/Host
  preserved. This uses the same mechanism as `connectAddress`, so it depends on that spike.
  Without the spike it's a follow-up.

Ready = `stateUpdateHandler` `.ready`. That fires after the TLS handshake **and** the
101 Switching Protocols, because the WS protocol is part of the stack. Failure modes to log
distinctly so users can debug CDN configs:
- `.failed(NWError.tls)`: TLS/cert problem.
- `.failed` with a WS error / `.waiting`: upgrade rejected. Read the HTTP status via
  `NWProtocolWebSocket.Metadata` on the connection if available, or log
  `conn.metadata(definition: NWProtocolWebSocket.definition)`.
- Timeout (dialer level).

### 3.2 Send

```swift
func send(content: Data?, contentContext:, isComplete: Bool, completion:) {
    guard let data = content, !data.isEmpty else {
        // ConnectionRelay never sends empty data with isComplete=true today. If it does,
        // treat it as "close": send a WS close frame (opcode .close, code .protocolCode(.normalClosure)).
        ...
    }
    let meta = NWProtocolWebSocket.Metadata(opcode: .binary)
    let ctx = NWConnection.ContentContext(identifier: "ss", metadata: [meta])
    underlying.send(content: data, contentContext: ctx, isComplete: true, completion: completion)
}
```

One `send` = one binary message. `isComplete: true` is **required** here: in a
message-oriented protocol it marks the end of the message. Shadowsocks already hands
us ≤ (16 KB + overhead) per chunk batch, so there's no need to coalesce or split.

### 3.3 Receive: the important part

On a WS connection, `receiveMessage` / `receive` deliver **one message per completion** and set
`isComplete = true` at the end of **every message**. `ShadowsocksStream.readAndProcess` and
`ConnectionRelay.pipe` both treat `isComplete == true` (with no pending data) as **EOF**. If we
passed it through unchanged, the first WS message that contained only part of a Shadowsocks
frame would close the tunnel.

So `WebSocketStream` translates:

```
receive(min:, max:, completion:)
  if pending non-empty → deliver pending.prefix(max), isComplete=false
  else underlying.receiveMessage { data, ctx, isComplete, error in
     if error            → completion(nil, ctx, true, error)
     let meta = ctx?.protocolMetadata(definition: NWProtocolWebSocket.definition) as? NWProtocolWebSocket.Metadata
     switch meta?.opcode
       case .binary, .cont, nil(with data):
            pending.append(data); deliver pending.prefix(max) with isComplete=false
       case .text:         treat as binary (outline-ss-server only sends binary); log once
       case .close:        completion(nil, ctx, true, nil)          // real EOF
       case .ping, .pong:  (autoReplyPing handles ping) → loop: receive again
     if ctx?.isFinal == true and no data → completion(nil, ctx, true, nil)  // TCP EOF without close frame
  }
```

- `pending` buffer: a message can be larger than the caller's `maximumLength`
  (ShadowsocksStream asks for 32768; the server may send bigger). Keep the remainder and serve it
  first next call, same pattern as `ShadowsocksStream.pendingDecrypted`.
- Empty binary message → loop and read again. Never report empty data with isComplete=false
  (ConnectionRelay would busy-loop on "empty read, retrying").
- All state is touched only from the receive completion chain, which is serialized per
  direction by design. Send state and receive state don't overlap, so no lock is needed, same
  as `ShadowsocksStream`.

### 3.4 Cancel / close

`cancel()`: best-effort send of a close frame, then `underlying.cancel()` right away
(don't wait for the close handshake; relay teardown must stay synchronous). Make it
idempotent with a `LockedFlag`.

### 3.5 Keepalive

CDNs drop idle WebSockets (Cloudflare ~100 s). `ConnectionRelay`'s 120 s idle timeout kills
idle tunnels anyway, so phase 1 needs no client pings. If we later raise the relay timeout,
add a `DispatchSourceTimer` that sends `.ping` every 30 s while the stream is alive.

## 4. Config parsing

`Shadowsocks/OutlineAccessKey.swift` becomes the single entry point, with three input forms.

| Input | Handling |
|---|---|
| `ss://…` | Unchanged. `transport = .tcp`. |
| `ssconf://host/path…` or `https://…` | Dynamic key. Fetch it (4.1), then parse the body with the next two rows. |
| Text starting with `{` | JSON: legacy Outline dynamic-key JSON *or* new-format config in JSON. |
| Text containing `transport:` | YAML new-format config (4.2). |

Since this becomes async, `parse` splits into:
- `static func parse(_ text: String) -> OutlineServerConfig?`: synchronous, for `ss://`,
  JSON and YAML text.
- `static func resolve(_ text: String, completion: @escaping (Result<OutlineServerConfig, KeyError>) -> Void)`:
  fetches if needed, then calls `parse`, sets `sourceURL`.
- `KeyError` carries a user-readable message ("Server returned 404", "Unsupported transport
  `$type: …`", "WebSocket UDP-only config", …). This replaces the single "Invalid access key".

### 4.1 Fetching dynamic keys

- `ssconf://` → `https://` with the same rest of the URL. Fragment (`#name`) is stripped.
- `URLSession` with an **ephemeral** config and `connectionProxyDictionary = [:]`. That
  bypasses the system proxy, which may be Spoofy itself and may be stopped. Timeout 15 s.
- Status 200 only. Body ≤ 64 KB. Trim whitespace. If the body starts with `ss://`, feed it to
  the `ss://` parser.
- The fetch domain itself may be blocked. That's out of scope; the user can paste the
  YAML/JSON body directly, and the error message should say so.

### 4.2 Accepted config shapes

Legacy JSON (old dynamic keys):
```json
{"server":"1.2.3.4","server_port":443,"password":"…","method":"chacha20-ietf-poly1305","prefix":"…"}
```

New format (YAML or JSON). **Verify the field names against the current Outline client
source (`outline-apps`, config parsing in `client/src/www/app/outline_server_repository/`)
and the outline-sdk `x/config` docs before implementing.** The shape we expect:

```yaml
transport:
  $type: tcpudp
  tcp:
    $type: shadowsocks
    endpoint:
      $type: websocket
      url: wss://proxy.example.com/SECRET/tcp
    cipher: chacha20-ietf-poly1305
    secret: SECRET
    prefix: "POST "            # optional
  udp:
    …                          # ignored
```

Extraction rules (operate on the parsed tree `Any`: `[String: Any]` / `[Any]` / `String` / `Int`):
1. `root["transport"]`, else `root` itself.
2. If `$type == "tcpudp"` → take `tcp`. If it's absent → error "UDP-only config".
3. If `$type == "first-supported"` → walk `options` in order and take the first that extracts
   successfully.
4. `tcp` node can be:
   - a string `ss://…` → old parser (`.tcp`);
   - `$type: shadowsocks` with `cipher`, `secret`, optional `prefix`, and `endpoint`:
     - string `"host:port"` or `$type: dial` + `address: "host:port"` → `.tcp`;
     - `$type: websocket` + `url` → `.webSocket`. `host`/`port` come from the URL (default 443/80);
     - anything else (e.g. `$type: tls` wrapping) → error naming the `$type`.
5. `cipher` must map to `ShadowsocksCipher`. Unknown → error naming the cipher.
6. `prefix` in the new format is a plain string whose code points 0–255 become bytes
   (Outline's convention; verify). Reuse/adapt `urlDecodeBytes` semantics accordingly.

### 4.3 Minimal YAML subset parser

New file `Shadowsocks/MiniYAML.swift`, ~150 lines, no dependency. We only need what Outline
emits:

- Block mappings by indentation (spaces only; a tab → error).
- `key: scalar`, `key:` followed by a more-indented block, `- item` sequences (scalar items and
  mapping items `- key: value`).
- Scalars: plain, `'single'` (`''` escape), `"double"` (`\" \\ \n \t \xHH \uHHHH`). Leave
  plain scalars as `String`; the extraction step converts ports to ints.
- `#` comments (full line, or after whitespace outside quotes). Blank lines. `---` at the top.
- Inline flow `{a: b}` / `[a, b]`: support one level deep for flow mappings/sequences of
  scalars. Anything more complex → error "unsupported YAML".
- No anchors, tags, multi-line scalars or merges. Hitting one of those → error, not
  silent misparse.

Algorithm: tokenize into lines `(indent, content)`, skipping blank/comment lines. Then recursive
`parseBlock(minIndent)`:
- a line starting `- ` → sequence at this indent; each item parses its rest-of-line, plus any
  deeper lines, as a nested block (the rest-of-line `key: v` opens a mapping whose indent is
  `indent + 2`);
- otherwise a mapping. Split at the first `:` that's outside quotes and followed by a space/EOL.
  An empty value → child block at the next line's indent (must be > current), or `null` when
  there's no deeper line.
- Duplicate key → error.

Since JSON is close to a YAML subset but our parser isn't a full YAML one, route any `{`-prefixed
body to `JSONSerialization` first and fall back to MiniYAML only if that fails.

## 5. UI (`Spoofy/SettingsView.swift`)

- Rename the field placeholder to "Access key (ss://, ssconf://, or config)". Keep it a
  multiline `TextField`, but raise `lineLimit` to `3...8` for pasted YAML.
- `parseAccessKey` stays synchronous for `ss://`/JSON/YAML. For `ssconf://`/`https://`, show
  "Fetching…" with a `ProgressView`, call `resolve`, and assign on the main queue. Debounce
  ~500 ms so typing a URL doesn't fire a fetch per keystroke. Also ignore stale results (keep a
  request token).
- Server summary rows (both the inherited and own blocks share this; extract a small
  `OutlineConfigSummary(config:)` view to stop duplicating it):
  - TCP: `server.rack host:port` (as now).
  - WS: `globe url.host + url.path` and a "WebSocket (TLS)" label (or "WebSocket (no TLS)" for
    `ws://`). Show sni/host overrides if present.
  - `sourceURL != nil`: a "Refresh" button that re-runs `resolve(sourceURL)`.
- Note: the text field state isn't persisted; only the parsed config is. With `sourceURL`
  we can refill the field with the URL on `onAppear`, which is a small UX improvement.

## 6. Project / housekeeping

- Add `OutlineDialer.swift`, `WebSocketStream.swift` and `MiniYAML.swift` to `project.pbxproj`
  (the Spoofy target, all platforms the target builds for: iOS + macOS).
- README: in "VPN mode / Outline server", document WS keys and the CDN setup (a short version of
  the Caddy + Cloudflare recipe), plus the limitation that the ClientHello to the wss host isn't
  fragmented.
- Export/import: `ExportedSettings` gets the new fields automatically. Check that an old export
  still imports (decode compat) and that a new export round-trips.

## 7. Testing

There's no test target today. Keep that unchanged in phase 1, but add a small
`#if DEBUG` self-check function run from a debug menu or on launch in debug builds. Better
still, add a minimal XCTest target if you're OK with touching the project for it. It should
cover:
- `MiniYAML` against: the sample above, the outline-sdk doc examples, comments/quotes edge
  cases, tabs (error), anchors (error).
- `OutlineAccessKey.parse` for every row in 4's table, including `first-supported` and a UDP-only
  config (error).
- `OutlineServerConfig` decode of an **old** JSON blob (no `transport`) → `.tcp`.
- `WebSocketStream` receive translation: a fake underlying that delivers messages split mid
  Shadowsocks frame → the stream must not end early. This is the regression that matters most.

Live test environment (extend `docker-compose.yml` or make a separate
`docker-compose.ws.yml`):
- `outline-ss-server` ≥ the version with `web:` / `websocket-stream` listeners (verify the
  version and the image; the current `diffusehyperion/outline-vpn` shadowbox image may not
  expose WS listeners, so build/run `outline-ss-server` directly with a config like:

  ```yaml
  web:
    servers:
      - id: ws
        listen: ["0.0.0.0:8000"]
  services:
    - listeners:
        - type: websocket-stream
          web_server: ws
          path: "/test/tcp"
      keys:
        - id: user1
          cipher: chacha20-ietf-poly1305
          secret: <secret>
  ```
- Steps:
  1. `ws://` directly to :8000. This proves framing without TLS.
  2. Caddy with an internal CA in front → `wss://`. On a device, use a real cert (Cloudflare
     origin cert or Let's Encrypt), because self-signed certs fail TLS validation and phase 1
     won't support pinning.
  3. Cloudflare-proxied domain → real-world path: HTTP CONNECT from Safari, SOCKS5 from
     `curl --socks5-hostname`, a long download (>16 KB frames, back-pressure) and a long-lived
     wss site through the tunnel.
- Wireshark check: only TLS to the CDN IP. The SNI equals the configured host (or the `sni`
  override).

## 8. Risks / open questions

1. **`NWProtocolWebSocket` + custom dial address** (`connectAddress`, DoH): unclear whether you
   can dial an IP while keeping the URL path, Host and SNI. Spike it before step 2 (~1 h). If it
   doesn't work, ship without `connectAddress`/DoH for WS.
2. **Outline config field names** (4.2): they come from memory. Confirm them against the
   `outline-apps` source.
3. **The receive `isComplete` semantics** on WS connections (3.3): confirm empirically with
   logging in the spike, including what `receive(min:max:)` vs `receiveMessage` return for
   large messages.
4. **CDN/ISP throttling** (e.g. the reported throttling of Cloudflare after ~16 KB): this is an
   environmental problem and code can't fix it. Test on the target network before spending
   effort on UI polish.
5. **iOS background:** same as the existing TCP path. Nothing new expected.

## 9. Order of work

1. Spike (risks 1 and 3): a throwaway WS client against local `outline-ss-server`.
2. `OutlineDialer` + `ShadowsocksStream` refactor to `ConnectionProtocol` (TCP only). Check that
   existing Outline profiles still work → commit.
3. `WebSocketStream` + `OutlineTransport` model with decode compat. Hard-code a `ws://` config
   in a debug build → tunnel works → commit.
4. Parsers: MiniYAML, the new-format/legacy JSON extraction, then `ssconf://` fetch → commit.
5. UI (summary view, fetching state, refresh) → commit.
6. README + test against a real CDN → release as alpha via `make release-alpha`.

## Phase 2 (later): own TLS over raw TCP

If the SNI to the wss host gets blocked, replace `NWProtocolTLS` in `WebSocketStream` with a
TLS client that runs over a raw TCP `NWConnection`. That gives us the ClientHello bytes, so
`TLSDesyncer.split` can fragment them exactly as in `HTTPSHandler`. Options:
- an `NWProtocolFramer` that sits *below* TLS and fragments the first outbound record. That's
  worth a spike first, since it could keep system TLS and be much smaller;
- a vendored TLS 1.3 client library;
- a hand-written TLS 1.3 client (big).

The `WebSocketStream` interface and everything above it stays the same. Only the
connection-setup step in 3.1 changes, plus a hand-rolled WS framer if the system TLS stack is
dropped entirely.
