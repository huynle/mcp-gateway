# MCP tunnel (`internal/federation/tunnel`, `mcp-gateway tunnel`)

The tunnel lets a user connect a **stdio MCP server** or an MCP server on a **private network** to the gateway. The gateway never starts programs and never dials into the user's network. Instead, the user runs `mcp-gateway tunnel` (the client CLI; `mcp-gateway-tunnel` is a compatible alias binary) next to the server. It connects **out** to the gateway over a WebSocket, and the gateway sends the MCP traffic back down that connection. Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz` (tunnel-only stdio), `17iv8p3b` (schema), `dzjepj6k` (tunnel transport), `ejjvsv5y` (stdio bridge); task `kwllocck`.

```
harness ──/mcp──▶ gateway ── federation client ── tunnel transport ═══ WebSocket (outbound from the user) ═══▶ mcp-gateway tunnel ──▶ stdio server (spawned locally)
                                                   (tunnel:// URLs only)                                                     └──▶ http://localhost:PORT/mcp
```

## Install the client

The client CLI `mcp-gateway` (with the alias `mcp-gateway-tunnel`) is published on [GitHub Releases](https://github.com/huynle/mcp-gateway/releases) for macOS, Linux and Windows on amd64 and arm64 (decision `efq0ncag`):

```sh
brew install huynle/tap/mcp-gateway        # Homebrew (macOS, Linux): cask in huynle/homebrew-tap

curl -fsSL https://gateway.huynle.com/install | sh   # your gateway's /install
# or, without a gateway: curl -fsSL https://github.com/huynle/mcp-gateway/releases/latest/download/install.sh | sh
#   VERSION=v1.2.3 pins a release; INSTALL_DIR (default $HOME/.local/bin) picks the directory; no sudo

go install github.com/huynle/mcp-gateway/cmd/mcp-gateway@latest   # from source
```

Every gateway serves `GET /cli` (a public install-and-tunnel guide, linked as *Install CLI* in every page's footer and shown as a card on My account) and `GET /install` (and `/install.sh`): a 302 to the latest release's `install.sh`, so the portal can show `curl -fsSL <GATEWAY_BASE_URL>/install | sh`. The homepage and the servers page's tunnel section show it with the Homebrew and `go install` alternatives as tabs (CSS only, no inline script). `install.sh` maps `uname` to the archive (`mcp-gateway_<os>_<arch>.tar.gz`, `.zip` on Windows), downloads it and `checksums.txt` from the same release, refuses a checksum mismatch or a missing entry, and installs both binaries atomically. Each archive, `checksums.txt` and `install.sh` carry a GitHub build provenance attestation: `gh attestation verify mcp-gateway_linux_amd64.tar.gz --repo huynle/mcp-gateway`. The Homebrew cask clears the macOS quarantine attribute because the binaries are not notarized.

`mcp-gateway` subcommands: `tunnel` (below), `version`, `help [command]`. An unknown command prints the usage and exits 2.

## For users

1. In the portal (*Servers → Tunnels*), create a tunnel. The token (`mgt_…`) is shown **once**. Only its SHA-256 is stored. The page shows the install commands and the exact run commands with the gateway URL, the token and the server address filled in, each with a copy button; the tunnel list keeps the commands with a `<token shown once>` placeholder.
2. Add a server with the URL `tunnel://<tunnel id>` (or `tunnel://<tunnel id>/mcp`; see *Paths* below).
3. On the machine with the server, run one of:

```sh
export MCP_GATEWAY_TUNNEL_TOKEN=mgt_…            # preferred over --token (visible in ps)

# a stdio server: the tunnel client starts it and bridges it
mcp-gateway tunnel --gateway https://gateway.huynle.com --stdio "npx -y @modelcontextprotocol/server-everything"

# a private HTTP server
mcp-gateway tunnel --gateway https://gateway.huynle.com --http http://localhost:8080/mcp

# the alias takes the same flags
mcp-gateway-tunnel --gateway https://gateway.huynle.com --http http://localhost:8080/mcp
```

| Flag / env | Meaning |
|---|---|
| `--gateway` / `$MCP_GATEWAY_URL` | gateway base URL; https required (http only for `localhost`/loopback) |
| `--token` / `$MCP_GATEWAY_TUNNEL_TOKEN` | the tunnel token; never logged; removed from the stdio server's environment |
| `--stdio "<cmd> <args>"` | start this command and bridge its stdin/stdout. Arguments split on whitespace, with `'…'`, `"…"` and `\` quoting; no shell expansion |
| `--http URL` | forward to this HTTP MCP server (Streamable HTTP or legacy SSE) |
| `--verbose` | debug logging |
| `--version` | print the version |
| `--help` | list the flags (`mcp-gateway help tunnel` too) |

Exactly one of `--stdio` and `--http` is required. Status lines go to stderr (`connecting to …`, `connected to …, serving …`, `disconnected (…); retrying in …`). The stdio server's own stderr passes through.

Behaviour:
- **Outbound only.** The client dials `wss://<gateway>/tunnel/connect`. Environment proxies (`HTTPS_PROXY`) are honoured for that connection. Nothing listens locally.
- **Reconnects** with exponential backoff and jitter (1s up to 1m), resetting after a successful connection.
- **Stops for good** (exit code 1) when the gateway rejects the token (wrong or revoked), when the tunnel is revoked while connected, when another client connects with the same token (the newer one wins), or when the stdio server exits.
- **Graceful shutdown** on SIGINT/SIGTERM (exit code 0): it closes the WebSocket, then the stdio server's stdin, then sends SIGTERM and finally SIGKILL.
- **`--http` stays on its target.** Every request goes to the target's scheme and host whatever path the gateway sends, so the gateway cannot make the client reach any other host. The path `/` maps to the target URL's path and query. Other paths, such as a legacy SSE server's `/messages?sessionId=…`, are kept. Proxies are not used for the target, and redirects are passed back untouched.

### The stdio bridge

`--stdio` turns the gateway's Streamable HTTP requests into JSON-RPC lines on the server's stdin, and its stdout lines back into HTTP responses. It is a JSON-RPC proxy, not a re-implementation of MCP, so tools, resources, prompts and completions all pass through unchanged. One process serves every gateway session:

- **Request ids** are rewritten to the bridge's own counter and restored on the way back, so concurrent sessions never collide.
- **Initialize once.** The first `initialize` is forwarded with client capabilities cleared, because the bridge cannot answer server-to-client requests. Its result is cached and returned to later sessions. `notifications/initialized` is forwarded once.
- **`server/discover`** (the 2026-07-28 stateless probe) is answered "method not found" locally, so clients fall back to the classic `initialize` handshake that stdio servers implement.
- **Server-to-client requests** (sampling, roots, elicitation) get a JSON-RPC error. `ping` is answered. Server notifications (progress, logging, list_changed) are dropped, because the gateway does not consume them yet.
- **Responses** are `application/json`. `GET` (the standalone SSE stream) returns 405. JSON-RPC batches return 400. A request body over 4 MiB returns 413. A stdout line over 16 MiB is skipped. A gateway-side cancellation becomes `notifications/cancelled` to the server. When the process exits, pending and later requests get 502 and the client stops.

## For the gateway (wiring)

Wired in `cmd/gateway/federation.go` through `connector.Wire` (see [federation-connector.md](federation-connector.md)): the handler is mounted at `/tunnel/connect` on the top-level mux, and the connector authorizes and dials `tunnel://` servers as below. What remains is the portal UI for tunnels (task 9dp13dgy) and the reverse proxy's WebSocket upgrade. The sketch:

```go
svc, _ := tunnel.NewService(tunnel.Options{
    Store:  tunnel.NewStore(st),   // *store.Store with the jobs pool (WithJobsURL)
    Limits: tunnel.Limits{},       // defaults below
    Log:    log,
})

mux.Handle(tunnel.ConnectPath, svc.Handler()) // "/tunnel/connect"

// portal (owner, WithUser under the hood)
tun, token, err := svc.CreateTunnel(ctx, userID, "laptop") // show token once
err = svc.Revoke(ctx, userID, tunnelID)                    // also drops the live connection
// listing: store.ListMCPTunnels (WithUser); admins: the admin_mcp_tunnels view

// federation connector, for a server whose URL is a tunnel URL
id, _, err := tunnel.ParseURL(server.URL)
if err := svc.Authorize(ctx, server.OwnerUserID, id); err != nil { /* refuse: ErrForbidden */ }
u, _ := tunnel.ClientURL(server.URL)              // http://<id>.tunnel.invalid/<path>
c, _ := client.New(client.Options{HTTPClient: svc.HTTPClient(guard.Client()), ...})
s, err := c.Connect(ctx, client.Endpoint{URL: u, Transport: client.TransportAuto})
var te *tunnel.Error
if errors.As(err, &te) && te.Class == tunnel.ClassOffline { /* "tunnel offline" to the user */ }
```

### API

| Symbol | Purpose |
|---|---|
| `NewService(Options) (*Service, error)` | `Store` required. `Limits`, `Log` and `Now` are optional |
| `(*Service).CreateTunnel(ctx, owner, name) (*store.MCPTunnel, token, error)` | `ErrInvalidName` unless the name is 1–100 printable characters |
| `(*Service).Revoke(ctx, owner, id) error` | `ErrForbidden` when the tunnel is not the owner's, unknown or already revoked |
| `(*Service).Authenticate(ctx, token)` | `ErrUnauthorized` for a malformed, unknown or revoked token |
| `(*Service).Authorize(ctx, serverOwnerID, tunnelID) error` | the tunnel is live and has the same owner, else `ErrForbidden` |
| `(*Service).Handler() http.Handler` | the `/tunnel/connect` endpoint |
| `(*Service).RoundTripper() http.RoundTripper` | serves tunnel URLs only, never dials |
| `(*Service).HTTPClient(base *http.Client) *http.Client` | a copy of `base` (or a zero client) with that transport. Redirects must stay in the same tunnel |
| `(*Service).Online(id) bool` | a live connection exists on this replica or, with the relay, a fresh holder on another |
| `(*Service).RelayEnabled() bool`, `(*Service).RelayHandler() http.Handler`, `RelayPath`, `RelayOptions`, `NewHolderStore` | the cross-replica relay (see *Multiple replicas*) |
| `URL(id, path)`, `ParseURL(raw)`, `ClientURL(raw)`, `IsTunnelURL(raw)` | tunnel URL helpers |
| `GenerateToken`, `ParseToken`, `HashToken`, `TokenScanPattern` | token format `mgt_<8 base62>_<43 base62>`, SHA-256 of the whole token stored |
| `NewStore(*store.Store) Store` | owner calls under `WithUser`, token lookup, re-check and touch under `WithJobs` |
| `NewAgent(AgentOptions)`, `(*Agent).Run(ctx)` | the client side (used by `internal/tunnelclient`, behind `mcp-gateway tunnel` and `mcp-gateway-tunnel`). `Run` returns `ErrRejected`, `ErrReplaced`, `ErrRevoked` or `ctx.Err()` |

### Tunnel URLs

The canonical form is `tunnel://<tunnel uuid>/<path>`, as stored in `mcp_servers.url`. `internal/federation/client` accepts only http(s), so `ClientURL` maps it to `http://<uuid>.tunnel.invalid/<path>`. `.invalid` is reserved and never resolves (RFC 6761). The tunnel transport accepts both forms. The federation client's origin guard keeps every request of a session on the same tunnel.

### netguard

Tunnel servers use `svc.HTTPClient(...)` **instead of** netguard's client. Its transport refuses every non-tunnel URL (`ClassNotTunnel`) and never opens a network connection. The only traffic is frames on the WebSocket that the user's client opened. netguard is therefore bypassed for tunnel URLs and nothing else. `TestFederationUsesOnlyTheGuard` still passes, because the package builds no `http.Client`/`Transport` literal.

### Limits and errors

| `Limits` field | Default | On breach |
|---|---|---|
| `MaxRequestBytes` | 4 MiB | `too_large` (request not sent) |
| `MaxResponseBytes` (non `text/event-stream` bodies) | 10 MiB | `too_large` on read, stream cancelled |
| `MaxBufferedBytes` (unread bytes per stream, SSE included) | 8 MiB | `too_large`, stream cancelled |
| `MaxStreams` (concurrent requests per tunnel) | 32 | `busy` |
| `ResponseHeaderTimeout` | 30s | `timeout` (`Timeout() == true`), cancel sent to the client |
| `HeartbeatInterval` | 30s | ping failure drops the connection |

Transport errors are `*tunnel.Error{Class, Reason}`, with these classes: `tunnel_offline` (no live connection on this replica and no usable holder elsewhere, or it dropped mid-request), `not_tunnel`, `too_large`, `timeout`, `busy` and `unreachable` (the client could not finish the response). Messages carry only the class and a short reason, never URLs, headers, bodies or tokens. Through the federation client they surface as its `*client.Error` (`unreachable` or `timeout`), and `errors.As(err, *tunnel.Error)` recovers the tunnel class. The tunnel client answers 502 when the local server is unreachable and 503 when it is busy. These are ordinary HTTP statuses, which the federation client classifies as `unreachable`.

## Wire protocol (v1)

1. The client sends `GET /tunnel/connect` with `Authorization: Bearer mgt_…` and a WebSocket upgrade with subprotocol `mcp-gateway-tunnel.v1`. A missing, malformed, unknown or revoked token gets **401** (`WWW-Authenticate: Bearer realm="mcp-gateway-tunnel"`, no reason given). The reason is logged; the token never is.
2. The gateway registers the connection as the tunnel's live one, replacing and closing (code 4001) any previous one, and touches `last_seen_at`. Every `HeartbeatInterval` it pings, re-reads the tunnel and touches it. If the tunnel was revoked, including by another replica, it closes with code 4003.
3. Messages are JSON text frames:

| Direction | Frame |
|---|---|
| gateway → client | `{"t":"req","id":N,"m":"POST","p":"/mcp?x=1","h":{…},"d":"<base64 body>"}` |
| gateway → client | `{"t":"cancel","id":N}` |
| client → gateway | `{"t":"head","id":N,"s":200,"h":{…}}` |
| client → gateway | `{"t":"data","id":N,"d":"<base64, ≤ 32 KiB>"}` (0..n) |
| client → gateway | `{"t":"end","id":N,"e":"<optional error>"}` |

The gateway assigns stream ids per connection. A request carries its whole (bounded) body. A response streams as `head`, `data*`, `end`, so SSE and Streamable HTTP responses flow as they are produced. Both sides drop hop-by-hop headers, `Host` and `Content-Length`. Frame size limits: 1 MiB read by the gateway, 32 MiB read by the client.

## Machine connections

An enrolled machine ([machines.md](machines.md), Brain decision `ldjix4y1`) opens **one** WebSocket for every tunnel linked to it instead of one per tunnel:

1. `GET /machine/v1/connect` with `Authorization: Bearer mgm_…` (a 10-minute machine access token; checked by `internal/machines`, 401 / 403 `revoked` at the handshake) and subprotocol `mcp-gateway-machine.v1`. The machines API hands the request to `(*Service).ServeMachine(w, r, machineID)`.
2. The connection becomes the live connection of every live tunnel of the machine (`mcp_tunnels.machine_id`); each is registered and holder-claimed like a legacy connection, so the relay works unchanged. A newer connection of the same machine closes the older with **4001**; revoking the machine (or its owner no longer active) closes it with **4003**.
3. Frames are the v1 frames above; `req` carries the tunnel id: `{"t":"req","id":N,"tid":"<tunnel id>",…}`. Stream ids are unique per connection, so `head`, `data`, `end` and `cancel` carry no tunnel id. On connect and whenever the set changes the gateway sends `{"t":"tunnels","ids":[…]}` (the client may ignore it). A request for a tunnel the client has no target for is answered 502.
4. The tunnel set follows the machine while connected: `SyncMachine` (called after the machine API created a tunnel on this replica) and a re-read every `Limits.MachineSyncInterval` (default 5 s, at most `HeartbeatInterval`) attach new tunnels and detach revoked ones without a reconnect; revoking one tunnel detaches only that tunnel. The same re-read notices a revocation through another replica. `DropMachine` closes the connection at once on this replica. Every `HeartbeatInterval` the gateway pings, touches the machine and its tunnels and re-checks the relay holders; if a newer connection of the machine holds a tunnel elsewhere, this connection closes with 4001.
5. Persistence: `tunnel.MachineStore` (`MachineTunnels`, `TouchMachine`; `tunnel.NewMachineStore(*store.Store)`, jobs role), set as `Options.Machines`; `connector.Wire` does it.

The client side is `tunnel.NewMachineAgent` (targets: tunnel id → `http.Handler`, built with `tunnel.NewHTTPForwarder` or `tunnel.StartStdio`, which the legacy client shares). The legacy `/tunnel/connect`, the `mgt_` tokens and wire format v1 are unchanged; a machine tunnel has no token hash, so `/tunnel/connect` can never match it.

## Multiple replicas (cross-replica relay)

Live connections are held **per replica, in process**. With several replicas behind a load balancer without sticky sessions, the WebSocket lands on one replica (the *holder*) and a tunnel request may arrive on another. The relay (Brain decision `efq0ncag` item 5) forwards such a request to the holder over an internal, authenticated HTTP hop, so tunnels work from every replica.

**Disabled unless all three are set** (`config.Config.RelayEnabled`); with none set nothing changes: no holder rows, `tunnel_offline` on a replica without the connection, `Online` is local only. Setting only some of them refuses to start.

| Env | Example | Meaning |
|---|---|---|
| `GATEWAY_RELAY_LISTEN_ADDR` | `:18081` | internal relay listener; must differ from `GATEWAY_LISTEN_ADDR`. Never on the Service/Ingress |
| `GATEWAY_RELAY_ADVERTISE_ADDR` | `http://$(POD_IP):18081` | this replica's relay base URL as peers reach it (scheme and host only); `POD_IP` from the downward API |
| `GATEWAY_RELAY_SECRET` | 32+ random bytes | HMAC key, identical on every replica; never logged or echoed |

How it works:

1. **Holder registry** (`mcp_tunnel_holders`, migration 00026, `gateway_jobs` only; the request-path role has no access). On connect the replica upserts `(tunnel_id, holder = advertise address, epoch = nextval(global sequence))` and touches `last_seen_at`. On disconnect it deletes the row only if it still has its epoch. Every heartbeat it re-claims a missing row, and if the row shows a **newer epoch** (the client reconnected to another replica) it closes its own connection with 4001, like an in-process replacement.
2. **Lookup.** The tunnel transport uses the local connection when there is one. Otherwise it reads the holder row; it is `tunnel_offline` when there is none, the tunnel is revoked, `last_seen_at` is older than 3 × `HeartbeatInterval` (a crashed replica's row expires on its own), the address is not a plain `http(s)://host[:port]`, or the row names this replica itself.
3. **Forward.** `POST <holder>/tunnel-relay/v1/roundtrip` with the tunnel id, epoch, unix time, a random nonce, the request head (method, path+query, cleaned headers; base64url JSON) and `X-Mgw-Relay-Signature = HMAC-SHA256(secret, "mcp-gateway-relay.v1\n" id \n epoch \n time \n nonce \n head \n sha256(body))`. The body is the request body, bounded by `MaxRequestBytes` (4 MiB) before it is sent.
4. **Serve (holder).** It checks the signature in constant time, the clock skew (±30 s), that the nonce is unused (replay cache for the skew window, bounded at 65 536 entries → `busy`), the body bound (413 `too_large`), and that it holds **that tunnel with that epoch** (409 `not_holder` otherwise). It then sends the request down its WebSocket and answers 200 with the response head in `X-Mgw-Relay-Head`, streams the body as it arrives (SSE included), and ends with the trailer `X-Mgw-Relay-End: ok` or the error class. Refusals carry `X-Mgw-Relay-Error` (`unauthorized`, `not_holder`, `bad_request` or a tunnel class).
5. **Errors** map to the existing `*tunnel.Error` classes: the holder's `timeout`, `too_large`, `busy`, `unreachable` pass through; an unreachable or rejecting peer (wrong secret, clock) is `tunnel_offline` (reasons `relay_unreachable`, `relay_rejected`, logged as an operator error without URLs or secrets); `not_holder` (handover race) retries the lookup once, then `tunnel_offline`. The sender bounds the wait for the head at `ResponseHeaderTimeout` + 5 s, so the holder's own timeout normally wins. Response bodies keep `MaxResponseBytes` (10 MiB, non-SSE) on the sending side; a missing end trailer is `unreachable` (`relay_truncated`).
6. **Revocation** across replicas: the revoking replica drops its own connection at once; every replica's lookup sees `revoked` immediately; the holder closes the WebSocket (4003) at its next heartbeat.
7. `(*Service).Online` is true for a local connection or, relay on, a fresh holder elsewhere (one registry read), so the portal and admin pages show the tunnel online on every replica. Readiness is unaffected.

Wiring: `connector.WireOptions.TunnelRelay` (`tunnel.RelayOptions`; holders default to `tunnel.NewHolderStore`), and `cmd/gateway/relay.go` serves `(*Service).RelayHandler()` (only `RelayPath`, 404 elsewhere) on its own `server.Server`, with a dedicated proxy-less HTTP client for peers. Metric: `tunnel_relay_requests_total{side="forward"|"serve", result}`; results are fixed words (`ok`, `miss`, `stale`, `revoked`, `self`, `bad_holder`, `lookup_error`, `unreachable_peer`, `unauthorized`, `not_holder`, `bad_request`, a tunnel class, …), never ids or addresses. Logs carry the tunnel id and epoch, never the secret or a peer URL in errors.

Deployment (Helm: `tunnelRelay.enabled=true`, `tunnelRelay.existingSecret`, `tunnelRelay.secretKey` (default `relay-secret`), `tunnelRelay.port` (default 18081)) sets the three variables plus `POD_IP` from `status.podIP`, adds the `tunnel-relay` containerPort (on no Service), and adds NetworkPolicy ingress and egress rules on that port limited to the release's own gateway pods. See [deploy.md](deploy.md).

## Mounting caveats

- Mount `svc.Handler()` **outside** the gateway's user authentication. The tunnel token is the credential.
- It must not be wrapped in middleware that hides `http.Hijacker`, buffers responses or applies a whole-request timeout. A WebSocket lives for hours. The gateway's `http.Server` only sets `ReadHeaderTimeout`, which is fine. The reverse proxy (Traefik) must allow WebSocket upgrades on `/tunnel/connect`.
- Browsers cannot set `Authorization` on a WebSocket, so the endpoint is not reachable cross-site. The library's origin check is left on.

## Tests

- Relay: `go test -race ./internal/federation/tunnel/` (`relay_test.go`: two Services over one store with their own relay listeners: round trip and SSE streaming through the non-holder, relay off = old behaviour and no holder rows, handover, newer connection elsewhere closes the old one with `ErrReplaced`, revocation across replicas, stale/self/wrong-epoch/bad-address holders, unreachable holder, mismatched secret, error classes (timeout, response and request bounds, status pass-through), the endpoint's checks (missing/wrong signature, tampered body, changed epoch, skew both ways, replay, not holder, other tunnel, 413, method and path), option validation); `internal/config/relay_test.go`; `TestIntegrationMCPTunnelHolders` (store, jobs-only grant); `TestIntegrationTunnelRelayAcrossReplicas` / `TestIntegrationTunnelRelayDisabled` (`cmd/gateway`: two in-process gateways wired by `newFederation` over one database, WebSocket on A and the tool call through B's `/mcp`, handover to B, relay path not on the public mux, revocation on both); `TestSecurityFedTunnelRelay` (public handler never serves the relay even for a signed request; bad, missing, stale, replayed, wrong-epoch refused); `TestTunnelRelay` (Helm).

- `go test -race ./cmd/mcp-gateway/` covers subcommand dispatch (help, version, unknown → exit 2) and that `mcp-gateway tunnel --help` lists every flag; `tests/test-install-script.sh` covers `install.sh` (OS/arch mapping, `$VERSION`, unsupported platforms, checksum mismatch and missing entry, shellcheck).

- `go test -race ./internal/federation/tunnel/...` covers: tokens; create, revoke, authenticate and owner-only authorize; 401 for missing, malformed, unknown, revoked and wrong-scheme tokens (the agent stops with `ErrRejected`); request and response round trip in both URL forms; streaming before the handler ends; offline and non-tunnel classes; a replacement connection (the old agent gets `ErrReplaced`); revoke and heartbeat revocation; disconnect fails in-flight requests and cleans up; request and response size bounds; header timeout cancels the local request; the max-streams bound and slot release; the token never appears in gateway or agent logs; URL parsing.
- `go test -race ./internal/tunnelclient/` (the client shared by `cmd/mcp-gateway` and `cmd/mcp-gateway-tunnel`) covers: flag and env parsing (the token never appears in errors), command splitting, the forwarder staying on its target, and these end-to-end runs with the real gateway handler, the command and `internal/federation/client`:
  - an HTTP go-sdk server on localhost;
  - a **stdio go-sdk server started by `--stdio`** (the test binary re-executed), with two sessions listing and calling tools;
  - the bridge over in-memory pipes, with 4 concurrent sessions and exactly one `initialize` reaching the server;
  - bridge protocol edge cases;
  - offline tunnel → `*tunnel.Error` `tunnel_offline` through the client.
- `make test-integration` (`TestIntegrationTunnelStoreAndConnect`, own database `gateway_tunnel_test`): the stored hash, `WithJobs` lookup, owner-only `Authorize` and `Revoke` under row-level security, `last_seen_at`, and a live connection cut off by revoke.
