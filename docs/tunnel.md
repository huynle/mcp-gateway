# MCP tunnel (`internal/federation/tunnel`, `cmd/mcp-gateway-tunnel`)

The tunnel lets a user connect a **stdio MCP server** or an MCP server on a **private network** to the gateway. The gateway never starts programs and never dials into the user's network. Instead, the user runs `mcp-gateway-tunnel` next to the server. It connects **out** to the gateway over a WebSocket, and the gateway sends the MCP traffic back down that connection. Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz` (tunnel-only stdio), `17iv8p3b` (schema), `dzjepj6k` (tunnel transport), `ejjvsv5y` (stdio bridge); task `kwllocck`.

```
harness ──/mcp──▶ gateway ── federation client ── tunnel transport ═══ WebSocket (outbound from the user) ═══▶ mcp-gateway-tunnel ──▶ stdio server (spawned locally)
                                                   (tunnel:// URLs only)                                                     └──▶ http://localhost:PORT/mcp
```

## For users

1. In the portal, create a tunnel. The token (`mgt_…`) is shown **once**. Only its SHA-256 is stored.
2. Add a server with the URL `tunnel://<tunnel id>` (or `tunnel://<tunnel id>/mcp`; see *Paths* below).
3. On the machine with the server, run one of:

```sh
export MCP_GATEWAY_TUNNEL_TOKEN=mgt_…            # preferred over --token (visible in ps)

# a stdio server: the tunnel client starts it and bridges it
mcp-gateway-tunnel --gateway https://gateway.huynle.com --stdio "npx -y @modelcontextprotocol/server-everything"

# a private HTTP server
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
| `(*Service).Online(id) bool` | a live connection exists **on this replica** |
| `URL(id, path)`, `ParseURL(raw)`, `ClientURL(raw)`, `IsTunnelURL(raw)` | tunnel URL helpers |
| `GenerateToken`, `ParseToken`, `HashToken`, `TokenScanPattern` | token format `mgt_<8 base62>_<43 base62>`, SHA-256 of the whole token stored |
| `NewStore(*store.Store) Store` | owner calls under `WithUser`, token lookup, re-check and touch under `WithJobs` |
| `NewAgent(AgentOptions)`, `(*Agent).Run(ctx)` | the client side (used by `cmd/mcp-gateway-tunnel`). `Run` returns `ErrRejected`, `ErrReplaced`, `ErrRevoked` or `ctx.Err()` |

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

Transport errors are `*tunnel.Error{Class, Reason}`, with these classes: `tunnel_offline` (no live connection on this replica, or it dropped mid-request), `not_tunnel`, `too_large`, `timeout`, `busy` and `unreachable` (the client could not finish the response). Messages carry only the class and a short reason, never URLs, headers, bodies or tokens. Through the federation client they surface as its `*client.Error` (`unreachable` or `timeout`), and `errors.As(err, *tunnel.Error)` recovers the tunnel class. The tunnel client answers 502 when the local server is unreachable and 503 when it is busy. These are ordinary HTTP statuses, which the federation client classifies as `unreachable`.

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

## Multi-replica note

Live connections are held **per replica, in process**. A tunnel's calls must be served by the replica that holds its connection. For the single-instance amos deploy this is always true. With several replicas, a request on another replica sees `tunnel_offline`, so sticky routing by tunnel ID (or a broker) is needed before tunnels work across replicas. Revocation works across replicas within one heartbeat interval.

## Mounting caveats

- Mount `svc.Handler()` **outside** the gateway's user authentication. The tunnel token is the credential.
- It must not be wrapped in middleware that hides `http.Hijacker`, buffers responses or applies a whole-request timeout. A WebSocket lives for hours. The gateway's `http.Server` only sets `ReadHeaderTimeout`, which is fine. The reverse proxy (Traefik) must allow WebSocket upgrades on `/tunnel/connect`.
- Browsers cannot set `Authorization` on a WebSocket, so the endpoint is not reachable cross-site. The library's origin check is left on.

## Tests

- `go test -race ./internal/federation/tunnel/...` covers: tokens; create, revoke, authenticate and owner-only authorize; 401 for missing, malformed, unknown, revoked and wrong-scheme tokens (the agent stops with `ErrRejected`); request and response round trip in both URL forms; streaming before the handler ends; offline and non-tunnel classes; a replacement connection (the old agent gets `ErrReplaced`); revoke and heartbeat revocation; disconnect fails in-flight requests and cleans up; request and response size bounds; header timeout cancels the local request; the max-streams bound and slot release; the token never appears in gateway or agent logs; URL parsing.
- `go test -race ./cmd/mcp-gateway-tunnel/` covers: flag and env parsing (the token never appears in errors), command splitting, the forwarder staying on its target, and these end-to-end runs with the real gateway handler, the command and `internal/federation/client`:
  - an HTTP go-sdk server on localhost;
  - a **stdio go-sdk server started by `--stdio`** (the test binary re-executed), with two sessions listing and calling tools;
  - the bridge over in-memory pipes, with 4 concurrent sessions and exactly one `initialize` reaching the server;
  - bridge protocol edge cases;
  - offline tunnel → `*tunnel.Error` `tunnel_offline` through the client.
- `make test-integration` (`TestIntegrationTunnelStoreAndConnect`, own database `gateway_tunnel_test`): the stored hash, `WithJobs` lookup, owner-only `Authorize` and `Revoke` under row-level security, `last_seen_at`, and a live connection cut off by revoke.
