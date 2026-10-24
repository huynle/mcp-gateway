# Upstream MCP client (`internal/federation/client`)

The gateway's client for **user-added MCP servers**: it connects to any remote MCP server over Streamable HTTP or legacy HTTP+SSE, always through the SSRF-safe [`netguard`](netguard.md) HTTP stack, and returns bounded results and classified errors. It knows nothing about users, the store or credentials. The auth task plugs credentials in through `Authorizer`, and the federation connector maps tools and errors into the gateway pipeline. Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz`, `yd6qrbqc`, task `oqwn4g6l`.

## API

```go
guard := netguard.New(netguard.Options{ /* allow list, metrics, log */ })

c, err := client.New(client.Options{
    HTTPClient:     guard.Client(), // required; must be netguard's
    Authorizer:     auth,           // nil / client.NoAuth{} = no credentials
    Timeout:        30 * time.Second, // per operation (default 30s)
    MaxResultBytes: 4 << 20,        // per JSON-RPC message (default 4 MiB)
    MaxListItems:   1000,           // per list operation (default 1000)
    ClientName:     "mcp-gateway",  // default
    ClientVersion:  version,
    Log:            log,            // default: discard
    OnCall:         func(ci client.CallInfo) { /* latency metric by ci.Label, ci.Op, ci.Class */ },
})

s, err := c.Connect(ctx, client.Endpoint{
    URL:       "https://mcp.example.com/mcp",
    Transport: client.TransportAuto, // "" = auto; or TransportStreamableHTTP / TransportSSE
    Headers:   map[string]string{"X-Tenant": "acme"}, // static, non-secret
    Label:     serverID,             // echoed in CallInfo only
})
defer s.Close()

s.ServerInfo()      // *mcp.Implementation
s.Capabilities()    // *mcp.ServerCapabilities
s.ProtocolVersion() // negotiated version
s.Instructions()    // server instructions
s.Transport()       // transport actually in use

tools, err := s.ListTools(ctx)              // all pages, capped
res, err := s.CallTool(ctx, "name", args)   // res.IsError = tool ran and failed (not a Go error)
rs, err := s.ListResources(ctx)
ts, err := s.ListResourceTemplates(ctx)
rr, err := s.ReadResource(ctx, uri)
ps, err := s.ListPrompts(ctx)
pr, err := s.GetPrompt(ctx, "name", map[string]string{...})
```

Types for tools, resources, prompts and results are the go-sdk's `mcp.*` types. A `Session` is safe for concurrent use (the SDK session is).

### Authorizer: where the auth task plugs in

```go
type Authorizer interface {
    Authorize(ctx context.Context, req *http.Request) error
}
```

`Authorize` is called on **every** HTTP request of a session: the handshake, each operation, the legacy SSE GET stream and its message POSTs. It runs after `Endpoint.Headers` are applied, so it may set `Authorization` or any other header. It receives a clone of the request, already pinned to the endpoint's origin. The auth task supplies implementations: bearer, API key, custom headers, and OAuth with refresh, per user or shared.

- An `Authorize` error aborts the request as `ClassAuthRequired`, `Reason "authorizer"` (e.g. no token for this user yet).
- An HTTP 401 becomes `ClassAuthRequired` with `Status` and the `WWWAuthenticate` challenge (capped at 4 KiB). OAuth discovery starts from that challenge (`resource_metadata=...`). The value comes from the upstream server, so parse it and never display it verbatim.

### Credentials never leak

- Every request is built by the MCP SDK from scratch. Nothing from the inbound gateway request (its `Authorization`, cookies, `Mcp-Session-Id`) is forwarded, only `Endpoint.Headers` plus what the `Authorizer` adds.
- Every request must stay on the endpoint's **origin** (scheme, host, port). A redirect, or a legacy SSE `endpoint` event pointing elsewhere, is refused before `Authorize` runs (`ClassBlocked`, `Reason "cross_origin"`), so credentials only ever go to the configured server. netguard additionally re-validates each redirect hop and refuses https→http.
- `Endpoint.Headers` may not set transport-owned headers (`Host`, `Content-Type`, `Accept`, `Accept-Encoding`, `Content-Length`, `Last-Event-Id`, `Cache-Control`, any `Mcp-*`), hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Te`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authenticate`) or **credentials** (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`), compared case-insensitively. Credentials belong in the `Authorizer` (sealed per user and URL); a static header would send one plain-text value on every user's calls. The servers portal refuses them too; the client check is defence in depth for a `header_config` written any other way (Brain task `68ss4tpc`). Names must be RFC 9110 tokens and values must contain no control characters. Violations return `ErrInvalidEndpoint` from `Connect` (the message never echoes the URL).
- The client declares **no client capabilities** in `initialize` (`capabilities: {}`): the gateway serves no roots, sampling or elicitation to upstreams, so the go-sdk's default `roots` capability is switched off (`ClientOptions.Capabilities = &mcp.ClientCapabilities{}`), and sampling or elicitation requests from an upstream are refused.

## Transport fallback heuristic

`TransportAuto` follows the MCP specification's backwards-compatibility procedure:

1. POST `initialize` with the **Streamable HTTP** transport. If the handshake succeeds, use it.
2. If that POST was answered with **HTTP 4xx other than 401, 403, 407, 408, 429**, typically 404 or 405 from a legacy server with no POST route, or 400 from one that rejects the body, reconnect with **legacy HTTP+SSE** (GET the URL, wait for the `endpoint` event, POST messages there).
3. Anything else is returned as is, with **no fallback**: success, 401/403 (credentials), 407/408/429 (proxy, timing, rate), a 4xx whose body is JSON-RPC error `-32022` (unsupported protocol version: the server speaks Streamable HTTP, so a fallback would only replace the real error with a confusing SSE failure), 5xx, network errors, timeouts, netguard refusals, oversize responses, and non-HTTP protocol errors such as malformed JSON on a 200. Falling back on those would hide the real failure, and on 401 it would send credentials over a second transport for nothing.

The fallback is logged at info (`host`, `status`). `Session.Transport()` and `CallInfo.Transport` report the transport actually used. Explicit `TransportStreamableHTTP` / `TransportSSE` never fall back.

The streamable transport runs with `DisableStandaloneSSE` (no server-initiated GET stream: the gateway does not consume server notifications yet) and `MaxRetries: -1`.

### Protocol version

The go-sdk (v1.8.0) negotiates the version. It first tries the stateless `server/discover` (SEP-2575, protocol 2026-07-28) and falls back to `initialize` (asking `2025-11-25`) when the server does not support it, so older servers get the version they answer with (e.g. `2025-06-18`). go-sdk servers accept 2026-07-28 only in stateless mode; the default (stateful) `StreamableHTTPHandler` negotiates `2025-11-25`. `ProtocolVersion()` reports the result.

**Caller contexts are isolated from the SDK.** `Connect` and every operation hide context values keyed by go-sdk types before handing the context to the SDK (`withoutSDKValues`, `sdkctx.go`); other values, deadlines and cancellation pass through. The gateway calls the client from inside its own go-sdk server handler (`/mcp`), and the SDK stores the inbound `Mcp-Protocol-Version` in the request context under the same key its client transport falls back to when setting that header. Without the isolation, a downstream client speaking 2026-07-28 made the gateway send `Mcp-Protocol-Version: 2026-07-28` on an `initialize` asking `2025-11-25`, and stateful upstreams rejected it with HTTP 400 `-32022` (Brain quirk `91d7smmg`, task `36hcuxk2`).

## Bounds

| Bound | Default | On breach |
|---|---|---|
| `Timeout`: each operation (handshake, list incl. all pages, read, get) | 30s | `ClassTimeout` |
| `CallTimeout`: each `tools/call` (`GATEWAY_FEDERATION_CALL_TIMEOUT` in the gateway) | `Timeout` | `ClassTimeout` |
| `MaxResultBytes`: one JSON response body, or one SSE event | 4 MiB | `ClassTooLarge` |
| `MaxListItems`: items across all pages of one list | 1000 | `ClassTooLarge`, `Reason "list_items"` |
| pages per list (servers sending empty pages) | `MaxListItems` | `ClassTooLarge`, `Reason "list_pages"` |
| repeated cursor | - | `ClassProtocol`, `Reason "cursor_loop"` |

The netguard `http.Client` timeout is replaced by these per-operation deadlines, because a legacy SSE session keeps one GET stream open for its whole life. A `CallTimeout` above netguard's (or the tunnel's) response header timeout is still cut there by an upstream that answers with one JSON body: raise `netguard.Options.ResponseHeaderTimeout` (and the tunnel's `Limits.ResponseHeaderTimeout`) to match, as `connector.Wire` does. `Session.Close` cancels every in-flight request of the session. netguard's own `MaxResponseBytes` still applies underneath; set it at least as high as `MaxResultBytes`.

## Errors

Upstream failures are `*client.Error`. Branch on `Class`:

| Class | Meaning |
|---|---|
| `unreachable` | dial/TLS/connection failure, HTTP 5xx, 408, 429 |
| `blocked` | netguard refused the destination (`Reason` = netguard reason, e.g. `loopback`, `private`, `metadata`) or a request left the origin (`cross_origin`) |
| `auth_required` | HTTP 401 (`Status`, `WWWAuthenticate`) or the Authorizer failed (`Reason "authorizer"`) |
| `forbidden` | HTTP 403 (`WWWAuthenticate` kept too, e.g. `insufficient_scope`) |
| `protocol_error` | not MCP: malformed JSON, unexpected status or content type, JSON-RPC error outside `tools/call`, broken pagination. A non-2xx answered with a JSON-RPC error body keeps both `Status` and `RPCCode` (e.g. 400 / `-32022`) |
| `too_large` | a response or list exceeded its bound |
| `timeout` | the operation's deadline passed or its context was cancelled |
| `tool_error` | `tools/call` answered with a JSON-RPC error (unknown tool, bad arguments; `RPCCode`) |

A tool that runs and fails is **not** an error: it is a `CallToolResult` with `IsError: true`.

`Error()` contains only the operation, class, HTTP status, JSON-RPC code and reason, for example `federation client: tools/list: auth_required (HTTP 401)`. It never includes upstream bodies or messages, URLs, or credentials, so it is safe to show to users and models. The cause is reachable through `errors.Unwrap`/`errors.As` (e.g. the `*netguard.BlockedError`), but it may contain the URL: log it only through `observability.RedactError`.

Classification uses facts recorded at the HTTP layer (status, challenge, transport error, refusal, size breach), not SDK error text. Precedence: own refusals (netguard, cross-origin, authorizer) > 401/403 > too large > deadline > network error > other HTTP status > JSON-RPC error > protocol.

`Connect` with a malformed `Endpoint` (bad scheme, empty host, reserved or invalid header, unknown transport) returns an error wrapping `ErrInvalidEndpoint`. That is a configuration error, not an `*Error`.

## Observability

`Options.OnCall` receives one `CallInfo{Label, Op, Transport, Class, Duration}` per finished operation, including a failed `connect`, with no URLs, arguments or results. The connector turns it into the per-server latency metric. `Log` gets only the host and status on fallback, plus SDK debug output.

## Tests

`go test -race ./internal/federation/...` runs everything against in-process go-sdk servers through the real netguard (127.0.0.1 allow-listed):

- streamable end to end, explicit SSE, auto fallback against a real legacy go-sdk SSE server and on forced 404/405, auto staying streamable, legacy stream outliving the handshake timeout
- Authorizer on every request; 401 → `auth_required` with the challenge and no fallback; 403; Authorizer failure; NoAuth adds nothing
- pagination; hostile servers: over-cap lists, empty-page and cursor loops, huge results (JSON and SSE), slow call and slow handshake → `timeout`, malformed JSON → `protocol_error`, JSON-RPC errors
- netguard blocking private, loopback and metadata URLs; cross-origin redirect and SSE endpoint; unreachable; 5xx
- `OnCall` reporting; protocol version negotiation
- endpoint static headers: credential, hop-by-hop and transport headers refused in any case; `initialize` declares no client capabilities (`endpoint_test.go`)
- stateful go-sdk upstream (default options): two sequential sessions with list + call, also when connecting from inside a go-sdk server handler whose downstream speaks 2026-07-28 (`stateful_test.go`); a stateless upstream still negotiates 2026-07-28 there; no SSE fallback on 400 `-32022`

`test/e2e` `TestE2EPluginsStatefulUpstream` covers the same through the whole gateway: review, then two `tools/call` via `/mcp` against a stateful upstream, checking each upstream `initialize` header matches its body.

`internal/netguard`'s `TestFederationUsesOnlyTheGuard` (rawhttpcheck) fails if anything under `internal/federation` builds its own `http.Client`/`Transport`.
