# Federation connector (`internal/federation/connector`)

User-added MCP servers' tools in the gateway pipeline: **visible per user, policed, approved, ledgered and audited** like built-in tools. This package ties together [netguard](netguard.md), the [federation client](federation-client.md), [upstream auth](federation-auth.md), [snapshots](federation-snapshots.md) and the [tunnel](tunnel.md), and `cmd/gateway/federation.go` wires it. Design: Brain plan `0omkv2e1` (step 4), decisions `yhd5kcaz`, `17iv8p3b`, `mrvsu07m`; task `fybs78bs`.

```
harness ─/mcp─▶ authenticate ▸ audit ▸ resolve ▸ strip ▸ account ▸ scope ▸ policy ▸ ledger ▸ ratelimit ▸ dispatch ─▶ Manager.call
                              (Decider wrapper: server visibility)   (anchor account)  (owner layer / roles; confirm → approval)
Manager.call ─▶ snapshot.Allowed (as caller) ▸ auth.ForUser ▸ netguard client | tunnel transport ▸ client Connect + CallTool (auth.Reauth) ─▶ upstream
```

## Tools in the registry

- A server's tools are registered as a **server app** named after the server: `<server>.<tool>` (`connectors.Registry.AddServerTools`, atomic per server; built-in and server apps never share a name, `ErrAppTaken`).
- Only **enabled** tools of the **approved** snapshot of an **active** server are registered, with the **pinned** input schema (a tool without one accepts only `{}`; a schema that is not a JSON object schema is skipped).
- Upstream names are sanitized to `[a-z0-9_-]`: camelCase becomes snake_case, other characters `_`, at most 64 characters. Tools whose names collide after sanitizing are **all** skipped (logged as `federation.tools_skipped`).
- Description: `[<server>] ` + the upstream description run through `snapshot.DisplayDescription` (control, bidi and zero-width characters stripped, capped).
- Kind = the review's kind. Writes declare `Reconcile: none` (an upstream call cannot be checked afterwards, so an unknown outcome becomes `unresolved` and the user is asked to check); no result IDs are kept. Resource identity: `{"server": "<name>"}`, so policy conditions and audit rows can name the server.

### Reload: the hook

| When | Call |
|---|---|
| startup | `Federation.Start(ctx)`: `Manager.Load` + `Manager.Run` (reload every minute, for other replicas) |
| **after any change** to a server (create, edit, rename, publish, unpublish, disable, delete), its snapshot review (approve, change decisions) or its credentials | **`Manager.ServerChanged(ctx, serverID)`** |

`ServerChanged` reloads every server, drops the visibility cache and invalidates the compiled policy (owner layer). The servers portal (task `9dp13dgy`) and admin pages **must** call it; otherwise changes show up only after the periodic reload.

## Reserved names

`ValidateServerName` refuses names that are not `^[a-z0-9_-]{1,63}$` (`ErrInvalidServerName`) and the built-in app names (`ErrReservedServerName`):

`atlassian calendar confluence contacts docs drive fake github gmail google jira mcp microsoft sheets slack tasks`

(`mcp` is the anchor vendor, below.) `Manager.CreateServer` / `UpdateServer` validate before writing, so the portal should create and edit servers through them. The loader also skips servers with a reserved name that already exist in the database.

## Visibility

A federated tool is visible (tools/list, resolve and the policy stage) only when **both** hold:

1. the user may use the server: owner of a private server, or holder of a role it is published to (`store.ListVisibleMCPServers` under the user's scope, the source of truth; cached per user for 10 s, dropped by `ServerChanged`); and
2. the policy lists the tool.

`Manager.Decider(policySvc)` wraps the policy so both apply everywhere: for a server the user may not use, `Visible` is false and `Decide` answers `hidden` (the call gets the same answer as an unknown tool) without consulting the policy. Each call checks visibility again through row-level security (`snapshot.Allowed` as the caller).

### Policy defaults

| Server | Default |
|---|---|
| **private** | **implicit owner layer** (`policy.OwnerGrant`, compiled into the Cedar set): the owner may list and call all its tools; **reads allow, writes confirm**. Token narrowing (read-only, allow-list), user restrictions and role denials still apply; a role `allow` cannot lift the write confirmation; the admin role gets nothing from it. |
| **published** | **hidden** for every role until an admin adds rules for `<server>.*` or individual tools in the role editor (the editor lists federated tools because it reads the registry). The owner layer no longer applies once a server is published: the owner too needs a role that grants the tools. |

## Accounts (anchors)

Approvals and ledger operations reference `connections(id, user_id)`, so every federated call runs against an **anchor connection**: one row per (user, server) under the disabled vendor app `mcp/federation` (vendor `mcp`, added by migration 00015), `external_account_id = mcp-server:<server id>`, display name = server name. It holds no token. Credentials stay in the federation tables.

| Server credential mode / auth kind | Account | Label |
|---|---|---|
| `per_user` + oauth / api_key / bearer / headers | only when the user has a credential row (not revoked); a row that needs reconnecting still yields it so the call can say "reconnect" | `personal` |
| `per_user` + `none`, or `shared` | always (the synthetic shared account) | `company` |

Without an account the account stage answers `no_account` (connect first). The `/connections` page lists enabled vendor apps only, so anchors do not appear there. The connections keep-alive job logs a daily warning per anchor (no token to refresh), as it does for fake accounts.

## Calls and errors

The handler: server still active → `snapshot.Allowed` as the caller (in the approved snapshot, enabled, args valid against the pinned schema) → a tool listed as a read that the review now marks a write is refused and the registry reloaded → `auth.ForUser` (per_user: the caller's connection; shared: the server's secret; none) → endpoint (netguard's client, or for `tunnel://` URLs `tunnel.Authorize(server owner, tunnel)` + the tunnel transport; `header_config.static` as headers) → `Connect` + `CallTool` under `auth.Reauth` → the upstream `CallToolResult` passed through whole (content, structuredContent, isError; bounded by the client).

**Gateway credentials are never forwarded**: the client builds every upstream request from the endpoint and the Authorizer (tests check with a capturing upstream and a tunnel-side capture).

| Class | Kind | Meaning |
|---|---|---|
| `tool_not_found` | JSON-RPC (same as unknown tool) | server gone, disabled, or not visible to the caller |
| `args_invalid` | JSON-RPC `-32602` | arguments do not match the pinned schema (never echoed) |
| `tool_disabled`, `tool_not_reviewed`, `tool_changed` | JSON-RPC `-32030`, audited as denials | the review does not allow the call (`tool_changed`: re-reviewed as a write since listed; list again) |
| `auth_required`, `needs_reconnect` | JSON-RPC `-32031` | connect / reconnect on the portal: the message carries `<BASE_URL>/servers/<id>` |
| `server_not_configured`, `shared_credential_rejected` | JSON-RPC `-32031` | ask the server's owner |
| `tunnel_offline`, `tunnel_unavailable` | tool error (isError) | start `mcp-gateway-tunnel` / the tunnel is revoked or not the owner's |
| `upstream_unreachable`, `upstream_timeout`, `upstream_protocol`, `upstream_too_large`, `upstream_forbidden`, `upstream_blocked`, `upstream_tool_error`, `upstream_error` | tool error (isError) | class-level; never upstream text or URLs |

Upstream failures implement `mcp.ClassedError`, so the audit row and a failed ledger operation record the class. A **write** that fails *inside* `tools/call` with a timeout, an unreachable server, a protocol error, an oversize answer or a tunnel dropping mid-call is an **unknown outcome** (`connectors.ErrOutcomeUnknown`) and the message tells the user to check before retrying. A tool that ran and reported an error (`isError: true`) is passed through as a result; the ledger records the write as succeeded, because the call completed.

## Resources and prompts

The gateway's own `/mcp` also serves the **resources, resource templates and prompts** of user-added servers (task `isdrqc6a`, plan `0omkv2e1` §3), through `Manager.ResourceProvider()` (`mcp.Options.Resources`; `cmd/gateway/federation_resources.go`). `/mcp` then advertises `resources` (no `subscribe`, no `listChanged`) and `prompts` (no `listChanged`); without a federation it advertises neither.

### Names and URIs

| Upstream | On the gateway |
|---|---|
| resource `notes://readme` of server `notes` | `mcpgw://notes/notes://readme` |
| template `notes://note/{id}` | `mcpgw://notes/notes://note/{id}` |
| prompt `summarize` | `notes.summarize` |

A gateway resource URI is `mcpgw://<server>/` followed by the upstream URI **verbatim** (no escaping): the server is the URI's authority and the mapping is a plain prefix, so it reverses exactly for any upstream URI (any scheme, query, fragment or characters; `connector.GatewayResourceURI` / `ParseGatewayResourceURI`). The prefix holds no template expressions, so the same prefix rewrites a template and a client filling in the gateway template gets the gateway URI of what the upstream template gives for the same values. Read contents carry gateway URIs too. Prompt names split at the first `.` (server names have none). Names are `<server>.<upstream name>`; **titles and descriptions start with `[<server>] `** (provenance) and are cleaned like tool descriptions (`snapshot.Display*`). Items whose URI, template or prompt name contains control or format characters (bidi, zero-width) are not listed.

### Visibility and checks

- **Lists** are the union, over the servers the caller may use (the same rule as their tools: owner of a private server, or a role it is published to; a narrowed token must name the server in its apps), of each server's **approved snapshot** as of the last load, never a live listing. Sorted by URI / name, paged with an opaque cursor (100 per page), `cacheScope: private`.
- **`resources/read`**: the URI must map back to a loaded server the caller may use, still active under that name, and the upstream URI must be a resource of the approved snapshot (read as the caller: RLS) or match one of its templates (RFC 6570, the go-sdk's matcher). Then it goes upstream **live** over the tool-call path: `auth.ForUser` (per_user / shared / none), netguard or the owner's tunnel, `auth.Reauth`, bounded by the federation client (timeout, 4 MiB per message). Text and blob contents pass through with their MIME types.
- **`prompts/get`**: the prompt must be in the approved snapshot; arguments pass through as given; then like a read.
- **Policy is server-level only for now**: anyone who may use the server may list and read all of its approved resources and prompts, including on published servers (no role rule is needed, unlike tools). Per-resource / per-prompt rules (Cedar actions, review toggles) are a follow-up.

### Errors and audit

| Answer | When |
|---|---|
| `-32602` `Resource not found` (`data.uri`) / `unknown prompt "<name>"` | not a gateway URI, no such server, a server the caller may not use, disabled, not in the approved snapshot. The same bytes for hidden and unknown. |
| `-32031` `auth_required`, `needs_reconnect`, `server_not_configured`, `shared_credential_rejected` | as for tools (the message carries `<BASE_URL>/servers/<id>`) |
| `-32029` `rate_limited` | the per-user / per-app limiter of tool calls, app = the server |
| `-32036` (`mcp.CodeUpstream`) with a class-level message | `tunnel_offline`, `tunnel_unavailable`, `upstream_unreachable` / `timeout` / `protocol` / `too_large` / `forbidden` / `blocked`, `upstream_refused` (the upstream answered with a JSON-RPC error; its text is never relayed) |

Every read and get writes **one audit event**, like a tool call: tool `<server>.resources/read` or `<server>.prompts/get` (the bare method when the request never resolved, e.g. not found), resource identity `{server, uri (without query and fragment), uri_sha256 (of the full URI)}` or `{server, prompt}`, decision, outcome, latency, error class. **Never content or arguments.** Lists are not audited.

## Wiring (`cmd/gateway/federation.go`)

Only with a database **and** a key provider (like app connections):

```go
fed, _ := newFederation(ctx, cfg, st, keys, registry, policySvc, metrics, log) // connector.Wire + Start
accounts = federationAccounts(fed, accounts)            // anchors for server apps
newMCPWithResources(..., federationDecider(fed, policySvc), ..., federationResources(fed), ...) // server visibility for list/resolve/policy; resources/prompts
```

| Route | Where | Handler |
|---|---|---|
| `GET /.well-known/mcp-gateway-client.json` | top-level mux, public | `auth.ClientMetadataDocument` (CIMD) |
| `/tunnel/connect` | top-level mux, outside session auth | `tunnel.Service.Handler` (WebSocket; the token is the credential) |
| `GET /servers/{id}/connect` | portal, signed in | `auth.StartConnect` (302 to the server's authorization server) |
| `GET /servers/oauth/callback` | portal, signed in | `auth.Callback` |

The tunnel handler sits outside any buffering or whole-request timeout: the outer metrics wrapper exposes `Unwrap`, which the WebSocket library follows to the hijacker, and the server sets only `ReadHeaderTimeout`. `TestIntegrationFederationTunnelThroughMux` proves the upgrade through the production handler chain. The reverse proxy must allow WebSocket upgrades on `/tunnel/connect`.

netguard uses `netguard.CachedAllowList` over `netguard_allow_hosts` (30 s TTL, fails closed when the table cannot be read, skips invalid rows); `Federation.AllowList.Invalidate()` after an admin edit.

## Tests

- `go test -race ./internal/federation/connector/`: names, sanitizing, tool building, load/reload, visibility and decider, accounts, the call path against an in-process go-sdk upstream through the real netguard (header capture, pinned-schema refusal, disabled/changed tools, credential errors, upstream isError, slow write = unknown outcome, unreachable, tunnel transport, offline and forbidden tunnels), reserved names.
- `make test-integration`: `TestIntegrationPostgresStore` (anchors under RLS, concurrent first use, allow-list loader), `TestIntegrationFederationTunnelThroughMux` (cmd/gateway: tunnel agent through the real mux, a tunnel-backed server reviewed, listed and called through `/mcp`, no gateway credential at the local server, CIMD route).
- `go test -race ./internal/federation/connector/ ./internal/mcp/`: gateway URI and prompt-name round trips (queries, fragments, odd characters, template expansion), template matching, audit identity; resource/prompt lists per visibility and token scope, live reads with the caller's credential, refusals of hidden / unreviewed / non-matching URIs without reaching the upstream, class-level errors; the `/mcp` methods (capabilities, cursor paging, not-found shape, upstream code, audit rows, rate limit).
- `make test-e2e`: `TestE2EFederatedResourcesAndPrompts`: alice lists, reads (text, blob, template) and gets a prompt of her server through the official SDK client; bob sees nothing and reading her URI is "Resource not found"; a resource added upstream after the review is refused without an upstream read; audit rows name the server, never the content.
- `make test-e2e`: `TestE2EFederatedServerVisibilityApprovalAndCredentials`: alice's private server visible to her only, read allowed, write approved and ledgered, a disabled tool absent, args outside the schema refused, a changed schema refused after refresh until re-reviewed, publish → hidden until the role grants → bob with his own credential, then the shared one, approval for bob's write, reserved names refused, no gateway token upstream, audit rows naming the server.
