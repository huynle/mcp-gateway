# Federation connector (`internal/federation/connector`)

User-added MCP servers' tools in the gateway pipeline: **visible per user, policed, approved, ledgered and audited** like built-in tools. This package ties together [netguard](netguard.md), the [federation client](federation-client.md), [upstream auth](federation-auth.md), [snapshots](federation-snapshots.md) and the [tunnel](tunnel.md), and `cmd/gateway/federation.go` wires it. Design: Brain plan `0omkv2e1` (step 4), decisions `yhd5kcaz`, `17iv8p3b`, `mrvsu07m`; task `fybs78bs`.

```
harness ─/mcp─▶ authenticate ▸ audit ▸ resolve ▸ strip ▸ account ▸ scope ▸ precheck ▸ policy ▸ ledger ▸ ratelimit ▸ dispatch ─▶ Manager.call
                              (Decider wrapper: server visibility)   (anchor account)  (Manager.Precheck: review)  (owner layer / roles; confirm → approval)
Manager.call ─▶ snapshot.Allowed (as caller) ▸ auth.ForUser ▸ netguard client | tunnel transport ▸ client Connect + CallTool (auth.Reauth) ─▶ upstream
```

## Tools in the registry

- A server's tools are registered as a **server app** named after the server: `<server>.<tool>` (`connectors.Registry.AddServerTools`, atomic per server; built-in and server apps never share a name, `ErrAppTaken`).
- Only **enabled** tools of the **approved** snapshot of an **active** server are registered, with the **pinned** input schema (a tool without one accepts only `{}`; a schema that is not a JSON object schema is skipped).
- Upstream names are sanitized to `[a-z0-9_-]`: camelCase becomes snake_case, other characters `_`, at most 64 characters. Tools whose names collide after sanitizing are **all** skipped (logged as `federation.tools_skipped`).
- Description: `[<server>] ` + the upstream description run through `snapshot.DisplayDescription` (control, bidi and zero-width characters stripped, capped).
- Kind = the review's kind. Writes declare `Reconcile: none` (an upstream call cannot be checked afterwards, so an unknown outcome becomes `unresolved` and the user is asked to check); no result IDs are kept. Resource identity: `{"server": "<name>"}`, so policy conditions and audit rows can name the server.
- **No replay of identical calls** (quirk `47ab9sk7`, decision `bbgv2sqv`): every tool declares `Idempotency: connectors.IdempotencyPerCall`. Writes still go through the ledger (an `in_progress` row before the call, the outcome after, `unknown` → `unresolved` for a cut-off call, approvals keyed `approval:<id>` and executed once), but each unconfirmed call has its own key (`call:<random>`), so the same arguments twice reach the upstream twice and both return its result. The built-in digest dedupe would be wrong here: the kind comes from the upstream's `readOnlyHint`, so every unannotated read (e.g. Brain's `recall`) counts as a write, and no result is kept, so a replay could only answer with an empty result. Duplicates of real upstream writes are the upstream's concern, exactly as for an MCP client calling the server directly. Built-in connectors and `gateway.*` keep the 24 h digest replay. To also skip the ledger (and approvals) for a tool the upstream did not annotate, the owner (or an admin, for a published server) sets its kind to **read** in the review (`kind_<i>` on the review form, a `KindOverride`; [federation-snapshots.md](federation-snapshots.md)).

### Reload: the hook

| When | Call |
|---|---|
| startup | `Federation.Start(ctx)`: `Manager.Load` + `Manager.Run` (reload every minute, for other replicas) |
| **after any change** to a server (create, edit, rename, publish, unpublish, disable, delete), its snapshot review (approve, change decisions) or its credentials | **`Manager.ServerChanged(ctx, serverID)`** |

`ServerChanged` reloads every server, drops the visibility cache and invalidates the compiled policy (owner layer). The servers portal (task `9dp13dgy`) and admin pages **must** call it; otherwise changes show up only after the periodic reload.

## Reserved names

`ValidateServerName` refuses names that are not `^[a-z0-9_-]{1,63}$` (`ErrInvalidServerName`) and the built-in app names (`ErrReservedServerName`):

`atlassian calendar confluence contacts docs drive fake gateway github gmail google jira mcp microsoft sheets slack tasks`

(`mcp` is the anchor vendor, below; `gateway` is the built-in `gateway.*` management app, [gateway-management.md](gateway-management.md).) A duplicate name is `ErrServerNameTaken` (the Postgres store maps the unique violation). `Manager.CreateServer` / `UpdateServer` validate before writing, so the portal should create and edit servers through them. `CreateServer` first checks that the owner may add MCP servers (`Options.Permissions`, required; `Wire` defaults it to `permissions.NewPostgres` and exposes it as `Federation.Permissions`) and returns `permissions.ErrNotPermitted` otherwise (decision `bnneszc1`). The loader also skips servers with a reserved name that already exist in the database.

## Visibility

A federated tool is visible (tools/list, resolve and the policy stage) only when **both** hold:

1. the user may use the server: its owner (private or published), or holder of a role it is published to (`store.ListVisibleMCPServers` under the user's scope, the source of truth; cached per user for 10 s, dropped by `ServerChanged`); and
2. the policy lists the tool.

`Manager.Decider(policySvc)` wraps the policy so both apply everywhere: for a server the user may not use, `Visible` is false and `Decide` answers `hidden` (the call gets the same answer as an unknown tool) without consulting the policy. Each call checks visibility again through row-level security (`snapshot.Allowed` as the caller).

### Policy defaults

| Server | Default |
|---|---|
| **private** | **implicit owner layer** (`policy.OwnerGrant`, compiled into the Cedar set for every **active** server): the owner may list and call all its tools and use its resources and prompts; **reads allow; writes follow the tool's approval mode** (Ask = confirm, the default; Auto = allow). Token narrowing (read-only, allow-list), user restrictions and role denials still apply; a role `allow` cannot lift an Ask write's confirmation, a role `confirm` keeps confirming an Auto write; the admin role gets nothing from it. |
| **published** | **hidden** for the roles it is published to until an admin adds rules for `<server>.*`, individual tools, `<server>.resources/read` or `<server>.prompts/get` in the role editor (the editor lists federated tools because it reads the registry, plus the two per-server actions). The **owner keeps the owner layer** after publishing (task `fekckdrt`, decision `q7vbxlyk`); an admin can still take access away with a role deny (an unconditional deny hides the tools, like for anyone). For the roles, the approval mode is the default: role allow + Auto = allow, role allow + Ask = confirm, role confirm = confirm. |

**Approval modes in the policy** (task auto-approve). `policy.ServerApproval{App, AutoRun}` is compiled for every active server (`CompileWithLayers(roles, assignments, restrictions, Layers{Owners, Servers})`; `CompileWithOwners` = owners only, every write asks) as one policy per app, `@id("server/<app>/confirm_writes")`: `permit (principal, action == confirm, resource in App::"<app>") when { resource.kind == "write" } unless { [<auto tools>].contains(resource.name) }`. The owner layer emits only call / list. So one Cedar decision path decides owners and roles alike, the auto tools are part of the policy text (versioned and audited with `policy_versions`), and a mode change recompiles through `ServerChanged` → `OnChange` → `policySvc.Invalidate` (other replicas within the reload interval). `policy.NewPostgresStore.Load` reads each active server's approved review (`snapshot.DecodeReview`, `Review.AutoRunToolNames()`); a review that does not decode counts as all Ask. The precheck stage still runs first, and auto-approved writes still go through the ledger and audit (decision `allow`).

## Accounts (anchors)

Approvals and ledger operations reference `connections(id, user_id)`, so every federated call runs against an **anchor connection**: one row per (user, server) under the disabled vendor app `mcp/federation` (vendor `mcp`, added by migration 00015), `external_account_id = mcp-server:<server id>`, display name = server name. It holds no token. Credentials stay in the federation tables.

| Server credential mode / auth kind | Account | Label |
|---|---|---|
| `per_user` + oauth / api_key / bearer / headers | only when the user has a credential row (not revoked); a row that needs reconnecting still yields it so the call can say "reconnect" | `personal` |
| `per_user` + `none`, or `shared` | always (the synthetic shared account) | `company` |

The `gateway.*` management tools use the same vendor app: one anchor per user with `external_account_id = gateway-management`, label `company`, display name `gateway` (`GatewayAccounts`, exposed as `Federation.GatewayAccounts`; see [gateway-management.md](gateway-management.md)).

Without an account the account stage answers `no_account` (connect first). The `/connections` page lists enabled vendor apps only, so anchors do not appear there. The connections keep-alive job logs a daily warning per anchor (no token to refresh), as it does for fake accounts.

## Calls and errors

### Pre-policy check (`precheck` stage)

`Manager.Precheck()` is an `mcp.Prechecker`; `cmd/gateway` inserts `mcp.PrecheckStage` right before the policy stage (`withFederationPrecheck`; before ratelimit when there is no policy stage). For a federated tool it runs the review part of the call path (`Manager.check`, shared with the handler): the server is still active, and `snapshot.Allowed` as the caller accepts the tool (in the approved snapshot, enabled, arguments valid against the pinned schema, not re-reviewed from read to write). So a call that can never run (schema-invalid, disabled or unreviewed) is refused **before policy**: no approval is created, no approval notification (Slack DM) goes out, no ledger operation is recorded (Brain task `8ky7l4e6`). Credentials are not checked there (the handler's `auth_required` answer carries the connect link); built-in tools pass through. The refusal is audited as a **denial** with its class (`args_invalid`, `tool_disabled`, `tool_not_reviewed`, `tool_changed`), never with argument values. The handler keeps its own check (defence in depth): a review that changes between an approval and its retry still refuses the call before the upstream.

### Handler

The handler: server still active → `snapshot.Allowed` as the caller (in the approved snapshot, enabled, args valid against the pinned schema) → a tool listed as a read that the review now marks a write is refused and the registry reloaded → `auth.ForUser` (per_user: the caller's connection; shared: the server's secret; none) → endpoint (netguard's client, or for `tunnel://` URLs `tunnel.Authorize(server owner, tunnel)` + the tunnel transport; `header_config.static` as headers) → `Connect` + `CallTool` under `auth.Reauth` → the upstream `CallToolResult` passed through whole (content, structuredContent, isError; bounded by the client).

Every `tools/call` carries `_meta["mcp-gateway/tool-digest"]`: the digest of the tool's definition in the **approved** snapshot (`internal/federation/tooldigest.Digest(name, description, inputSchema)`: `sha256:` + hex SHA-256 of the canonical JSON, keys sorted, numbers normalized, so jsonb storage does not change it; `connector/tooldigest.go`). Servers that do not know the key ignore it (the SDK adds its own protocol `_meta` keys next to it). The machine actions server (`internal/machineclient`) refuses a call whose digest is not the one of the definition it serves now, so a tool edited under the same name runs only after its new snapshot is approved.

**Gateway credentials are never forwarded**: the client builds every upstream request from the endpoint and the Authorizer (tests check with a capturing upstream and a tunnel-side capture).

| Class | Kind | Meaning |
|---|---|---|
| `tool_not_found` | JSON-RPC (same as unknown tool) | server gone, disabled, or not visible to the caller |
| `args_invalid` | JSON-RPC `-32602`, audited as a denial | arguments do not match the pinned schema (never echoed); refused by the precheck before any approval, and again at dispatch |
| `tool_disabled`, `tool_not_reviewed`, `tool_changed` | JSON-RPC `-32030`, audited as denials | the review does not allow the call (`tool_changed`: re-reviewed as a write since listed; list again) |
| `auth_required`, `needs_reconnect` | JSON-RPC `-32031` (with credential links: `-32042`, below) | connect / reconnect on the portal: the message carries `<BASE_URL>/servers/<id>` |
| `user_header_missing` | JSON-RPC `-32042` (only with credential links) | a declared per-user header has no value for the caller (`auth.ErrUserHeaderMissing`); refused before the upstream |
| `server_not_configured`, `shared_credential_rejected` | JSON-RPC `-32031` (the owner, with credential links: `-32042`) | ask the server's owner |
| `tunnel_offline`, `tunnel_unavailable` | tool error (isError) | start `mcp-gateway-tunnel` / the tunnel is revoked or not the owner's |
| `upstream_unreachable`, `upstream_timeout`, `upstream_protocol`, `upstream_too_large`, `upstream_forbidden`, `upstream_blocked`, `upstream_tool_error`, `upstream_error` | tool error (isError) | class-level; never upstream text or URLs |

### Credential links

`GATEWAY_CREDENTIAL_LINKS_ENABLED` (default off; `WireOptions.CredentialLinks`, `Options.CredentialLinks`; read by `cmd/gateway/federation.go` through `elicit.ConfigFromEnv`; design: [plan 1](plans/2026-10-23-credential-links-and-elicitation-relay-design.md)) turns credential answers the caller can act on into `-32042` (`mcp.NewURLElicitationRequired`, `connector/credlinks.go`). **The class never changes**, so audit rows, ledger operations and the secrets stage's refund list (which gains `user_header_missing`) behave as before. **Off, every answer is byte for byte what it was** (`TestCredentialLinksOffIsUnchanged`, `TestSecurityFedCredentialLinksOwnerOnly`).

| Class | Cause | Who gets the link | Link |
|---|---|---|---|
| `no_account` | per-user server (auth kind other than none) without the caller's connection; the account stage asks `Accounts(...).MissingAccount` (`mcp.MissingAccounter`) | anyone who may use the server | `ConnectLink`: `/servers/<id>/connect` (per-user OAuth) or `/servers/<id>#connection` |
| `auth_required` | `auth.ErrNotConnected`, or the upstream refusing authentication (`client.ClassAuthRequired`) | the caller, on a server that takes a credential or header values from each user; otherwise the owner (edit link) | `ConnectLink` |
| `needs_reconnect` | `auth.ErrNeedsReconnect` (ForUser, or a 401 after refresh) | as above | `ConnectLink` |
| `user_header_missing` | `auth.ErrUserHeaderMissing`: the Manager's credentials are `Federation.Auth.UserHeadersRequired(true)` (the portal's stay lenient) | the caller | `/servers/<id>#connection` |
| `server_not_configured` | `auth.ErrSharedMissing`, `ErrModeInvalid`, `ErrUnsupported`, `ErrNotConfigured`, `ErrNowRequiresAuth` (a no-auth server answering 401: with the flag no longer `upstream_error`), an invalid tunnel URL | **the owner only** (`server.OwnerUserID`) | `EditLink`: `/servers/<id>/edit` |
| `shared_credential_rejected` | the upstream rejected the shared credential | **the owner only** | `EditLink` |
| `credentials_unavailable`, `tunnel_*`, `upstream_*` | everything else | nobody: unchanged | - |

The answer: message `<server>: connect your account at <url>, then retry` (reconnect / per-user headers / for the owner `<reason>; as the server's owner, fix it at <url>, then retry`), `data.url`, `data.server` = the server name, `data.elicitations = [{mode: "url", elicitationId: "gwc_" + sha256(user, server, class)[:16 bytes hex], url, message: "Connect <server>" / "Set up <server>"}]`. Everyone but the owner gets today's `-32031` text for owner-only cases, so the edit page and the cause never leak. A server the caller cannot see gets the plain `no_account`. The same mapping applies to `resources/read` and `prompts/get` (`withSession`). The `gateway.*` account wrapper forwards the hook.

Upstream failures implement `mcp.ClassedError`, so the audit row and a failed ledger operation record the class. A **write** that fails *inside* `tools/call` with a timeout, an unreachable server, a protocol error, an oversize answer or a tunnel dropping mid-call is an **unknown outcome** (`connectors.ErrOutcomeUnknown`) and the message tells the user to check before retrying. A tool that ran and reported an error (`isError: true`) is passed through as a result; the ledger records the write as succeeded, because the call completed.

## Resources and prompts

The gateway's own `/mcp` also serves the **resources, resource templates and prompts** of user-added servers (task `isdrqc6a`, plan `0omkv2e1` §3), through `Manager.ResourceProvider(policySvc)` (`mcp.Options.Resources`; `cmd/gateway/federation_resources.go`). `/mcp` then advertises `resources` (no `subscribe`, no `listChanged`) and `prompts` (no `listChanged`); without a federation it advertises neither.

### Names and URIs

| Upstream | On the gateway |
|---|---|
| resource `notes://readme` of server `notes` | `mcpgw://notes/notes://readme` |
| template `notes://note/{id}` | `mcpgw://notes/notes://note/{id}` |
| prompt `summarize` | `notes.summarize` |

A gateway resource URI is `mcpgw://<server>/` followed by the upstream URI **verbatim** (no escaping): the server is the URI's authority and the mapping is a plain prefix, so it reverses exactly for any upstream URI (any scheme, query, fragment or characters; `connector.GatewayResourceURI` / `ParseGatewayResourceURI`). The prefix holds no template expressions, so the same prefix rewrites a template and a client filling in the gateway template gets the gateway URI of what the upstream template gives for the same values. Read contents carry gateway URIs too, and so do **resource links and embedded resources in prompt results** (`rewritePromptResult`, task `bdb5zcud`), so a client reads them back through the gateway and its checks. Prompt names split at the first `.` (server names have none). Names are `<server>.<upstream name>`; **titles and descriptions start with `[<server>] `** (provenance) and are cleaned like tool descriptions (`snapshot.Display*`). Items whose URI, template or prompt name contains control or format characters (bidi, zero-width) are not listed.

### Visibility and checks

- **Lists** are the union, over the servers the caller may use (the same rule as their tools: the owner, or a role it is published to; a narrowed token must name the server in its apps) **and policy permits** (below), of the items of each server's **approved snapshot** the review **enabled** (as of the last load), never a live listing. Sorted by URI / name, paged with an opaque cursor (100 per page), `cacheScope: private`.
- **`resources/read`**: the URI must map back to a loaded server the caller may use, still active under that name, policy must permit `<server>.resources/read`, and the upstream URI must be an **enabled** resource of the approved snapshot (read as the caller: RLS) or match one of its **enabled** templates (RFC 6570, the go-sdk's matcher). Then it goes upstream **live** over the tool-call path: `auth.ForUser` (per_user / shared / none), netguard or the owner's tunnel, `auth.Reauth`, bounded by the federation client (timeout, 4 MiB per message). Text and blob contents pass through with their MIME types.
- **`prompts/get`**: policy must permit `<server>.prompts/get` and the prompt must be enabled in the approved snapshot; arguments pass through as given; then like a read.
- **Policy: two per-server actions** (task `bdb5zcud`, decision `q7vbxlyk` point 2). `<server>.resources/read` covers `resources/list`, `resources/templates/list` and `resources/read`; `<server>.prompts/get` covers `prompts/list` and `prompts/get`. They are pseudo-tools (`policy.ServerAccessTool`, kind read; never in `tools/list`) decided with `policy.Service.Permits`: only **allow** counts (there is no approval flow for reads of resources or prompts, so a `confirm` outcome refuses them like `deny`). The owner layer grants both; a published server's roles need a rule (`<server>.resources/read`, `<server>.prompts/get`, or the `<server>.*` wildcard; a tool grant alone does not). Token narrowing applies (an allow-list must name the server or the action). A policy error fails closed. The servers portal's resource and prompt pages ask the same policy (`fedportal.Deps.Policy`).
- **Review toggles**: the snapshot review enables each resource, template and prompt (`snapshot.ContentReview`, docs/federation-snapshots.md). A snapshot approved before the toggles existed has no content review and counts as **all enabled**, so servers approved earlier keep working without a new review.

### Errors and audit

| Answer | When |
|---|---|
| `-32602` `Resource not found` (`data.uri`) / `unknown prompt "<name>"` | not a gateway URI, no such server, a server the caller may not use, not permitted by policy, disabled server, not in the approved snapshot, or disabled by the review. The same bytes for hidden and unknown. |
| `-32031` `auth_required`, `needs_reconnect`, `server_not_configured`, `shared_credential_rejected` | as for tools (the message carries `<BASE_URL>/servers/<id>`); with credential links `-32042` exactly as for tools (and `user_header_missing`) |
| `-32029` `rate_limited` | the per-user / per-app limiter of tool calls, app = the server |
| `-32036` (`mcp.CodeUpstream`) with a class-level message | `tunnel_offline`, `tunnel_unavailable`, `upstream_unreachable` / `timeout` / `protocol` / `too_large` / `forbidden` / `blocked`, `upstream_refused` (the upstream answered with a JSON-RPC error; its text is never relayed) |

Every read and get writes **one audit event**, like a tool call: tool `<server>.resources/read` or `<server>.prompts/get` (the bare method when the request never resolved, e.g. not found), resource identity `{server, uri (without query and fragment), uri_sha256 (of the full URI)}` or `{server, prompt}`, decision, outcome, latency, error class. **Never content or arguments.** Lists are not audited.

## Wiring (`cmd/gateway/federation.go`)

Only with a database **and** a key provider (like app connections):

```go
fed, _ := newFederation(ctx, cfg, st, keys, registry, policySvc, perms, metrics, log) // connector.Wire + Start
gw, _ := newGatewayTools(fed, st, registry, perms, cfg.BaseURL, log) // gateway.* tools (gateway-management.md)
accounts = gw.Accounts(federationAccounts(fed, accounts)) // anchors for server apps and the gateway app
newMCPWithResources(..., gw.Decider(federationDecider(fed, policySvc)), ..., federationResources(fed, policySvc), withFederationPrecheck(fed, log), withLedgerStage(ledgerSvc)) // gate + server visibility for list/resolve/policy; resources/prompts; precheck before policy
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

- `go test -race ./internal/federation/connector/ ./internal/mcp/`: the precheck (`TestManagerPrecheck`: schema-invalid, disabled, unreviewed, changed, hidden and disabled-server calls refused without the upstream; `TestManagerDispatchStillChecksAfterPrecheck`; `TestPrecheckRunsBeforePolicyAndConfirm`: no confirm hook for a refused call, audited deny/denied/args_invalid).
- Credential links: `go test -race ./internal/federation/connector/ ./internal/mcp/ ./internal/federation/auth/` (`TestCredentialLinks*`: flag off byte for byte, user-fixable rows for owner and non-owner, owner-only rows, elicitation ids, the account hook, resources/prompts; `TestAccountStageMissingAccountHook`; `TestUserHeaderMissing`, `TestForUserOwnerOnlyErrorsAreSubSentinels`, `TestNoAuthServerAnswering401IsNowRequiresAuth`); `make test-e2e`: `TestE2ECredentialLinks` (no connection → `-32042` `#connection`, set the key, retry runs; a declared per-user header without a value → `-32042` `user_header_missing`, nothing upstream, set it, retry runs); `make test-security`: `TestSecurityFedCredentialLinksOwnerOnly` (a non-owner's answer on a shared server without its credential is the flag-off bytes; only the owner gets the edit link), `TestSecurityFedCredentialLinksPerUser` (per-user links, distinct elicitation ids, no edit link); `make test-integration`: `TestIntegrationFederationCredentialLinksFlag`.
- `make test-security`: `TestSecurityFedApprovalModes` (Ask still confirms; Auto runs and is ledgered; a forged mode for a read tool is ignored; a read-only token, a role deny and a role without a grant stay refused; the owner of a published server cannot change modes through the page (403) or the service (RLS); the approval POST is in the portal IDOR and admin-route sweeps).
- `make test-security`: `TestSecurityFedSnapshotBypass` (schema-invalid writes: `-32602`, no approval row, no ledger operation, no approval notification, five audited `args_invalid` denials; a valid write asks for an approval; a review change after the approval refuses the retry before the upstream).
- `go test -race ./internal/federation/connector/`: names, sanitizing, tool building, load/reload, visibility and decider, accounts, the call path against an in-process go-sdk upstream through the real netguard (header capture, pinned-schema refusal, disabled/changed tools, credential errors, upstream isError, slow write = unknown outcome, unreachable, tunnel transport, offline and forbidden tunnels), reserved names.
- `make test-integration`: `TestIntegrationPostgresStore` (anchors under RLS, concurrent first use, allow-list loader), `TestIntegrationFederationTunnelThroughMux` (cmd/gateway: tunnel agent through the real mux, a tunnel-backed server reviewed, listed and called through `/mcp`, no gateway credential at the local server, CIMD route).
- `go test -race ./internal/federation/connector/ ./internal/mcp/`: gateway URI and prompt-name round trips (queries, fragments, odd characters, template expansion), template matching, audit identity; resource/prompt lists per visibility and token scope, live reads with the caller's credential, refusals of hidden / unreviewed / non-matching URIs without reaching the upstream, class-level errors; the `/mcp` methods (capabilities, cursor paging, not-found shape, upstream code, audit rows, rate limit).
- `make test-e2e`: `TestE2EFederatedResourcesAndPrompts`: alice lists, reads (text, blob, template) and gets a prompt of her server through the official SDK client; bob sees nothing and reading her URI is "Resource not found"; a resource added upstream after the review is refused without an upstream read; audit rows name the server, never the content.
- `go test -race ./internal/federation/connector/ ./internal/mcp/ ./internal/ledger/`: `TestBuildTools` (every built tool is per-call), `TestLedgerStagePerCallToolsRunEveryIdenticalCall`, `TestLedgerStageReplayAnswerIsExplicit`, `TestBeginPerCallNeverReplaysOrWaits`, `TestBeginPerCallWithApprovalUsesTheApprovalKey`.
- `make test-e2e`: `TestE2EPluginsIdenticalUpstreamCallsBothRun` (an unannotated upstream `recall`, auto mode, called twice with identical arguments: two upstream calls, both answers the upstream's text, two `succeeded` operations with `call:` keys, no `replayed` audit row); `TestE2EDuplicateWritesReplayAndWindow` keeps proving the built-in replay (`fake.post_note`) and its explicit message.
- `make test-e2e`: `TestE2EFederatedServerVisibilityApprovalAndCredentials`: alice's private server visible to her only, read allowed, write approved and ledgered, a disabled tool absent, args outside the schema refused, a changed schema refused after refresh until re-reviewed, publish → hidden until the role grants → bob with his own credential, then the shared one, approval for bob's write, reserved names refused, no gateway token upstream, audit rows naming the server.
- `make test-e2e`, plugins scenarios (task `w2cd39bc`; `test/e2e/plugins_*_test.go`), through the **servers portal and admin pages over HTTP** (mounted in the e2e world as `cmd/gateway` mounts them) and the official SDK client:
  - `TestE2EPluginsPortalAddDetectConnectReviewAndApprove`: Detect on the add form for a Brain-shaped OAuth server (DCR, PKCE S256), an API-key-only server and a no-auth server; add all three; per-user OAuth connect through `/servers/{id}/connect` → in-process authorization server → `/servers/oauth/callback` (connection stored, tools called with the upstream token); a write approved on the portal and ledgered; Refresh after the upstream changes a schema and adds a tool: the review shows changed/added, nothing pre-checked, the old pinned schema still applies, the changed tool is refused until re-enabled, then callable with the new schema.
  - `TestE2EPluginsSharedKeyPublishedByAdmin`: a shared API key server published to a role and its key replaced on the admin pages; two users of the role call with the shared key once the role grants the tool; the owner keeps the tool after publish (owner layer, task `fekckdrt`); the owner cannot approve a published server's review (403); admin actions audited without the key.
  - `TestE2EPluginsPrivateVsPublishedVisibility`: tools, resources, templates and prompts per user while private, published (nothing for the role until granted; a tool grant gives the tool only; `resources/read` + `prompts/get` grants give the rest, a templated read through the published server; the owner keeps everything), and unpublished again.
  - `TestE2EPluginsApprovalModes` (task auto-approve): an Ask write asks; "Run all without asking" on the server page; the same write then runs in one MCP call without an approval row, ledgered `succeeded` and audited, the mode change audited; after publish the owner's mode edit is 403; role allow + Auto runs for bob, the admin's Ask makes bob and the owner ask, a role confirm keeps asking under Auto.
  - `TestE2EPluginsOwnerKeepsAccessAfterPublish`: the owner reads and gets a write confirmation on her published server without a role grant; the admin page says the owner keeps access; a role deny on her role hides the tools.
  - `TestE2EPluginsResourceReviewAndGrants`: review toggles for resources, templates and prompts; disabled ones are not listed and answer "Resource not found"; approve_all enables all; a legacy approved snapshot (flat review column) serves everything unreviewed; prompt results carry gateway URIs.
  - `TestE2EPluginsTunnelStdioServer`: the real `mcp-gateway-tunnel` binary (built by the test) with `--stdio` next to a stdio server; tunnel created on the portal (token shown once), server `tunnel://<id>/` reviewed and called through `/mcp`; client stopped → `tunnel_offline`; admin revoke → client exits 1, calls refused `tunnel_unavailable`, the revoked token is refused.
  - `TestE2EPluginsAddServerNeedsPermission`: a member without "May add MCP servers" gets no Add server button, 403 on create and detect, a refusing connector and a disabled Gateway management tools switch; once an admin assigns a role with the flag, the member adds a server.
  - `TestE2EPluginsLegacySSEUpstream`: a legacy HTTP+SSE-only server detected, added, refreshed and called (automatic fallback from Streamable HTTP observed at the upstream).
  - The fake upstreams are `httptest` **TLS** servers (the portal accepts only https and netguard verifies TLS against the system roots). The e2e test binary trusts the httptest certificate through `x509.SetFallbackRoots` with `//go:debug x509usefallbackroots=1` (`test/e2e/plugins_world_test.go`); 127.0.0.1 is allow-listed through the admin allow-list page. Production code is unchanged.
