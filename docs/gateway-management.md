# Gateway management tools (`gateway.*`, `internal/federation/gatewaytools`)

A user's own MCP client (OpenCode, Claude, ...) can manage the user's MCP servers on this gateway through `/mcp`: list them, inspect one, detect how a new server authenticates, add it, refresh it and delete it. Design: Brain plan `ax0w46sh`, decisions `bnneszc1` (permission + per-user switch; no approval, secrets or sign-in over MCP) and the decision recorded with task `99b5yzdb` (this package). The tools sit on the same services the servers portal uses ([plugins-portal.md](plugins-portal.md)) and the connector Manager ([federation-connector.md](federation-connector.md)).

## Who sees them

The tools exist for a user only when **both** hold, evaluated **per request**:

1. the user **may add MCP servers** (admin, or a role an admin marked "May add MCP servers"; `permissions.Service.CanAddServers`), and
2. the user switched **Gateway management tools** on in My account (`/account`, `POST /account/gateway-tools`, default off).

That is `permissions.Service.GatewayToolsActive`. Otherwise the tools are **absent from `tools/list`** and a call is answered **exactly like an unknown tool** (`-32602 unknown tool "gateway.…"`), for every tool name. "On in the database but the role was removed" counts as off: the stored setting is not rewritten.

| Permitted | Setting | `gateway.*` |
|---|---|---|
| no | off | hidden |
| no | on (role removed later) | hidden |
| yes | off | hidden |
| yes | on | listed and callable |

`gatewaytools.Gate` caches one answer per user for **2 s** (`DefaultGateTTL`; tools/list asks once per tool). Switching the setting goes through `Gate.Setting(perms)` (what the portal is given), which drops the user's cached answer, so switching **off takes effect at once** on that replica; a role removed by an admin, or a switch on another replica, takes effect within the TTL. The admin role never bypasses: admins are permitted but still need the switch.

The gate wraps the policy decider (`Gate.Decider`, outermost, around the federation's server visibility) so one check covers `tools/list`, tool resolution and the policy stage. The connector checks the gate again inside every call (defense in depth).

## Policy

The compiled Cedar set has an implicit **gateway layer** (`internal/policy/gateway.go`, like the owner layer of private servers): every principal may list and call `gateway.*` without a role grant, and `gateway.delete_server` needs a confirmation.

```
@id("gateway/management")           permit list, call   on App::"gateway"
@id("gateway/management/confirm_delete") permit confirm on App::"gateway" when resource.name == "gateway.delete_server"
```

- reads and `add_server`: **allow**; `delete_server`: **confirm** (approval required);
- token narrowing still applies: a **read-only token** never sees `add_server` or `delete_server`; a token restricted to other apps sees no `gateway.*`;
- user restrictions and role **deny** rules apply; a role **allow** cannot lift the delete confirmation;
- the admin role gets nothing extra (still confirm on delete);
- the role editor lists the `gateway.*` tools (it reads the registry), so an admin can deny them per role.

Who actually sees the tools is the gate's decision; the layer only spares admins from granting them in every role.

## Account (approvals and ledger)

Approvals and ledger operations need a `connections` row (decision `mrvsu07m`). The gateway app uses the same **anchor** approach as user-added servers: one row per user under the disabled vendor app `mcp/federation`, `external_account_id = gateway-management`, label `company`, display name `gateway`, created in the user's own scope on first use (`connector.GatewayAccounts`, `Federation.GatewayAccounts`). `Gate.Accounts` returns it as the only `gateway` account when the gate is open and none otherwise. There is no `gateway.list_accounts` tool. The anchor holds no token and does not appear on `/connections`.

## Tools

All tools take only the arguments listed (`additionalProperties: false`; anything else is refused). `server` is a server's **name or ID**. Links are absolute (`GATEWAY_BASE_URL` + path).

| Tool | Kind / policy | Arguments | Returns |
|---|---|---|---|
| `gateway.list_servers` | read / allow | – | My servers and those published to me: `id`, `name`, `url_host` (tunnel servers: `tunnel <name>`), `owner`, `audience`, `status`, `last_error_class`, `auth_kind`, `credential_mode`, `connection` (connected / needs connect / needs reconnect / shared credential / no connection needed), `pending_review`, `approved_tools` (enabled in the approved snapshot), `links` (`server`; owner: `review`, `settings`; when a credential is needed: `connect`). Plus `add_server` and `servers_url` links. |
| `gateway.get_server` | read / allow | `server` | The above plus `api_key_placement`, `scopes`, `static_header_names`, `per_user_header_names`, `approved_version`, `latest_version`, `next_steps` (`step`, `link`, `note`): `set_shared_credential` (owner, shared secret kind, none stored → settings page), `connect` (OAuth → `/servers/{id}/connect`) or `enter_credential` (→ `/servers/{id}#connection`), `inactive`, `refresh` (owner, no snapshot yet → call `gateway.refresh_server`), `review` (owner of a private server with a pending snapshot → `/servers/{id}/review`), `await_review` (published: an admin reviews), else `ready`. |
| `gateway.detect_auth` | read / allow | `url` (https) | `auth_kinds` (most preferred first), `oauth`, `dcr`, `cimd`, `pkce_s256`, `offline_access`, `scopes`, `blocked` (discovery destinations netguard refused). Runs `auth.Detect` through netguard. |
| `gateway.add_server` | write / allow | `name`, `url`, `auth_kind` (oauth, api_key, bearer, headers, none), `credential_mode` (per_user, shared), optional `api_key_in` (header, query), `api_key_name`, `static_header_names` | `server_id`, `server` (as in the list), `next_steps`, `review_link`, a note. |
| `gateway.refresh_server` | read / allow | `server` (owner) | `from_version`, `to_version`, `added` / `changed` / `removed` (`count`, `names` capped at 20, `truncated`), changed resource / template / prompt counts, `review_link`, a note that nothing was approved. |
| `gateway.connect_link` | read / allow | `server` | `link` (OAuth: `/servers/{id}/connect`; api_key / bearer / headers: `/servers/{id}#connection`; shared or none: the server page), `connection`, a note. |
| `gateway.delete_server` | write / **confirm** | `server` (owner) | `deleted`, `server_id` (after the approval). |

Every description tells the model that **secrets, signing in to a server and approving its tools happen in the browser at the returned links**, and never to ask the user to paste a secret into the chat.

### add_server

- **Never a secret.** Refused with class `secret_refused` and "enter API keys, tokens and header values in the browser at the server's portal page" before anything is stored or any request is made:
  - an argument whose name suggests a credential (`key`, `token`, `secret`, `password`, `credential`, `authorization`, `bearer`, `cookie`, `private`, `session`, `signature`, in any case or combination, also nested inside objects), other than the listed arguments;
  - a value the log redactor would hide (`Bearer …`, provider token formats such as `ghp_…`, `key=value` credentials, credentials in URL query parameters) anywhere in the arguments;
  - a URL with user info or a query parameter whose name suggests a credential;
  - a `static_header_names` entry with a value (`Name: value`, `Name=value`).
  The answer never echoes the value; the e2e and security suites check that refused secrets never reach the logs or the audit trail.
- **Name**: `connector.ValidateServerName` (`[a-z0-9_-]{1,63}`, not reserved). The reserved list includes **`gateway`** (this app) and `mcp` (the anchor vendor). A name already taken: `name_taken`.
- **URL**: an `https` URL that netguard's literal check accepts (`netguard.Guard.CheckURL`: loopback, private, link-local, metadata and ambiguous numeric hosts refused unless an admin allow-listed them; names are checked again at dial time), or `tunnel://<id>/<path>` of one of **the caller's own live tunnels**. Tunnels themselves (and their tokens) are only created in the browser.
- **Auth**: `none` is stored as `per_user`; `oauth` + `shared` is refused (no shared OAuth tokens); `api_key_in` / `api_key_name` only with `api_key` (header name: an HTTP token the transport does not own; query name: letters, digits, `-`, `_`, `.`).
- **`static_header_names`** (agent decision, needs review): names of extra request headers whose **values each user enters in the browser**, stored as `header_config.per_user` (the portal's "per-user header names"). Values are never accepted over MCP, so static `Name: value` headers (`header_config.static`) can only be set on the portal's edit page.
- **Create** through `connector.Manager.CreateServer`: the add-server permission check (`not_permitted`), the name rules, the private server owned by the caller, the registry reload. A shared credential is **set on the portal** (`next_steps`: `set_shared_credential` → `/servers/{id}/edit`).
- The new server is **private and every tool is disabled** until the owner refreshes it and approves tools on the review page; that is why the policy default is allow.

### refresh_server

Owner only (a server published to me but owned by someone else is "not found" here, like on the portal). Opens an upstream session **as the caller** through the portal's client factory (`fedportal.NewClientFactory`: the caller's or the shared credential, netguard or the owner's tunnel, one refresh-and-retry on 401), then `snapshot.Refresh` with `Actor{UserID: caller}`. It **never approves**: the `Snapshots` interface the tools get has no `Approve`, new and changed tools stay disabled (decision `d6sitdqi`), and the result points at the review page. Failures are the portal's class-level messages (`fedportal.SessionMessage`: connect first, reconnect, credentials not set up, tunnel offline, blocked by network policy, ...) with the server page link.

### delete_server

Owner only; a **write that always needs an approval** (policy confirm, `approval required` with the approval link; the harness retries with `approval_id`). The approval is requested **before** the tool runs (the policy stage comes first), so it is asked for whatever the `server` argument names; after approval, a server the caller does not own answers "not found" like a missing one. On success: `DeleteServer` as the owner (row-level security), then `Manager.ServerChanged` (registry reload, visibility cache, policy invalidation). Ledgered (reconcile `none`, result id `server_id`).

## Errors

Tool failures are tool results with `isError` and a fixed audit class (`mcp.ClassedError`); messages are short, class-level and never contain upstream text or argument values that could be secrets.

| Class | When |
|---|---|
| `server_not_found` | the server does not exist, is not visible to the caller, or (refresh, delete) is not the caller's: one wording for all, by name or ID |
| `secret_refused` | see add_server |
| `args_invalid` | unknown argument, wrong type, missing value, bad combination |
| `name_invalid`, `name_taken`, `not_permitted` | add_server |
| `url_invalid` | not https / not one of my live tunnels |
| `upstream_blocked` | netguard refuses the address (the portal's SSRF message) |
| `upstream_unreachable`, `upstream_timeout`, `upstream_protocol`, `upstream_too_large`, `upstream_forbidden`, `upstream_auth_required`, `upstream_tool`, `detect_failed` | detect_auth, by federation client class (`fedportal.DetectMessage`) |
| `refresh_failed` | refresh_server (`fedportal.SessionMessage`) |

## Audit

Every call is an audit row of the `/mcp` pipeline (tool, decision, outcome, error class) with the resource identity `{"server": <name or id>}` (`add_server`: the new name; `detect_auth`: `{"host": …}`; `list_servers`: `{"app": "gateway"}`). An argument that is not a server name or ID is recorded as `invalid`, so arbitrary text never reaches the audit trail. `add_server` and `delete_server` are also ledger operations; `delete_server` approvals appear on `/approvals`. Log events: `gateway_tools.server_added`, `gateway_tools.server_refreshed`, `gateway_tools.server_deleted`, `gateway_tools.detect_failed`, `gateway_tools.refresh_failed`. Switching the setting is audited as `user.gateway_tools_toggled`.

## Not over MCP

By design there is **no** tool to approve a tool review, change a review, publish or unpublish a server, edit the network allow list, create or revoke a tunnel (or see its token), enter or read any credential, or sign in to a server. Those happen in the browser (servers portal and admin pages).

## Wiring

`cmd/gateway` (`newGatewayTools`, `federation.go`), only when the federation is wired (database and key provider):

```go
perms := permissions.NewPostgres(st, ...)                         // one instance for all
fed, _ := newFederation(ctx, cfg, st, keys, registry, policySvc, perms, metrics, log)
gw, _ := newGatewayTools(fed, st, registry, perms, cfg.BaseURL, log) // gatewaytools.Wire: registers gateway.*
accounts = gw.Accounts(federationAccounts(fed, accounts))         // the gateway anchor account
newPortal(..., gw.Setting(perms), ...)                             // My account switch drops the gate cache
newMCPWithResources(..., gw.Decider(federationDecider(fed, policySvc)), ...)
```

A nil `*gatewaytools.Tools` (no federation) leaves every wrapper unchanged and registers nothing.

## Tests

- `go test -race ./internal/federation/gatewaytools/`: the visibility matrix over the real `permissions.Service` (not permitted / off, not permitted / on in the DB, permitted / off, permitted / on) for `Visible`, `Decide` and `PolicyVisibility`; the policy is not consulted while the gate is closed; switching off takes effect at once, a removed role within the TTL; accounts; registration (seven tools, kinds, closed schemas, descriptions that point to the browser, no list_accounts); policy defaults of the registered tools (delete confirms); a closed gate answers like an unknown tool; list / get with next steps and links; another user's server not found by name or ID with the same wording; owner-only tools; detect (fields, class-level errors, refused URLs never reach the detector); add (OAuth, API key in header / query, per-user header names, shared bearer note, none); secret-looking arguments refused without echo; reserved and invalid names, http, blocked literals, other users' and revoked tunnels, bad combinations, name taken, not permitted; refresh (as the caller, never approves, capped diff, class-level failure with link); connect links; delete (ServerChanged, result ids, resource identity never echoes arbitrary text).
- `go test ./internal/policy/ -run Gateway`: the gateway layer (no role needed, delete confirms, admin no bypass, role deny, restriction, read-only and restricted tokens).
- `make test-integration`: `TestIntegrationPostgresStoreNameTakenAndGatewayAccount` (duplicate name → `ErrServerNameTaken`; the gateway anchor is per user, stable, RLS-private).
- `make test-e2e`: `TestE2EGatewayToolsManageServers` (admin switches on via My account; lists, detects, adds a fake TLS upstream, refreshes, follows the review link to approve on the portal, the server's tool appears and runs; secret and reserved name refused; delete needs an approval, then deletes and ledgers; a member without permission never sees or reaches `gateway.*` and cannot switch on; switching off hides them at once), `TestE2EGatewayToolsRoleRemoved` (the stored setting stays on but the tools disappear within seconds after the role is taken away).
- `make test-security`: `TestSecurityGatewayToolsSecretArguments` (sixteen ways to pass a secret, none stored, echoed, logged or audited), `TestSecurityGatewayToolsSSRF` (metadata, loopback literal / numeric / hex / IPv6 / mapped, private ranges, a name resolving to loopback: refused by the real netguard, the internal server never hit, nothing stored), `TestSecurityGatewayToolsCrossUser` (bob's private server by name and ID answers like a missing one on get / connect_link / refresh / delete, after approving the delete too; bob's tunnel refused; a server published to alice is readable but not refreshable or deletable by her).
