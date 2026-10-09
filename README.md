# MCP Gateway

A self-hosted, always-on [MCP](https://modelcontextprotocol.io) gateway that sits in front of every app a team's AI harnesses use. Coworkers sign in with their company account, connect their own app accounts (GitHub, Slack, Atlassian, Google Workspace, Microsoft 365), and point any harness (OpenCode, Claude Code, Claude Desktop, ...) at one endpoint using a generated token or MCP OAuth sign-in. Every tool call is filtered by role, checked by policy, optionally confirmed by the user, recorded in a write ledger and audited. One deployment serves one company. The design lives in Brain plan `36bakiw8` (*Team MCP Gateway v1 design*, revision 2) and its linked decisions; the earlier single-user design is in [`docs/plans/`](docs/plans/).

## Status

Foundation, data layer and sign-in: Go module, configuration, structured logging, `/healthz`, `/readyz` (`database` and `schema` checks), graceful shutdown, the full v1 PostgreSQL schema as goose migrations, a repository layer scoped per user, row-level security as the second isolation layer, the envelope-encryption key provider, company sign-in through any configured OIDC provider (dex locally; Google, Entra, Okta) with just-in-time users, server-side sessions, the embedded portal shell (sign-in, my account, admin users, activity, audit search), generated harness tokens (`mgw_...`) with their authenticator, and the `/mcp` endpoint: stateless Streamable HTTP on the official Go SDK behind bearer authentication, a tool registry, per-token `tools/list`, and a staged `tools/call` pipeline (authenticate, audit, resolve, strip, account, rate limit, dispatch). The connector contract (`internal/connectors`: `Connector`, `Account`/`AccountSource`, reconciliation declarations, bounds, vendor rate-limit errors, `RegisterConnector` with the generated `<app>.list_accounts`), its contract test, the in-process `fake` connector the safety-core tests run against, account resolution (one account auto-resolves, several must be named) and the per-user / per-app token-bucket limiter honouring vendor `Retry-After` are in. Policy is in: admins edit roles as structured data in the portal, the gateway compiles roles, user restrictions and token scope into a versioned Cedar policy set ([cedar-go](https://github.com/cedar-policy/cedar-go)) and decides allow / confirm / deny / hidden per call (see [Policy](#policy)). App connections are in: admins register one OAuth app per vendor (two for Google) on `/admin/vendor-apps`, users connect company and personal accounts on `/connections` through a generic OAuth 2.0 + PKCE flow, tokens are envelope-encrypted and refreshed one at a time per connection, and the account stage reads the connections table (see [App connections](#app-connections)). The write ledger is in: every write is recorded as `in_progress` before the app call (consuming its approval in the same transaction), duplicates inside a window replay the stored result IDs, unknown outcomes are reconciled with backoff or surfaced as `unresolved` with a notification, stale rows are swept, and users see their writes on `/operations` (see [Write ledger](#write-ledger)). The registry holds only the fake until the real connectors land; OAuth for harnesses, approvals and the ledger follow (Brain feature `team-mcp-gateway-v1`).

## Run locally

Requirements: Go 1.25, Docker with Compose v2, [golangci-lint](https://golangci-lint.run) v2 for `make lint`.

```bash
make build test lint          # bin/gateway + bin/migrate, unit tests (race detector), lint
make compose-up               # PostgreSQL 16 (15432), dex (15556), migrations, gateway (18080)
curl -f localhost:18080/healthz
curl -f localhost:18080/readyz # {"status":"ok","checks":[{"name":"database",...},{"name":"schema",...}]}
open http://localhost:18080    # sign in as dev@example.com / password (an admin), see "My account" and "Users"
make compose-down             # stop and drop volumes
```

Run the binary on the host instead of in Compose (Compose must be up for PostgreSQL, or unset `GATEWAY_DATABASE_URL` to run without a database):

```bash
cp .env.example .env          # edit as needed; every GATEWAY_ variable is documented there
set -a; . ./.env; set +a
make migrate                  # applies pending migrations as the owner (GATEWAY_MIGRATE_DATABASE_URL)
go run ./cmd/gateway
```

Configuration precedence is built-in defaults < the YAML file named by `GATEWAY_CONFIG_FILE` < individual `GATEWAY_*` variables. Ports are deliberately off the usual defaults (15432 / 15556 / 18080) so parallel checkouts and other local services do not collide.

Integration tests need a PostgreSQL **superuser** URL in `GATEWAY_TEST_DATABASE_URL` (they migrate up and down and give the two application roles a temporary password); they are skipped when it is unset:

```bash
make compose-up
export GATEWAY_TEST_DATABASE_URL='postgres://gateway:gateway-dev@localhost:15432/gateway?sslmode=disable'
make test-integration
```

## Database

The schema is one linear set of goose migrations embedded in the binaries (`internal/store/migrations`). `cmd/migrate` (`make migrate`, `make migrate-down`, `make migrate-status`, or `/migrate up` in the container image) runs them as the database owner before a rollout; the gateway never migrates itself and refuses to start, and reports not ready, when the database's version differs from `store.ExpectedSchemaVersion`.

Three roles, three connection strings:

| Role | Variable | Purpose |
|---|---|---|
| owner / superuser | `GATEWAY_MIGRATE_DATABASE_URL` | runs migrations; migration 00001 creates the two roles below (NOLOGIN; grant LOGIN and a password out of band, as [`deploy/postgres/init/01-roles.sql`](deploy/postgres/init/01-roles.sql) does for Compose) |
| `gateway_app` (NOBYPASSRLS) | `GATEWAY_DATABASE_URL` | the request path; `store.WithUser(ctx, userID, fn)` runs `fn` in a transaction after `SET LOCAL app.user_id` |
| `gateway_jobs` (BYPASSRLS) | `GATEWAY_JOBS_DATABASE_URL` | `store.WithJobs(ctx, fn)`: background workers, just-in-time user creation, admin metadata reads |

Isolation is enforced twice: repositories only exist on a transaction opened by `WithUser` or `WithJobs`, and every user-scoped table (`users`, `identities`, `sessions`, `role_assignments`, `user_restrictions`, `tokens`, `oauth_refresh_tokens`, `connections`, `connection_secrets`, `approvals`, `ledger_operations`, `ledger_attempts`, `audit_events`) has row-level security enabled and forced with a policy on `app_user_id()`, so a connection without a user scope sees and writes nothing. Global tables (`roles`, `policy_versions`, `oauth_clients`, `vendor_apps`, `signing_keys`, `job_locks`) have no policy. Secrets (vendor app client secrets, connection token bundles, approval payloads, signing private keys) are stored as the crypto package's four envelope-encryption columns and never appear in the `admin_*` views, which are `security_invoker` column projections. `audit_events` is append-only: `gateway_app` has no UPDATE/DELETE privilege and a statement-level trigger blocks UPDATE for everyone and DELETE unless the retention purge flags the transaction.

The Compose dex instance is a mock company identity provider: issuer `http://localhost:15556/dex`, static client `gateway` / `gateway-dev-secret`, static users `dev@example.com` (bootstrap admin), `alice@example.com` and `mallory@evil.test` (rejected by the domain allow-list), all with password `password` (see [`deploy/dex/config.yaml`](deploy/dex/config.yaml)). Dev credentials only.

## Sign-in, users and the portal

Coworkers sign in with the company identity provider; the gateway is an OIDC relying party ([zitadel/oidc](https://github.com/zitadel/oidc), authorization code + PKCE S256 + state + nonce) and never sees passwords. A user is created on first sign-in, identified by the provider's issuer and permanent `sub` claim, never by email, and there is no linking across providers (Brain decision `uamxx6ba`). Routes: `GET /auth/{provider}/start?return_to=/path`, `GET /auth/{provider}/callback`, `POST /auth/signout` (CSRF-protected). Pages: `/signin`, `/account`, `/tokens`, `/connections`, `/activity`, and for admins `/admin/users`, `/admin/roles`, `/admin/settings/default-role`, `/admin/vendor-apps`, `/admin/audit` (everyone else gets the same 404 as an unknown page). Templates and htmx are embedded in the binary (`internal/portal/templates`, `internal/portal/static`); there is no frontend build.

Providers are configured by `GATEWAY_OIDC_PROVIDERS` (comma-separated names) plus `GATEWAY_OIDC_<NAME>_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_DISPLAY_NAME`, and an allow-list: `_ALLOWED_DOMAINS` (hosted domain `hd` claim, else the verified email's domain; `_DOMAIN_CLAIM` picks another claim) and/or `_ALLOWED_TENANTS` (Entra `tid`). Every provider needs at least one allow-list; a sign-in from outside it is refused with a `403` page and an `identity.signin_rejected` log event (`reason=domain_not_allowed`, the domain, issuer and subject, never the email). The redirect URI to register at the provider is `GATEWAY_BASE_URL` + `/auth/<name>/callback`. `.env.example` has ready-made blocks for dex, Google Workspace, Microsoft Entra ID and Okta.

New users get the role flagged as default on `/admin/settings/default-role`, else `GATEWAY_DEFAULT_ROLE` (default `member`; the role row is created if missing). `GATEWAY_BOOTSTRAP_ADMINS` lists `issuer|subject` pairs that receive the `admin` role on every sign-in; the subject is logged on each sign-in (`event=identity.signin`) so it can be copied from the log. Admins list users, disable/enable them and assign any existing role at `/admin/users`; disabling revokes the user's sessions immediately and runs the hooks later modules register with `identity.Service.OnDisable` (tokens, OAuth sessions, app connections).

Sessions are server-side rows (`sessions`, hash of the cookie secret only), rotated on every sign-in, with an idle timeout (`GATEWAY_SESSION_IDLE_TIMEOUT`, 12h) and an absolute one (`GATEWAY_SESSION_ABSOLUTE_TIMEOUT`, 7d). Cookies are `HttpOnly`, `SameSite=Lax` and `Secure` unless `GATEWAY_SESSION_COOKIE_SECURE=false` (plain-http localhost only). Every POST carries a per-session CSRF token (`_csrf` field or `X-CSRF-Token` header; missing or wrong is `403`), `return_to` only accepts same-origin paths, and each sign-in records `users.last_company_sign_in_at` for the 30-day token rule. The in-flight sign-in state (state, nonce, PKCE verifier, return path) travels in a short-lived cookie HMAC-signed with a key derived from the provider's client secret, so any replica can finish a callback without sticky sessions.

### Local sign-in smoke (dex)

dex's issuer is `http://localhost:15556/dex` for the browser and the gateway alike; the Compose gateway resolves `localhost` to the Docker host as well (`extra_hosts: localhost:host-gateway`), so the same URL works from inside the container. Verified steps:

```bash
make compose-up
curl -fsS localhost:18080/readyz
# browser: http://localhost:18080 -> "Continue with Local dex" -> dev@example.com / password
#   -> /account shows roles admin, member; "Users" lists users, Disable/Enable, role select
# sign in again: the user is reused (users = 1) and the session rotated (one live session)
# mallory@evil.test / password -> 403 "not allowed"; gateway log: event=identity.signin_rejected reason=domain_not_allowed
# alice@example.com / password -> member; GET /admin/users -> 404
curl -X POST localhost:18080/auth/signout      # no session/CSRF token -> 403
docker compose logs gateway | grep identity.   # signin / signin_rejected / user_disabled events
make compose-down
```

The same flow can be scripted with curl: fetch `/auth/dex/start` with a cookie jar, POST `login`/`password` to the dex form `action`, and follow redirects back to `/account`. To run the gateway on the host instead (`go run ./cmd/gateway` with `.env`), keep Compose up for PostgreSQL and dex; no alias is needed there.

## Harness tokens

Signed-in users mint tokens at `/tokens` for harnesses that cannot do the MCP OAuth dance (or do not want to): OpenCode, Claude Code, scripts. A token is `mgw_<id>_<secret>`: the id is 8 random base62 characters stored in `tokens.public_id` and shown in lists and logs; the secret is 32 random bytes encoded as 43 base62 characters and stored only as its SHA-256 hash (`tokens.token_hash`). The full token is rendered exactly once, on the page that follows creation, together with ready-to-paste OpenCode (`opencode.json`) and Claude Code (`.mcp.json` / `claude mcp add`) snippets pointing at `GATEWAY_BASE_URL` + `/mcp` with `Authorization: Bearer <token>`. Lists show `mgw_<id>_…`.

Rules (decision `uamxx6ba`):

- **Expiry is required and at most 90 days** (default 30). There is no renewal; create a new token.
- **Sign-in freshness:** a user's tokens stop working when their last company sign-in is older than `GATEWAY_TOKEN_SIGNIN_MAX_AGE` (default `720h` = 30 days). The harness sees `401` with *"sign in to the portal to reactivate your tokens"*; signing in at the portal reactivates every token at once, nothing needs re-issuing.
- **Revocation is immediate** (button on `/tokens`); disabling a user revokes all their tokens in the same transaction (`identity.Service.OnDisable`).
- **Scope:** an optional allow-list of apps (`github`) and tools (`github.create_issue`) and a read-only flag narrow the token below what the user's role allows; policy combines both. `last_used_at` is recorded at most once a minute, best-effort.
- Authentication (`tokens.Service.Authenticate`, used by `tokens.BearerMiddleware` and the `/mcp` endpoint) does one lookup by public id through the bypass scope, a constant-time hash compare, then revocation, expiry, owner status and freshness. Every rejection increments `auth_failures_total{reason}` (`malformed`, `unknown`, `revoked`, `expired`, `user_disabled`, `signin_stale`, `rate_limited`) and logs `event=tokens.auth_failed reason=... public_id=...`; the secret is never logged (and the redacting logger would scrub it anyway). Failed authentications are rate limited per client IP (20 per minute, in memory) with `429` + `Retry-After`; a missing header is a plain `401` challenge and does not count.
- Each create and revoke is a `user` audit event (`/activity`) with `token_id` and `action` in the resource identity.

**Secret scanning.** The `mgw_` prefix is not registered with any scanner's built-in rules, so add a custom pattern (GitHub secret scanning custom pattern, gitleaks, trufflehog, pre-commit) wherever harness configs might be committed:

```
mgw_[A-Za-z0-9]{8}_[A-Za-z0-9]{43}
```

(`tokens.ScanPattern`; a unit test keeps it in sync with the generator.) A leaked token is bounded by its expiry and the 30-day freshness rule and can be revoked on `/tokens`.

## Connecting a harness

`/mcp` is a stateless [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) MCP endpoint (official [Go SDK](https://github.com/modelcontextprotocol/go-sdk) v1.8.0, `StreamableHTTPOptions{Stateless: true}`, decision `ysorv868`): every POST is authenticated and routed on its own, no `Mcp-Session-Id` is issued, any replica can serve any request, and `GET`/`DELETE` answer `405`. Responses are plain JSON (`JSONResponse: true`); the SDK client and every harness that speaks Streamable HTTP accept that. Server-initiated notifications are not used: a harness picks up new tools on its next `tools/list`.

Create a token at `/tokens` (see [Harness tokens](#harness-tokens)); the one-time page shows these snippets with the token filled in:

```jsonc
// OpenCode: opencode.json
{ "$schema": "https://opencode.ai/config.json",
  "mcp": { "gateway": { "type": "remote", "url": "https://gw.example.com/mcp", "enabled": true,
                        "headers": { "Authorization": "Bearer mgw_<id>_<secret>" } } } }
```

```jsonc
// Claude Code: .mcp.json
{ "mcpServers": { "gateway": { "type": "http", "url": "https://gw.example.com/mcp",
                               "headers": { "Authorization": "Bearer mgw_<id>_<secret>" } } } }
```

```bash
claude mcp add --transport http gateway https://gw.example.com/mcp --header "Authorization: Bearer mgw_<id>_<secret>"
curl -sS https://gw.example.com/mcp -H "Authorization: Bearer mgw_<id>_<secret>" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

What a harness sees:

- **401 without a token**, with `WWW-Authenticate: Bearer realm="mcp-gateway", resource_metadata="<GATEWAY_BASE_URL>/.well-known/oauth-protected-resource"` (RFC 9728; the metadata document itself ships with the OAuth task) so OAuth-capable harnesses can discover sign-in. A rejected token adds `error="invalid_token"` and the reason; the per-IP failure budget gives `429` + `Retry-After`.
- **`tools/list`** returns only the tools the compiled policy lists for the user and token (the user's roles and restrictions, narrowed by the token's allow-list and read-only flag; see [Policy](#policy)). A fresh deployment lists nothing until an admin grants tools to a role. Every tool's schema gains two optional string properties the gateway owns: `account` (which connected account to use when the user has several; decision `dovthftx`) and `approval_id` (retry a call after an approval; decision `s0p05diu`). They are stripped before the connector sees the arguments. The list is marked `cacheScope: private`.
- **`tools/call`** of a hidden or nonexistent tool returns the same JSON-RPC error (`-32602`, `unknown tool "<name>"`), byte for byte. A call policy denies is `-32003 denied by policy`; one that needs an approval is `-32005 approval required` (the approvals task adds the approval flow behind that answer). Pipeline failures (not found, denied, approval required, bad injected argument, account problems, rate limited) are JSON-RPC errors; errors a connector returns come back as tool results with `isError: true` after secret redaction, so the model can react. Read results carry `_meta["mcp-gateway/read"] = {"empty"|"partial"|"unavailable": true}` when the connector says so, which tells "no results" from "could not look".
- **Accounts** (decision `dovthftx`): every app has a generated read tool `<app>.list_accounts` returning the caller's connected accounts (`id`, `label` company|personal, `display_name`; never tokens). With exactly one account for the app the gateway picks it; with several, a call without `account` fails with `-32602 account required: ... set "account" to one of: <id> (<display name>, <label>), ...` listing only the caller's own; an `account` that is not the caller's (someone else's, nonexistent, or for another app) is `-32602 unknown account "<id>" for <app>`; with none, `-32004 no connected account for <app>`. The resolved account and label are on the audit row.
- **Rate limits** (decision `dovthftx`): token buckets per user (`GATEWAY_RATE_USER_PER_MIN`, default 60, every app together) and per vendor app across all users (`GATEWAY_RATE_APP_PER_MIN`, default 600); burst equals the per-minute rate. A refused call is `-32029 rate limited; retry in <n>s` with `error.data.retry_after` (whole seconds, rounded up). When a connector reports a vendor 429 (`connectors.RateLimited`), the harness gets `-32029 <app> is rate limiting this gateway; retry in <n>s` with the vendor's `Retry-After`, that app is paused for everyone until then, and `vendor_rate_limited_total{app}` is incremented.
- Request bodies above `GATEWAY_MCP_MAX_BODY` (default 1 MiB) get `413`.
- Every call is one `tool_call` audit event (`/activity`): tool, user, token, resource identity from the connector's hook, decision (allow / confirm / deny / hidden), policy version, outcome, latency, request ID, a short error class, never arguments or results.

The SDK's localhost DNS-rebinding guard is disabled on `/mcp`: the bearer token is the boundary (a browser cannot attach it), and the guard would `403` every request a reverse proxy on the same host forwards to `127.0.0.1` with the public `Host`.

## Policy

Roles are structured data (decision `490o45d0`): admins never write Cedar, and no page or endpoint accepts policy text. A role has a name, a description, **tool rules** and a **personal-account allowance** per app; `admin` is only a role name that unlocks the admin pages and grants no tools by itself (decision `uamxx6ba`).

- A **tool rule** names an app and a tool (or `*` for every tool of the app) and gives it an outcome: **allow** (the call runs), **confirm** (the user must approve each call first), **deny** (refused with `-32003`) or **hidden** (absent from `tools/list`; a call answers like an unknown tool). A rule may carry **conditions** on the resource identity the connector extracts from the arguments (`repo`, `channel`, `org`, ...): `equals`, `prefix`, or `glob` (`*` wildcard). All conditions of a rule must hold; a call whose resource identity lacks the key does not match.
- **Precedence.** A tool rule overrides the app's `*` rule, exactly where it applies: a conditional rule takes over when its condition matches and the wildcard remains the default otherwise ("allow github.\*, confirm github.create_issue when repo prefix acme/" confirms acme repos and allows the rest). Across roles and rules of equal specificity, deny beats confirm beats allow; hidden grants nothing, so another role can still grant the tool. An unconditional deny also hides the tool; a conditional deny leaves it listed.
- **Personal accounts** (decision `mh7c6z3v`): per app, a role says `allow` (the default), `confirm_writes` (every write tool on a personal account needs approval) or `deny` (refused on personal accounts).
- **Narrowing only** (decision `0ft3v5mh`): a user restriction (`user_restrictions`, same rule shape; no portal page yet) can hide, deny or confirm, never allow — an allow rule in a restriction is ignored and logged (`event=policy.restriction_ignored`). A token's allow-list and read-only flag narrow further and are evaluated per call.

The compiler (`internal/policy`, `Compile(roles, assignments, restrictions)`) emits one canonical Cedar document: `permit`/`forbid` statements over three action namespaces — `Action::"call"` (may run), `Action::"confirm"` (needs approval) and `Action::"list"` (visible) — with `principal in Role::"<name>"` for roles, `principal == User::"<id>"` for restrictions, `resource in App::"<app>"` / `resource == Tool::"<app.tool>"`, conditions as `when { context.resource has "repo" && context.resource["repo"] like "acme/*" }`, and two fixed forbids over `context.token` for the token scope. Every statement is annotated `@id("role/<role>/<app.tool>/<outcome>")` so a decision's reason (in the logs) names the rule. The **version** is the SHA-256 of the text, which also lists the role assignments, so a role edit or a re-assignment yields a new version. `Decide(Input{UserID, Roles, TokenID, TokenScope, Tool, AccountLabel, ResourceIdentity})` evaluates with cedar-go in the order decision `490o45d0` fixes: not listed → hidden; call forbidden or not permitted → deny; confirm permitted → confirm; else allow. Golden files under `internal/policy/testdata` (`*.json` role fixtures → `*.cedar`) pin the compiler's output; `go test ./internal/policy -update` rewrites them after review.

`policy.Service` loads roles, assignments and restrictions through the jobs scope, compiles, stores every new version in `policy_versions` (`version_hash`, `cedar`, `created_by` = the admin whose change produced it, NULL for the gateway's own reloads) and caches the result. Admin edits through the portal take effect at once on that replica; other replicas and role assignments made on `/admin/users` or at sign-in are picked up within `GATEWAY_POLICY_RELOAD_INTERVAL` (default `15s`), or at once for a user the compiled set has never seen. A reload failure keeps the last good policy; without any policy every call fails closed (`-32603`, class `policy_unavailable`). Decisions are counted in `policy_decisions_total{decision}`. The audit row's `policy_version_id`, and later approvals and ledger rows, reference the `policy_versions` row (`Decision.VersionID`), so an approval granted under an older version can be told apart from the version in force.

**Admin pages** (`/admin/roles`, `/admin/roles/new`, `/admin/roles/{name}`, `/admin/roles/{name}/delete`, `/admin/settings/default-role`; admins only, same 404 as an unknown page for everyone else, CSRF on every POST): the editor shows a tool grid built from the connector registry (one row per tool plus the app's `*` row, an outcome select each, a personal-account select per app) and a table of conditional rules (app, tool, outcome, key, match, value; one condition per row). Deleting a role that users still hold is refused. The default-role page flags the role new users receive (`roles.is_default`; the configured `GATEWAY_DEFAULT_ROLE` applies when none is flagged). Users are assigned roles on `/admin/users`. Every change is a `user` audit event under the admin (`action` = `role_saved` / `role_deleted` / `default_role_set`, `role`, the new `policy_version_id`) and compiles a new version.

Local smoke with the fake connector: sign in as `dev@example.com` (admin), open `/admin/roles/member`, set `fake.*` to `allow` and `fake.create_item` to `confirm`, save; a token's `tools/list` now shows the fake tools, `fake.list_items` runs and `fake.create_item` answers `-32005 approval required`.

## App connections

Decision `mh7c6z3v`: users connect **company and personal** accounts per vendor, each bound to the vendor's permanent account ID and labelled; admins decide per role whether personal accounts are allowed for an app; tokens are stored encrypted and never shown. The vendor registrations themselves (consoles, scopes, callback URLs) are in [`docs/vendor-apps.md`](docs/vendor-apps.md).

**Vendor apps** (`/admin/vendor-apps`, admins only, same 404 as an unknown page for everyone else): one registered app per vendor — `github`, `slack`, `atlassian`, `microsoft`, and two **variants** for `google`: `internal` (the Workspace client; company accounts) and `external` (the published-unverified app; personal accounts). The editor (`/admin/vendor-apps/{vendor}` or `/admin/vendor-apps/google/{internal|external}`) is prefilled with the vendor's documented endpoints and holds the client ID, the **client secret (write-only: encrypted under AAD `{kind: vendor_app, record: app id}`, never rendered; leave blank to keep)**, for Slack also the **Bot User OAuth token** and the **signing secret** (same write-only treatment; `VendorApp.Secrets` on write, `VendorApp.SecretKeys` on read says which are stored; all of an app's secrets are one envelope-encrypted JSON bundle in the row's four secret columns, rows written before the bundle existed still decrypt; `Service.VendorSecrets(ctx, vendor, variant, keys...)` returns values to the OAuth flow, the Slack notifier and `/slack/interactions`), authorization / token / user-info / revoke URLs, base scopes and extra parameters (`key=value` lines: authorization parameters such as `access_type=offline`, plus the binder hints `company_domains`, `default_label`, `scope_param`, `id_field`, `name_field`, `email_field`). Every save is a `user` audit event of the admin (`action=vendor_app_saved`, vendor, variant). The redirect URI to register at the vendor is `GATEWAY_BASE_URL` + `/connect/<vendor>/callback`.

**Connecting** (`/connections`): per vendor, the connected accounts (name, label, scopes, status, last refresh) with *Grant more access* (re-runs the flow with extra scopes; the connection keeps the union), *Reconnect* and *Disconnect*, and a *Connect* button per enabled app. `GET /connect/{vendor}/start?variant=&scopes=` stores the flow server-side (`connect_flows`: state, PKCE S256 verifier, requested scopes; bound to the user by row-level security, 10 minutes, one use, any replica can finish it) and redirects to the vendor; `GET /connect/{vendor}/callback` consumes the state, exchanges the code, asks the vendor's **`connections.Binder`** who the account is (`Bound{ExternalAccountID, DisplayName, Label, Scopes}`; `GenericBinder` reads the user-info JSON and labels by the app's `company_domains`; connector tasks register theirs with `Service.RegisterBinder`), refuses a **personal** account when every connector app of that vendor denies personal accounts for the user's roles (`PolicyAllowance`; deny wins across roles; the refusal is an audited `denied` event with class `personal_account_denied`), then upserts the connection by (user, app, external account ID) and stores the access + refresh tokens as one envelope-encrypted bundle under AAD `{user, kind: connection, record: connection id, app: vendor}`. Every connect and disconnect is a `user` audit event with the connection ID and label.

**Tokens.** `Service.TokenSource(ctx, userID, connectionID)` is the `oauth2.TokenSource` connectors use: `Token()` opens one user-scoped transaction, takes the connection row with `SELECT ... FOR UPDATE`, and refreshes only when the access token is within two minutes of expiry, so concurrent callers (and replicas) make **one** vendor call and share the result; a rotated refresh token is persisted; `invalid_grant` sets the connection to `needs_reconnect`, notifies the user through the `connections.Notifier` (log by default; the approvals task plugs in Slack/portal), increments `connection_refresh_failures_total{app}` and returns `connections.ErrNeedsReconnect`; transient vendor failures only count the metric. `Disconnect` revokes at the vendor when the app has a revoke URL (best effort), **deletes the `connection_secrets` row** and marks the connection `revoked` (the row stays: approvals, ledger and audit rows reference it; reconnecting revives it). Disabling a user runs the same for every connection inside the disabling transaction (`identity.Service.OnDisable`). `connections.KeepAliveJob` (`Name`, `Interval` = 24h, `Run`) refreshes tokens that have not been refreshed for 30 days and sweeps expired flows; the jobs runner registers it (TODO in `cmd/gateway/main.go`).

**Accounts.** `connections.Service` implements `connectors.AccountSource`: the user's `active` connections of the vendor an app uses (`Service.MapApp(app, vendor)`, e.g. `gmail` → `google`; unmapped apps are their own vendor), as `Account{ID: connection UUID, Label, DisplayName, App, Scopes}`. `cmd/gateway` routes app `fake` to the fake connector's own source and everything else to the connections table. Without a key provider (`GATEWAY_KEY_PROVIDER` / `GATEWAY_KEY_FILE`) the connections module is not mounted.

Tests: `internal/connections` runs an httptest vendor (authorize, token with PKCE and rotating refresh tokens, user info, revoke) through the service and the real portal; the integration suite (`gateway_connections_test`) proves the refresh race under `FOR UPDATE`, row-level security on connections, secrets and flows, AAD binding (a bundle moved to another connection or with a flipped byte fails to decrypt), `invalid_grant`, disconnect keeping audit rows, keep-alive, the disable hook, and scans every column of the four tables and the logs for any issued token or client secret.

### Writing a connector

A connector implements `connectors.Connector`: `App() string`, `Tools() []Tool`, `Call(ctx, Call) (Result, error)`. `Call` dispatches on `Call.Tool` and must return `connectors.ErrUnknownTool` for a name it does not serve; the tools returned by `Tools()` leave `Handler` nil and `connectors.RegisterConnector(registry, connector, accountSource)` binds them to `Call`, validates the contract and adds `<app>.list_accounts` (a tool that sets its own `Handler` keeps it). `Tool` carries `App, Name, Description, InputSchema (object), Kind (read|write), RequiredScopes, ResourceIdentity (never nil; returns a map, never argument content), Reconcile{Kind none|stable_id|client_id|marker, Check}` (every write declares a kind; `Check(ctx, ReconcileInput{Call, OperationID})` answers `found`/`not_found` or an error meaning "cannot tell yet"), and `Bounds{MaxPageSize, MaxResultBytes}` (requests above `MaxPageSize` are clamped). `Call.OperationID` is the ledger operation a write runs under, so a connector can derive a stable ID or marker from it. A vendor 429 is returned as `&connectors.RateLimited{App, RetryAfter}`; a write whose outcome the vendor did not confirm wraps `connectors.ErrOutcomeUnknown`. Run `connectortest.ContractTest(t, connector)` in the connector's tests: it checks names, descriptions, schemas (parsed; `account` and `approval_id` are reserved), kinds, reconciliation declarations, resource identity on sample arguments, bounds, `ErrUnknownTool`, and registration.

`connectors.AccountSource` (`ListAccounts(ctx, userID, app) ([]Account, error)`) is what the account stage and `list_accounts` consult; `StaticAccountSource` is the in-memory implementation and `connections.Service` the store-backed one. `Account{ID, Label company|personal, DisplayName, App, Scopes}` carries no tokens; a connector gets them through `connections.Service.TokenSource(ctx, call.Principal.UserID, call.Account)`.

**The fake connector** (`internal/connectors/fake`, app `fake`) is what the safety-core tests drive, and what `make compose-up` exposes (`GATEWAY_ENABLE_FAKE_CONNECTOR=true`; every user gets one make-believe company account on first use). Reads: `list_items` (paginated with `page_size`/`cursor`, honours bounds, optional `prefix`), `get_item`. Writes: `create_item` (reconciles by stable ID: the client-chosen `id`, else one derived from the operation), `post_note` (reconciliation `none`), `flaky_write` (reconciles by `marker`, defaulting to the operation ID). `fake.New(Options)`, `SeedAccount(userID, Account)`, `SeedItems`, `State().Items/Notes/Writes(account)`, and faults: `InjectFault(tool, Fault{Mode: FaultFail|FaultUnknown|FaultHang|FaultRateLimited|FaultPartial|FaultUnavailable, Latency, RetryAfter, Message, Applied, Remaining})`; `Faults()` returns the table (`fake.NewFaults()` is usable on its own). `FaultUnknown`/`FaultHang` with `Applied` perform the write before reporting the unknown outcome, so reconciliation finds it.

### Extending the pipeline

`internal/connectors.Registry` holds every `Tool` keyed by `app.tool`; `Register` enforces unique lower-case names, an object schema and non-negative bounds (connector-contract checks live in `RegisterConnector` and the contract test). `internal/mcp.DefaultPipeline(PipelineDeps{Registry, Visibility, RateLimiter, Accounts, Policy, Confirm, Audit, Metrics, Log})` builds the ordered stages `authenticate, audit, resolve, strip, account, policy, ratelimit, dispatch` (audit is second so it wraps every later outcome; `account` is present when `Accounts` is set, `policy` when `Policy` is); a `Stage` is `Name() string` + `Run(ctx, *CallContext, next)` and later modules add theirs with `pipeline.Insert(mcp.Before|mcp.After, mcp.StageRateLimit, stage)` in `cmd/gateway/newMCP`, filling `CallContext` fields (`AccountID`, `AccountLabel`, `Decision`, `PolicyVersion`, `ApprovalID`, `OperationID`) that the audit stage records. `mcp.Visibility` (`Visible(ctx, principal, tool)`) filters `tools/list` and resolve: `mcp.PolicyVisibility{Decider}` in production, `mcp.ScopeVisibility` (token scope only) in tests. The policy stage (`mcp.StagePolicy`, `PolicyStage(Decider, ConfirmHandler, log)`) asks the `mcp.Decider` (`policy.Service`: `Decide(ctx, policy.Input)`, `Visible(ctx, policy.Input)`) with the resolved tool, the account label and the resource identity, sets `CallContext.Decision` and `PolicyVersion`, and answers hidden (not-found), deny (`-32003`), allow (next) or confirm, which it hands to the `mcp.ConfirmHandler` hook (`Confirm(ctx, *CallContext, next)`); `mcp.DefaultConfirmHandler()` returns `mcp.ErrApprovalRequired` (`-32005 approval required`) and the approvals task supplies the real one through `PipelineDeps.Confirm`. `mcp.RateLimiter` (`Allow(ctx, userID, tool) (ok, retryAfter)`) is implemented by `mcp.NewRateLimiter(RateLimitConfig{UserPerMinute, AppPerMinute})`, a `TokenBucketLimiter` that also implements `AppPauser` (`Pause(app, retryAfter)`), which the ratelimit stage calls when a connector returns `connectors.RateLimited`. A `mcp.ToolError` has `Code`, `Message`, an audit class and an optional `RetryAfter` that reaches the wire as `error.data.retry_after`.

### Local /mcp smoke

Verified against `bin/gateway` and a token minted through the tokens service (the same code path as `/tokens`):

```bash
make build && export GATEWAY_DATABASE_URL=... GATEWAY_JOBS_DATABASE_URL=... GATEWAY_BASE_URL=http://localhost:18080
./bin/gateway &
T=mgw_...   # from /tokens
curl -s -D - -o /dev/null -X POST localhost:18080/mcp                      # 401 + WWW-Authenticate ... resource_metadata=...
curl -s localhost:18080/mcp -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
#  {"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":{}},"protocolVersion":"2025-11-25","serverInfo":{"name":"mcp-gateway","version":"..."}}}
curl ... -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'               # {"tools":[]} unless GATEWAY_ENABLE_FAKE_CONNECTOR=true (then the six fake.* tools)
curl ... -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"github.list_issues","arguments":{}}}'
#  {"error":{"code":-32602,"message":"unknown tool \"github.list_issues\""}}; log: event=mcp.tool_call decision=deny outcome=denied error_class=tool_not_found
# with the fake connector enabled:
curl ... -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fake.list_accounts","arguments":{}}}'
#  {"result":{"content":[{"type":"text","text":"{\"accounts\":[{\"id\":\"fake-...\",\"label\":\"company\",\"display_name\":\"Fake company account\"}]}"}],...}}
curl ... -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fake.create_item","arguments":{"id":"it-1","name":"first"}}}'
curl ... -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fake.list_items","arguments":{}}}'   # account auto-resolved: the user has one
curl -s -o /dev/null -w '%{http_code}' localhost:18080/mcp -H "Authorization: Bearer $T"   # 405
```

## Approvals

A tool call whose policy decision is **confirm** (a role rule, a personal-account allowance, or a user restriction) does not run until the user says so (decision `s0p05diu`). The pipeline's confirm handler (`approvals.ConfirmHandler`, behind `mcp.PipelineDeps.Confirm`):

1. **Stores the call** as a pending approval: user, token, account (a `connections` row), tool, the connector's resource identity, the policy version (`policy_versions` row id, quirk `zn4dw3q1`), the canonical argument digest (`approvals.Canonical`: sorted keys, no insignificant whitespace, HTML unescaped; `approvals.Digest` is its SHA-256) and the **full arguments, envelope-encrypted** (`crypto.Encrypt` with AAD `{user, "approval", approval id, app}`) — the one carve-out to "no app content stored". It expires after `GATEWAY_APPROVAL_TTL` (default `15m`).
2. **Waits** up to `GATEWAY_APPROVAL_WAIT` (default `30s`; keep it under the harness timeout, `0` disables, at most `5m`) for the user. Approved in time: the call completes in this round trip (`approvals_total{state="waited_through"}`). A decision made on the same replica wakes the waiter at once; one made elsewhere is seen within 500 ms (polling; no LISTEN/NOTIFY).
3. Otherwise answers `-32005` with `error.data = {approval_id, portal_url, expires_at, instructions}` and a message that repeats the id and the instruction: *ask the user to approve, then call this tool again with `approval_id=<id>`*.
4. On the **retry with `approval_id`** the approval is consumed and the **stored arguments run**; whatever the harness regenerated is ignored (LLM harnesses rarely reproduce arguments byte for byte). The approval must be bound to the same user, account, tool and policy version — an admin's role change after the approval produces a new version and the approval answers `-32003 approval does not match this call`, as does someone else's or an unknown id. One that was denied, already used or expired answers `-32003` with a message saying which; a retry while it is still pending waits again and answers with the same id. A retry **without** `approval_id` whose canonical arguments match an approved, unused approval consumes that one.
5. **Single use.** `Service.Consume(ctx, tx, Binding)` runs inside the caller's user-scoped transaction (`approvals.FromStoreTx(storeTx)` adapts a `store.Tx`; the ledger task will call it next to its `in_progress` insert, decision `dovthftx`) and is one conditional `UPDATE ... WHERE status='approved' AND consumed_at IS NULL AND expires_at > now()`, so concurrent retries with the same id yield exactly one winner; the losers get *already used*. `ConsumeNow` opens the transaction itself (the handler's path when no ledger is wired); with the ledger the handler defers consumption to the ledger stage (see [Write ledger](#write-ledger)).
6. **The payload never outlives the approval**: the four ciphertext columns are set to `NULL` by the consume, by a deny, and by the expiry job (`approvals.ExpiryJob`, every 30 s, `UPDATE ... SET status='expired'` for pending and approved rows past `expires_at`); migration 00010 lets an *approved* row keep its payload until it is consumed and adds `token_id` and `resource` for the history.

**Portal** (`/approvals`, signed-in users; mounted with `approvals.NewPortal(svc, session, log).Mount(p.MountUser)`): the pending list shows tool, account (display name and company/personal label), resource identity, the decrypted arguments as a summary (keys sorted, strings as they are, nested values as compact JSON, values cut at 200 characters) and a countdown to expiry, polled by htmx every 5 s; Approve/Deny are CSRF-protected POSTs (`/approvals/{id}/approve`, `/approvals/{id}/deny`; someone else's id is a 404, an already-decided one a notice); `/approvals/history` lists the last 50 without arguments. Approve and deny are `user` audit events (`action` = `approval_approved` / `approval_denied`, `tool`, `approval_id`), and every `tool_call` audit row of a confirmed call carries the `approval_id`. Transitions are counted in `approvals_total{state}` (`created`, `approved`, `denied`, `consumed`, `expired`, `waited_through`).

**Notifications** go through `approvals.Notifier` (`Notify(ctx, Approval)`): `PortalNotifier` (no-op: the row is the notification), `MultiNotifier` (fan-out, errors joined and logged, never failing the approval) and `SlackNotifier`. Without a key provider (`GATEWAY_KEY_PROVIDER` / `GATEWAY_KEY_FILE` unset) the approvals service is not built: confirmed calls answer a bare `-32005` and the portal has no approval pages.

**Slack** (decision `s0p05diu`): a user who has connected their **company** Slack account (an active `slack` connection labelled `company`; its external account id is `<team id>:<user id>`, `connections.SlackAccountID`) gets every pending approval as a DM from the gateway's Slack app with Approve / Deny buttons; everyone else is portal-only and nothing is sent. `approvals.NewSlackNotifier(SlackNotifierOptions{Identity, Secrets, PortalURL, ...})` takes `connections.Service` for both sources (`SlackIdentity(ctx, userID)` and `VendorSecrets(ctx, "slack", "", "bot_token")`), opens the DM (`conversations.open`) and posts a Block Kit message (`approvals.SlackApprovalBlocks`, pinned by `testdata/slack_dm.golden.json`): tool, account, resource identity, expiry, the argument summary (`Summarize`, cut to Slack's limits, fetched through `SlackNotifier.SetArguments(svc)` once the service exists) and two buttons whose `value` is the approval id; one notification is bounded by 5 s and any failure (no bot token, Slack down) is a logged `approvals.notify_failed`, never a failed approval. The button press reaches **`POST /slack/interactions`** (`internal/slack.NewInteractionsHandler`, mounted on the public mux outside the portal's session checks): the body is read and the `X-Slack-Signature` / `X-Slack-Request-Timestamp` pair is verified (`slack.VerifySignature`: v0 HMAC-SHA256 with the signing secret, timestamp within 5 minutes; stale or wrong is `401` before anything is parsed), the `block_actions` payload names the approval, `approvals.Service.Lookup` finds its owner across users, and the pressing Slack user **and** team must equal the owner's connected Slack identity, else `403` and a `denied` audit event of the owner (`action=approval_slack_rejected`, class `slack_user_mismatch`, the foreign Slack ids in the resource). Approve / Deny then go through the same `Service.Approve` / `Deny` as the portal (same audit events, same single use, same retry path), and the DM is updated (`chat.update`, bounded by 2 s) to "Approved by you at …" / "Denied …", or "already approved / used / expired" when the row moved first; an unknown id gets "expired". The response is `200` within Slack's 3 s budget. The bot token and signing secret live in the Slack vendor app (next section); with none the endpoint answers `401` and the notifier logs.

**Background jobs** (`internal/jobs`): `jobs.NewRunner(jobs.NewPostgresLocker(st), Options{Lease})` runs registered `Job{Name, Interval, Run}` on one replica. Each job is a row in `job_locks`: a replica takes the lease (one upsert, `expires_at <= now() OR holder = me`, database clock) when free or expired, a heartbeat renews it every `Lease/3` while the job runs (a lost lease cancels the job's context), and after the run the lease is kept for `Interval + Lease`, so the job stays on a healthy replica and moves within `Interval + Lease` when that replica dies; runs are spaced `Interval` apart, panics and errors are logged and retried next interval. `cmd/gateway` starts the runner with the approval expiry job; the reconciler, audit purge and token keep-alive register there too.

## Write ledger

Every write is recorded before it happens, duplicates are suppressed within the right scope, and unknown outcomes are resolved or surfaced instead of blocking forever (decision `dovthftx`). The ledger stage (`mcp.StageLedger`, between `policy` and `ratelimit`) applies to every write tool and to any call that carries an approval:

1. **Record first.** `ledger.Service.Begin(ctx, Intent)` inserts the `ledger_operations` row as `in_progress` (user, token, account, tool, policy version, the connector's resource identity, never the arguments) in **one transaction** that, for a confirmed call, also consumes the approval (`approvals.Service.LedgerConsumer`, decision `s0p05diu`): the single use and the row commit or roll back together, and the call then runs the approval's **stored** arguments. The confirm handler is in `DeferConsumption` mode whenever the ledger is wired; it still creates, waits for and answers approvals, but never consumes one itself.
2. **Idempotency scope.** A consumed approval's key is `approval:<id>` (an approval executes at most once, whatever the digest). An unconfirmed write's key is `digest:` + SHA-256 of user, account, tool and the canonical argument digest, valid inside `GATEWAY_LEDGER_IDEMPOTENCY_WINDOW` (default `24h`): the same arguments inside the window answer with the first operation's stored result IDs as the tool result (`{"_ledger": "replayed", "operation_id": ..., "result": {...}}`, audit class `replayed`) and the connector is not called; after the window they are a new operation. Concurrent attempts serialise on a per-key transaction advisory lock and a unique partial index on open keys (migration 00012), so exactly one inserts. While an earlier attempt is still `in_progress` or `unknown` the harness gets `-32006 pending verification` with `error.data.operation_id`; a `failed` or `unresolved` prior does not block.
3. **Outcomes.** After the call `Finish` records `succeeded` with the IDs the tool's `ResultIDs` hook extracted (identifiers and URLs only, at most 16 entries, keys ≤ 64 and values ≤ 512 bytes), `failed` with the error class, or `unknown` for `connectors.ErrOutcomeUnknown`, a deadline, a cancellation, a timeout or a reset connection; one `ledger_attempts` row per call. The outcome is written even when the request context was cut off by the drain. Transitions are counted in `ledger_operations_total{state}`.
4. **Reconciler** (`jobs.ReconcilerJob`, every minute, one replica): for each `unknown` operation of a tool that declares `Reconcile{Kind: stable_id|client_id|marker}` it calls `Check(ctx, ReconcileInput{Call, OperationID, ResourceIdentity})` — `Call.Args` is empty because arguments are never stored; connectors derive the stable id or marker from the resource identity and the operation id. `found` resolves to `succeeded` with the resource id, `not_found` to `failed`; an error means "cannot tell yet" and attempt *n* waits 2^(n−1) minutes. After `GATEWAY_LEDGER_MAX_RECONCILE_ATTEMPTS` (default 6) or `GATEWAY_LEDGER_MAX_RECONCILE_AGE` (default `24h`), and at once for `Reconcile{Kind: none}` or an unregistered tool, the operation is **`unresolved`**: the user is notified through `ledger.Notifier` (`LogNotifier` by default, `MultiNotifier` for fan-out; the Slack notifier is a separate task), an audit event records the verdict (outcome `unresolved`, class `not_reconcilable` / `reconcile_exhausted` / `reconcile_expired`), and the idempotency block is lifted so the user can deliberately retry after checking the app.
5. **Stale sweep and shutdown.** `jobs.StaleSweepJob` (every 30 s) turns `in_progress` rows older than `GATEWAY_LEDGER_STALE_AFTER` (default `2m`) into `unknown` (class `stale`): the replica that owned them died or was cut off. On shutdown, after the drain, the replica marks its own still-in-flight operations `unknown` (class `shutdown`) so the reconciler does not have to wait for the sweep. The `/mcp` handler also propagates HTTP request cancellation to tool handlers (protocol ≥ 2026-07-28), so a cut-off call stops instead of running on detached.
6. **Portal.** `GET /operations` lists the signed-in user's last 50 writes with state, result identifiers (URLs linked) and the *verify in the app* hint for unresolved ones.

Local smoke with the fake connector: `fake.create_item` twice with the same `id` and `name` inside a day replays (`_ledger: replayed`); `fake.post_note` after `InjectFault(FaultUnknown)` becomes `unresolved` on the next reconciler run and is listed on `/operations`. The fake's auto-seeded Compose accounts are not `connections` rows yet, so unconfirmed fake writes fail the `ledger_operations` insert in Compose until that is fixed (quirk `enqgtw5y`); the integration tests create the rows.

## Repository layout

```
cmd/gateway/            entry point: config, logging, store, routes, signal handling
cmd/migrate/            pre-upgrade job: goose up / down / down-to / status / version
internal/config/        GATEWAY_* env + optional YAML config loader
internal/server/        HTTP server lifecycle, bounded graceful drain
internal/observability/ slog bootstrap, /healthz, /readyz check registry (metrics later)
internal/identity/      users, sessions, company sign-in (OIDC relying party); identitytest/ in-memory store for tests
internal/authserver/    MCP OAuth 2.1 authorization server (RFC 8414/9728/8707)
internal/tokens/        generated mgw_ tokens: format, service, authenticator + BearerMiddleware, portal pages; tokenstest/ in-memory store
internal/policy/        structured roles compiled to versioned Cedar (cedar-go): model, compiler, Decide, service + cache, PostgreSQL store, admin role pages; policytest/ in-memory store; testdata/ golden files
internal/approvals/     durable confirmations with bounded wait; Slack DM notifier (notify_slack.go)
internal/slack/         POST /slack/interactions: signature verification, Approve/Deny button presses
internal/ledger/        write ledger: Begin/Finish, idempotency keys and window, reconciler + stale sweep, Notifier, /operations page; ledgertest/ in-memory store
internal/connections/   vendor apps (admin pages), OAuth connect flow (state + PKCE), Binder, encrypted tokens + serialized refresh (TokenSource), AccountSource, keep-alive job, connection pages; connectionstest/ in-memory store
internal/connectors/    connector contract (Connector, Tool, Account/AccountSource, Reconciliation, Bounds, RateLimited), registry, RegisterConnector; connectortest/ contract test; fake/ in-process test connector; github, slack, atlassian, google, microsoft later
internal/audit/         append-only audit events
internal/store/         pgx pools, WithUser / WithJobs scopes, repositories, schema check
internal/store/migrations/  embedded goose SQL migrations and their runner
internal/crypto/        key provider interface, envelope encryption
internal/mcp/           /mcp stateless Streamable HTTP endpoint (go-sdk), Visibility, the staged tools/call pipeline, account stage, policy stage + ConfirmHandler hook, token-bucket rate limiter
internal/portal/        embedded server-rendered portal (templates/ + static/htmx, CSRF, role gating)
internal/jobs/          single-replica background workers (runner + locker; ReconcilerJob, StaleSweepJob)
deploy/dex/             dex configuration for Compose
deploy/postgres/init/   Compose-only role bootstrap (dev passwords)
docs/plans/             design documents
```

Each `internal/*` package has a `doc.go` stating what it owns and which design sections and decisions it implements.

## Development

- `make fmt` / `make fmt-check`, `make lint`, `make test`, `make test-integration`, `make build`.
- `make migrate` / `make migrate-down` / `make migrate-status` wrap `cmd/migrate`; migrations run as a pre-upgrade job, the service never migrates itself. Adding a migration means adding `internal/store/migrations/NNNNN_name.sql` **and** bumping `store.ExpectedSchemaVersion`; a unit test fails if they disagree.
- Expected-failure assertions against PostgreSQL (an RLS violation, a bad enum) must run in their own `WithUser` transaction: PostgreSQL aborts the transaction on the first error.
- Lookups that precede user resolution (identity by issuer+subject, session by hash, just-in-time user creation, admin actions) run through `store.WithJobs`; self-service reads run through `store.WithUser`. Package-level helpers for these live in `internal/store/repo_identity_lookup.go`.
- The identity, audit, tokens, mcp, policy and connections integration tests use their own databases (`gateway_identity_test`, `gateway_audit`, `gateway_tokens_test`, `gateway_mcp_test`, `gateway_policy_test`, `gateway_connections_test`, created on demand) so they never race the store tests' `TRUNCATE`; every bootstrap retries `ALTER ROLE` on `tuple concurrently updated`, since the packages run in parallel against the same cluster-global roles.
- Dependency pins: zitadel/oidc v3.51.8 (v3.51.9+ requires Go 1.26, like goose v3.28.0 and prometheus/client_golang v1.25.0); modelcontextprotocol/go-sdk v1.8.0 (declares `go 1.25.0`; check the directive before bumping); cedar-policy/cedar-go v1.8.0 (declares `go 1.23.0`); golang.org/x/oauth2 v0.36.0 (v0.37.0 requires Go 1.26); slack-go/slack v0.29.0 (v0.30.0+ requires Go 1.26); htmx v2.0.8 is vendored under `internal/portal/static` (see THIRD_PARTY_NOTICES.md).
- Shutdown: on SIGTERM the server stops accepting connections, waits up to `GATEWAY_DRAIN_TIMEOUT` (default 25s) for in-flight requests, then cancels their contexts and closes them. Keep the orchestrator's termination grace period above the drain timeout.
- Third-party code: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) before adapting anything.
- CI (`.github/workflows/ci.yml`) runs gofmt, golangci-lint, unit tests, integration tests against a PostgreSQL 16 service container and a container image smoke test.

## History

The repository started as a ~1,300-line Python prototype (FastAPI, SQLAlchemy, Alembic, Kustomize manifests). It was removed when the Go foundation landed; the last prototype revision is commit `b6ad1b4` (`git show b6ad1b4`). Its Jira/Confluence tests (`tests/test_atlassian.py`) and connector (`src/mcp_gateway/atlassian.py`) remain useful references for the Atlassian connector.
