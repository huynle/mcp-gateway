# MCP Gateway

A self-hosted, always-on [MCP](https://modelcontextprotocol.io) gateway that sits in front of every app a team's AI harnesses use. Coworkers sign in with their company account, connect their own app accounts (GitHub, Slack, Atlassian, Google Workspace, Microsoft 365), and point any harness (OpenCode, Claude Code, Claude Desktop, ...) at one endpoint using a generated token or MCP OAuth sign-in. Every tool call is filtered by role, checked by policy, optionally confirmed by the user, recorded in a write ledger and audited. One deployment serves one company. The design lives in Brain plan `36bakiw8` (*Team MCP Gateway v1 design*, revision 2) and its linked decisions; the earlier single-user design is in [`docs/plans/`](docs/plans/).

## Status

Foundation, data layer and sign-in: Go module, configuration, structured logging, `/healthz`, `/readyz` (`database` and `schema` checks), graceful shutdown, the full v1 PostgreSQL schema as goose migrations, a repository layer scoped per user, row-level security as the second isolation layer, the envelope-encryption key provider, company sign-in through any configured OIDC provider (dex locally; Google, Entra, Okta) with just-in-time users, server-side sessions, the embedded portal shell (sign-in, my account, admin users, activity, audit search), and generated harness tokens (`mgw_...`) with their authenticator. `/mcp`, OAuth for harnesses and connectors land in the tasks that follow (Brain feature `team-mcp-gateway-v1`).

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

Coworkers sign in with the company identity provider; the gateway is an OIDC relying party ([zitadel/oidc](https://github.com/zitadel/oidc), authorization code + PKCE S256 + state + nonce) and never sees passwords. A user is created on first sign-in, identified by the provider's issuer and permanent `sub` claim, never by email, and there is no linking across providers (Brain decision `uamxx6ba`). Routes: `GET /auth/{provider}/start?return_to=/path`, `GET /auth/{provider}/callback`, `POST /auth/signout` (CSRF-protected). Pages: `/signin`, `/account`, `/admin/users` (admins only; everyone else gets the same 404 as an unknown page). Templates and htmx are embedded in the binary (`internal/portal/templates`, `internal/portal/static`); there is no frontend build.

Providers are configured by `GATEWAY_OIDC_PROVIDERS` (comma-separated names) plus `GATEWAY_OIDC_<NAME>_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_DISPLAY_NAME`, and an allow-list: `_ALLOWED_DOMAINS` (hosted domain `hd` claim, else the verified email's domain; `_DOMAIN_CLAIM` picks another claim) and/or `_ALLOWED_TENANTS` (Entra `tid`). Every provider needs at least one allow-list; a sign-in from outside it is refused with a `403` page and an `identity.signin_rejected` log event (`reason=domain_not_allowed`, the domain, issuer and subject, never the email). The redirect URI to register at the provider is `GATEWAY_BASE_URL` + `/auth/<name>/callback`. `.env.example` has ready-made blocks for dex, Google Workspace, Microsoft Entra ID and Okta.

New users get `GATEWAY_DEFAULT_ROLE` (default `member`; the role row is created if missing). `GATEWAY_BOOTSTRAP_ADMINS` lists `issuer|subject` pairs that receive the `admin` role on every sign-in; the subject is logged on each sign-in (`event=identity.signin`) so it can be copied from the log. Admins list users, disable/enable them and assign any existing role at `/admin/users`; disabling revokes the user's sessions immediately and runs the hooks later modules register with `identity.Service.OnDisable` (tokens, OAuth sessions, app connections).

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
internal/policy/        structured roles compiled to versioned Cedar
internal/approvals/     durable confirmations with bounded wait
internal/ledger/        write intent, idempotency, outcomes, reconciler
internal/connections/   per-user app accounts, envelope-encrypted tokens
internal/connectors/    connector interface; fake, github, slack, atlassian, google, microsoft
internal/audit/         append-only audit events
internal/store/         pgx pools, WithUser / WithJobs scopes, repositories, schema check
internal/store/migrations/  embedded goose SQL migrations and their runner
internal/crypto/        key provider interface, envelope encryption
internal/mcp/           /mcp stateless Streamable HTTP endpoint and the call pipeline
internal/portal/        embedded server-rendered portal (templates/ + static/htmx, CSRF, role gating)
internal/jobs/          single-replica background workers
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
- The identity, audit and tokens integration tests use their own databases (`gateway_identity_test`, `gateway_audit`, `gateway_tokens_test`, created on demand) so they never race the store tests' `TRUNCATE`.
- Dependency pins: zitadel/oidc v3.51.8 (v3.51.9+ requires Go 1.26, like goose v3.28.0); htmx v2.0.8 is vendored under `internal/portal/static` (see THIRD_PARTY_NOTICES.md).
- Shutdown: on SIGTERM the server stops accepting connections, waits up to `GATEWAY_DRAIN_TIMEOUT` (default 25s) for in-flight requests, then cancels their contexts and closes them. Keep the orchestrator's termination grace period above the drain timeout.
- Third-party code: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) before adapting anything.
- CI (`.github/workflows/ci.yml`) runs gofmt, golangci-lint, unit tests, integration tests against a PostgreSQL 16 service container and a container image smoke test.

## History

The repository started as a ~1,300-line Python prototype (FastAPI, SQLAlchemy, Alembic, Kustomize manifests). It was removed when the Go foundation landed; the last prototype revision is commit `b6ad1b4` (`git show b6ad1b4`). Its Jira/Confluence tests (`tests/test_atlassian.py`) and connector (`src/mcp_gateway/atlassian.py`) remain useful references for the Atlassian connector.
