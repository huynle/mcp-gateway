# MCP Gateway

A self-hosted, always-on [MCP](https://modelcontextprotocol.io) gateway that sits in front of every app a team's AI harnesses use. Coworkers sign in with their company account, connect their own app accounts (GitHub, Slack, Atlassian, Google Workspace, Microsoft 365), and point any harness (OpenCode, Claude Code, Claude Desktop, ...) at one endpoint using a generated token or MCP OAuth sign-in. Every tool call is filtered by role, checked by policy, optionally confirmed by the user, recorded in a write ledger and audited. One deployment serves one company. The design lives in Brain plan `36bakiw8` (*Team MCP Gateway v1 design*, revision 2) and its linked decisions; the earlier single-user design is in [`docs/plans/`](docs/plans/).

## Status

Foundation only: Go module, configuration, structured logging, `/healthz`, `/readyz` (check registry; nothing registered yet) and graceful shutdown. The store, key provider, sign-in, tokens, `/mcp` endpoint, portal and connectors land in the tasks that follow (Brain feature `team-mcp-gateway-v1`).

## Run locally

Requirements: Go 1.25, Docker with Compose v2, [golangci-lint](https://golangci-lint.run) v2 for `make lint`.

```bash
make build test lint          # bin/gateway, unit tests (race detector), lint
make compose-up               # PostgreSQL 16 (15432), dex (15556), gateway (18080)
curl -f localhost:18080/healthz
curl -f localhost:18080/readyz
make compose-down             # stop and drop volumes
```

Run the binary on the host instead of in Compose:

```bash
cp .env.example .env          # edit as needed; every GATEWAY_ variable is documented there
set -a; . ./.env; set +a
go run ./cmd/gateway
```

Configuration precedence is built-in defaults < the YAML file named by `GATEWAY_CONFIG_FILE` < individual `GATEWAY_*` variables. Ports are deliberately off the usual defaults (15432 / 15556 / 18080) so parallel checkouts and other local services do not collide.

Integration tests need PostgreSQL and read `GATEWAY_TEST_DATABASE_URL`; they are skipped when it is unset:

```bash
make compose-up
export GATEWAY_TEST_DATABASE_URL='postgres://gateway:gateway-dev@localhost:15432/gateway?sslmode=disable'
make test-integration
```

The Compose dex instance is a mock company identity provider: issuer `http://localhost:15556/dex`, static client `gateway` / `gateway-dev-secret`, static user `dev@example.com` / `password` (see [`deploy/dex/config.yaml`](deploy/dex/config.yaml)). Dev credentials only.

## Repository layout

```
cmd/gateway/            entry point: config, logging, routes, signal handling
internal/config/        GATEWAY_* env + optional YAML config loader
internal/server/        HTTP server lifecycle, bounded graceful drain
internal/observability/ slog bootstrap, /healthz, /readyz check registry (metrics later)
internal/identity/      users, sessions, company sign-in (OIDC relying party)
internal/authserver/    MCP OAuth 2.1 authorization server (RFC 8414/9728/8707)
internal/tokens/        generated mgw_ tokens
internal/policy/        structured roles compiled to versioned Cedar
internal/approvals/     durable confirmations with bounded wait
internal/ledger/        write intent, idempotency, outcomes, reconciler
internal/connections/   per-user app accounts, envelope-encrypted tokens
internal/connectors/    connector interface; fake, github, slack, atlassian, google, microsoft
internal/audit/         append-only audit events
internal/store/         PostgreSQL, goose migrations, row-level security
internal/crypto/        key provider interface, envelope encryption
internal/mcp/           /mcp stateless Streamable HTTP endpoint and the call pipeline
internal/portal/        embedded server-rendered portal (templates + htmx)
internal/jobs/          single-replica background workers
deploy/dex/             dex configuration for Compose
docs/plans/             design documents
```

Each `internal/*` package has a `doc.go` stating what it owns and which design sections and decisions it implements.

## Development

- `make fmt` / `make fmt-check`, `make lint`, `make test`, `make test-integration`, `make build`.
- `make migrate` is a placeholder until the store task adds goose migrations; migrations run as a pre-upgrade job, the service never migrates itself.
- Shutdown: on SIGTERM the server stops accepting connections, waits up to `GATEWAY_DRAIN_TIMEOUT` (default 25s) for in-flight requests, then cancels their contexts and closes them. Keep the orchestrator's termination grace period above the drain timeout.
- Third-party code: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) before adapting anything.
- CI (`.github/workflows/ci.yml`) runs gofmt, golangci-lint, unit tests, integration tests against a PostgreSQL 16 service container and a container image smoke test.

## History

The repository started as a ~1,300-line Python prototype (FastAPI, SQLAlchemy, Alembic, Kustomize manifests). It was removed when the Go foundation landed; the last prototype revision is commit `b6ad1b4` (`git show b6ad1b4`). Its Jira/Confluence tests (`tests/test_atlassian.py`) and connector (`src/mcp_gateway/atlassian.py`) remain useful references for the Atlassian connector.
