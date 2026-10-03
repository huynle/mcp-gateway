# Personal MCP Gateway v1 design and implementation plan

Date: 2026-10-03

## Objective

Evolve the existing `mcp-gateway` repository into an independently deployed,
always-on personal MCP gateway. The first production provider is Google, initially
supporting Calendar, Tasks, Gmail, Drive, Docs, Sheets, People, and a gated Keep
compatibility connector. The architecture must also admit third-party MCP servers
without weakening the authorization, policy, audit, or idempotency boundary.

Supernote becomes a restricted gateway client only after parity, shadow reads,
rollback rehearsal, and explicit acceptance. Its current Google integration remains
authoritative until then.

## Existing repository disposition

The target already exists at `/Users/huy/projects/mcp-gateway`, with GitHub remote
`git@github.com:huynle/mcp-gateway.git` and initial commit `b21ab04`. It contains a
Python/FastAPI/SQLAlchemy prototype, Alembic schema, Jira and Confluence connectors,
tests, CI, and Kubernetes manifests.

Preserve that history. Do not reinitialize or replace the repository. Treat current
Jira/Confluence support as input to the later federation layer. Existing claims of
production readiness are not acceptance evidence for OAuth 2.1, current MCP
Streamable HTTP, multi-account Google access, confirmation, idempotency, or homelab
deployment.

## Architecture

Implement a modular Python monolith using the official MCP Python SDK. One gateway
core owns protocol handling, client authentication, account selection, authorization,
per-tool policy, confirmation, rate limits, operation state, and audit. Native Google
connectors use shared provider contracts. A separate federation adapter imports tools
from explicitly registered upstream MCP servers under stable namespaces.

The service exposes two routing surfaces:

- Private LAN/Tailscale: administration, account enrollment, approvals, audit,
  metrics, and MCP access.
- Public HTTPS: OAuth metadata and an explicitly published subset of MCP tools.

Public exposure is deny-by-default. Private networking supplements rather than
replaces application authentication.

Use PostgreSQL in production. Start with one application process until session,
confirmation, refresh locking, and operation semantics are proven across replicas.

## Repository layout

All implementation stays under `/Users/huy/projects/mcp-gateway`:

```text
src/mcp_gateway/
  domain/          clients, accounts, grants, policies, approvals, operations
  application/     authorize, discover, execute, confirm, reconcile
  auth/            OAuth resource server, JWT validation, static tokens, scopes
  mcp/             official SDK composition, transport, errors, context
  google/          auth, identity, scopes, shared transport, service connectors
  federation/      upstream registry, discovery, client, policy projection
  persistence/     async database, models, repositories, locks, encryption
  api/             private admin/enrollment/approval/health surfaces
  observability/   redacted logging, metrics, tracing, audit projection
migrations/        one linear Alembic head, owned by foundation tasks
tests/             unit, contract, integration, security, concurrency, provider
deploy/            immutable release, systemd, Traefik, smoke and rollback tooling
docs/              architecture, threat model, authorization and operations
scripts/           operator-only enrollment, token, key and reconciliation commands
```

Parallel connector tasks own only their provider modules and matching tests. Shared
models, scope registries, migrations, MCP composition, dependency locks, and fixtures
have one owner at a time.

## Identity and authorization

Each request is authorized by the intersection of:

1. authenticated client identity;
2. inbound OAuth/static-token scopes;
3. explicit client-to-account grant;
4. enabled account and connector;
5. tool grant and resource allowlist;
6. provider scopes actually granted;
7. per-tool `allow`, `confirm`, or `deny` policy;
8. argument-level restrictions.

Writes always name an immutable account ID. Email and display names are never account
identities. Supernote receives its own client identity and only bounded context tools.

For public MCP, implement the current MCP OAuth resource-server contract: protected
resource metadata, authorization-server discovery, Authorization Code with S256 PKCE,
resource indicators, exact issuer/audience/signature/expiry validation, and proper
scope challenges. Prefer an existing homelab identity provider; do not build a custom
authorization server into the gateway.

Static tokens are independently scoped client credentials with hashed storage,
expiry, revocation, network restrictions, last-use tracking, and overlapping rotation.
Secrets are returned once and never accepted in URLs or logs.

## Confirmation and write safety

`confirm` creates a durable approval, not an LLM prompt. The approval binds client,
account, tool/version, canonical argument digest, effect summary, policy version,
expiry, and approving principal. Execution rechecks policy and consumes it atomically.
Any changed argument or policy invalidates approval.

Every mutation records a durable operation before contacting a provider. Idempotency
keys bind client, account, tool, and canonical request digest. Definite failures may
be retried according to provider rules; uncertain outcomes are never retried blindly.
Provider-specific reconciliation uses stable IDs, request IDs, revisions, ETags, or
exact payload evidence. Database restoration is not treated as rollback of external
effects.

## Google accounts and credentials

Enroll each Google account independently and bind it to the immutable Google subject.
Request service scopes incrementally; adding Gmail cannot widen a Calendar-only grant.
Resource enrollment uses canonical IDs and explicit allowlists.

Credentials use versioned envelope encryption with AEAD associated data. Root key
material stays outside the database and source tree. Refresh is serialized per account.
Revocation disables access without deleting audit or operation history. Existing
Supernote credentials are not copied through source, Brain, logs, chat, or task
context; migration, if chosen, is a separate reviewed operation.

Scope bundles remain distinct for Calendar, Tasks, Gmail, Drive, People, Docs, Sheets,
and Keep, with read and write scopes separated wherever the provider allows it.

## Connector plan

- Calendar and Tasks: preserve all-day, recurrence, due-date, completeness, and
  pagination semantics already proven in Supernote; add guarded writes.
- Gmail: separate metadata/read/modify/compose/send; sending requires durable
  draft/send identity and duplicate-send protection.
- Drive, Docs, Sheets: share Drive file identity, explicit file allowlists,
  revisions/ETags, update masks, and conditional writes.
- People: stable resource names, update masks, ETags, and read/write separation.
- Keep: run a read-only Workspace eligibility and API feature spike. Full Keep parity
  is not promised. If required behavior needs unsupported UI features, mark it
  unsupported rather than scraping, automating browsers, or copying cookies.

Provider reads must distinguish empty, partial, stale, and unavailable results.
Bound response bytes, pages, durations, and concurrency. Safe reads may use bounded
backoff; writes follow operation-ledger semantics.

## Persistence and migrations

Foundation entities include principals, OAuth clients, static tokens, accounts,
client-account grants, encrypted credentials, provider grants, resource allowlists,
tool definitions/policies, approvals, operations/attempts, audit events, federated
servers, and federated tool snapshots.

Use one linear migration head and one migration owner. Production startup checks but
does not mutate schema. A one-shot migration unit acquires a deployment lock. Test
upgrade from each supported release. Prefer forward fixes; destructive downgrade is
not an operational rollback. Foreign keys must not cascade-delete audit or operation
history.

## Observability and privacy

Structured logs may include request ID, pseudonymous client/account IDs, tool, policy
decision, operation ID, outcome, and latency. Never log tokens, OAuth codes/URLs,
provider bodies, message/document content, or raw tool arguments. A shared redaction
layer requires adversarial tests.

Metrics cover request latency, authentication failures, policy decisions, approvals,
quota/429 responses, uncertain operations, credential refresh failures, audit failures,
and connector availability. Metrics and detailed readiness remain private. Liveness
does not refresh Google grants.

## Deployment and rollback

The initial homelab target is a dedicated systemd service behind Traefik and
Tailscale, unless host inventory proves a better existing platform. Recommended
production paths are:

- `/opt/mcp-gateway/releases/<version>-<commit>` and `/opt/mcp-gateway/current`
- `/var/lib/mcp-gateway`
- `/etc/mcp-gateway/gateway.env`
- `/etc/mcp-gateway/credential.key`
- `/etc/systemd/system/mcp-gateway.service`
- `/etc/systemd/system/mcp-gateway-migrate.service`
- `/docker/amos/traefik2/rules/app-mcp-gateway-private.yml`
- `/docker/amos/traefik2/rules/app-mcp-gateway-public.yml`

Deployment must not modify `/opt/snhub`, `/opt/snhub-product`, `/var/lib/snhub`,
`/etc/snhub`, existing Supernote routes, locks, receipts, or holds. Production and
Supernote cutover require explicit approval tasks. Retain previous immutable releases;
only roll code back when schema-compatible.

## Verification and acceptance

Required suites include policy/deny precedence, explicit account binding, token
rotation/revocation, encryption key rotation, approval expiry and single use,
idempotency conflicts, provider pagination/bounds, redaction, PostgreSQL migrations,
concurrent refresh and writes, uncertain-outcome reconciliation, and OAuth metadata.

MCP contract tests cover initialization, protocol versions, notifications,
Streamable HTTP GET/POST/SSE behavior, tool filtering, errors, sessions, cancellation,
disconnects, and intended OpenCode/Supernote clients.

Live Google tests use dedicated non-sensitive resources and remain separately gated.
Supernote cutover requires restricted-client parity, shadow comparison, write-denial
and confirmation tests, rollback rehearsal, and explicit user acceptance.

## Dependency graph

All Brain implementation tasks use feature ID `personal-mcp-gateway-v1`, target
`/Users/huy/projects/mcp-gateway`, and worktree execution. The graph is:

```text
baseline
├── repository-foundation
│   └── mcp-conformance
├── persistence
│   ├── credentials-and-enrollment
│   └── audit-observability
├── mcp-conformance + persistence → client-auth
├── client-auth + persistence → policy-and-approvals
├── policy-and-approvals + persistence → operation-ledger
├── credentials + policy + operations → google-adapter
│   ├── calendar-tasks
│   ├── gmail
│   ├── drive-docs-sheets
│   ├── people
│   └── keep-spike
├── connector tasks → google-composition
├── mcp + auth + policy + operations → federation
├── foundation + persistence + auth + observability → deployment-package
├── composition + federation + observability + deployment → security-acceptance
└── security-acceptance → supernote-contract → staging gate → production/cutover gates
```

Production deployment and Supernote cutover tasks remain draft/manual gates rather
than automatically runnable work.
