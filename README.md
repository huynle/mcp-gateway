# MCP Gateway

Production-oriented MCP gateway for agent harnesses. It exposes a single MCP Streamable HTTP endpoint, filters the advertised tools for each authenticated user, denies ungranted `tools/call` requests server-side, brokers per-user credentials to downstream MCP servers, and records audit logs for every MCP access decision.

The implementation was shaped by the same primitives Prefect Horizon describes publicly: a registry of MCP servers, a gateway that enforces authentication/RBAC/audit at the infrastructure layer, and scoped tool composition so agents only see the capabilities they should use.

## What Is Included

- `POST /mcp`: MCP JSON-RPC endpoint for agent harnesses.
- Admin REST API for users, MCP server registration, grants, revocation, tool refresh, and audit reads.
- User REST API for setting per-server credentials such as Atlassian URL, email, and PAT.
- Built-in server registry entries for first-party `jira` and `confluence`.
- Separate first-party Jira and Confluence MCP server apps.
- Encrypted credential storage using Fernet.
- SQLite for local development, PostgreSQL-ready SQLAlchemy configuration for Kubernetes.
- Alembic migrations run by a Kubernetes init container before gateway pods serve traffic.
- Prometheus metrics at `/metrics`.
- Non-root, read-only-root-filesystem Kubernetes pod posture.
- Kustomize base and local overlay.

## Local Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Run the gateway:

```bash
export GATEWAY_ADMIN_TOKEN=local-admin-token
export GATEWAY_SECRET_KEY=local-secret-key
export GATEWAY_ENCRYPTION_KEY=WpB-6_RzIvz2FZMfNfyWuIYfJ3VAwJvA9SRuB7rj2rw=
uvicorn mcp_gateway.app:create_gateway_app --factory --reload --port 8000
```

Run first-party MCP servers in mock mode:

```bash
ATLASSIAN_MOCK=true uvicorn mcp_gateway.atlassian:create_jira_app --factory --port 8101
ATLASSIAN_MOCK=true uvicorn mcp_gateway.atlassian:create_confluence_app --factory --port 8102
```

Register local first-party server URLs:

```bash
curl -sS -X POST http://localhost:8000/api/admin/servers \
  -H 'authorization: Bearer local-admin-token' \
  -H 'content-type: application/json' \
  -d '{"slug":"jira","display_name":"Jira","url":"http://localhost:8101/mcp","first_party":true,"credential_header_map":{"base_url":"X-Atlassian-Base-Url","pat":"X-Atlassian-Token","email":"X-Atlassian-Email"}}'

curl -sS -X POST http://localhost:8000/api/admin/servers \
  -H 'authorization: Bearer local-admin-token' \
  -H 'content-type: application/json' \
  -d '{"slug":"confluence","display_name":"Confluence","url":"http://localhost:8102/mcp","first_party":true,"credential_header_map":{"base_url":"X-Atlassian-Base-Url","pat":"X-Atlassian-Token","email":"X-Atlassian-Email"}}'
```

Create a user, grant access, and set that user's Atlassian PAT:

```bash
USER_JSON=$(curl -sS -X POST http://localhost:8000/api/admin/users \
  -H 'authorization: Bearer local-admin-token' \
  -H 'content-type: application/json' \
  -d '{"external_id":"alice","display_name":"Alice"}')

USER_ID=$(python -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<< "$USER_JSON")
USER_TOKEN=$(python -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<< "$USER_JSON")

curl -sS -X POST http://localhost:8000/api/admin/policies \
  -H 'authorization: Bearer local-admin-token' \
  -H 'content-type: application/json' \
  -d "{\"user_id\":\"$USER_ID\",\"server_slug\":\"jira\",\"tool_name\":\"search_issues\"}"

curl -sS -X POST http://localhost:8000/api/users/me/credentials/jira \
  -H "authorization: Bearer $USER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"config":{"base_url":"https://your-domain.atlassian.net","email":"alice@example.com","pat":"ATATT..."}}'
```

List the user's MCP tools:

```bash
curl -sS -X POST http://localhost:8000/mcp \
  -H "authorization: Bearer $USER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Call an allowed tool:

```bash
curl -sS -X POST http://localhost:8000/mcp \
  -H "authorization: Bearer $USER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"jira__search_issues","arguments":{"jql":"project = TEST","max_results":5}}}'
```

## API Model

Admin APIs require the admin bearer token or an admin user token:

- `POST /api/admin/users`: create a user and return a one-time API token.
- `PATCH /api/admin/users/{user_id}/status`: activate or deactivate a user.
- `POST /api/admin/users/{user_id}/rotate-token`: rotate a user's bearer token.
- `POST /api/admin/servers`: register first-party or third-party MCP servers.
- `POST /api/admin/policies`: grant a user either one tool or every tool on a server when `tool_name` is `null`.
- `DELETE /api/admin/policies/{grant_id}`: revoke a grant.
- `POST /api/admin/servers/{server_slug}/refresh-tools`: refresh a server's cached tool list.
- `GET /api/admin/audit`: read recent audit events.

User APIs require the user's bearer token:

- `POST /api/users/me/credentials/{server_slug}`: set encrypted credential config for a downstream server.
- `GET /api/users/me/tools`: list the same tools the MCP endpoint will advertise.

## Credential Brokering

Each server has a `credential_header_map`. For Jira and Confluence the default map is:

```json
{
  "base_url": "X-Atlassian-Base-Url",
  "pat": "X-Atlassian-Token",
  "email": "X-Atlassian-Email"
}
```

The gateway decrypts the user's config, maps only those values into downstream headers, and never includes credential values in audit records.

## Kubernetes

Render the production base:

```bash
kubectl kustomize k8s/base
```

Render a local mock overlay with in-cluster PostgreSQL and mocked Atlassian calls:

```bash
kubectl kustomize k8s/overlays/local
```

Render the production overlay with HTTPS ingress placeholders:

```bash
kubectl kustomize k8s/overlays/production
```

Deploy the local overlay to a test cluster:

```bash
kubectl apply -k k8s/overlays/local
kubectl -n mcp-gateway rollout status deploy/mcp-gateway
kubectl -n mcp-gateway rollout status deploy/jira-mcp
kubectl -n mcp-gateway rollout status deploy/confluence-mcp
```

Before deploying production, replace:

- `images` in `k8s/base/kustomization.yaml`
- `GATEWAY_ADMIN_TOKEN`
- `GATEWAY_SECRET_KEY`
- `GATEWAY_ENCRYPTION_KEY`
- `GATEWAY_DATABASE_URL`
- `GATEWAY_FIRST_PARTY_INTERNAL_TOKEN` and `ATLASSIAN_INTERNAL_TOKEN`; these must be the same random value so the gateway can call the first-party Jira and Confluence MCP services.
- `GATEWAY_ALLOW_ORIGINS` with a JSON list of trusted agent/client origins when browser-origin traffic can reach the service.
- Keep `GATEWAY_ALLOW_INSECURE_BOOTSTRAP=false` in production. The local overlay sets it to `true` only so demo secrets can boot in a disposable cluster.

Use a managed PostgreSQL database for production. The included local overlay is for cluster smoke tests, not durable production data.

Generate a Fernet key:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Production migration flow:

- The `mcp-gateway` Deployment has an `alembic upgrade head` init container.
- `GATEWAY_AUTO_CREATE_SCHEMA=false` is set in Kubernetes so app pods do not mutate schema on startup.
- The app still seeds the built-in `jira` and `confluence` registry rows after migrations are present.
- Jira and Confluence MCP pods require `X-MCP-Gateway-Internal-Token` when `ATLASSIAN_INTERNAL_TOKEN` is configured. The gateway injects this header for first-party registered MCP servers.

Operational endpoints:

- `GET /healthz`: liveness.
- `GET /readyz`: database readiness.
- `GET /metrics`: Prometheus metrics.

## Architecture Notes

The gateway is stateless across pods. Shared state lives in PostgreSQL: users, server registry, grants, encrypted credentials, cached tool metadata, and audit logs. Downstream MCP servers can be first-party deployments in the same cluster or third-party HTTPS MCP URLs. Tool names are exposed as `<server_slug>__<tool_name>` to prevent collisions across many servers.

For enterprise identity, keep the bearer-token boundary behind your IdP or API gateway now, then replace `require_user` with OIDC/JWT validation while preserving the same `User.external_id` policy lookup.

## Production Checklist

- Keep CI green. The included workflow runs tests, compiles Python, renders every Kustomize overlay, parses the rendered YAML, and builds the image.
- Put TLS, WAF/rate limiting, and OIDC/JWT validation at your ingress or API gateway boundary.
- Replace all generated Kustomize secrets before applying production manifests.
- Leave `GATEWAY_ALLOW_INSECURE_BOOTSTRAP=false`; startup intentionally fails if placeholder secrets are still configured.
- Update `k8s/overlays/production/ingress.yaml` for your ingress class, hostname, and TLS secret.
- Use managed PostgreSQL with backups, PITR, and retention aligned to audit requirements.
- Rotate `GATEWAY_ADMIN_TOKEN` after bootstrap and prefer named admin users for ongoing operations.
- Restrict `GATEWAY_ALLOW_ORIGINS`; the default `["*"]` is for non-browser/local development.
- Export pod logs to your SIEM. Audit entries are written to the database and emitted as structured JSON log lines.
- Treat first-party Jira/Confluence write tools (`add_comment`, `transition_issue`, `create_page`, `update_page`) as separate grants from read tools.
