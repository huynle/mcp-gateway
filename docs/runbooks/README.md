# Runbooks

Operator procedures for a deployed gateway (Helm chart, [`docs/deploy.md`](../deploy.md)). Each runbook has the same shape: **when to use it**, **preconditions**, **steps** with exact commands, **verification**, **rollback**. Every page and route named here was checked against the code at `team-mcp-gateway-v1` (the file is cited next to each claim); when a runbook says a mechanism does not exist yet, it links the Brain draft task that adds it.

| Runbook | Use when | Alert (PrometheusRule, `metrics.prometheusRule.enabled`) |
|---|---|---|
| [deploy-and-rollback.md](deploy-and-rollback.md) | installing, upgrading, rolling back, scaling, a pod that will not become ready | `MCPGatewayScrapeDown`, `MCPGatewayNoReadyReplicas`, `MCPGatewayReplicasBelowMinimum` |
| [key-rotation.md](key-rotation.md) | rotating the Vault transit key, the Vault token, the file key (local only), database passwords, OIDC client secrets | — |
| [unresolved-operations.md](unresolved-operations.md) | a write the vendor did not confirm and reconciliation gave up on; a user asks "did my write happen?" | `MCPGatewayUnresolvedOperations` |
| [user-offboarding.md](user-offboarding.md) | someone leaves or must lose access now | — |
| [vendor-app-secret-rotation.md](vendor-app-secret-rotation.md) | a vendor client secret, the Slack bot token or signing secret expires, leaks or is rotated at the vendor | `MCPGatewayConnectionRefreshFailures` |
| [audit-export.md](audit-export.md) | an investigation or compliance request needs audit rows out of the system | — |
| [incident-redaction-check.md](incident-redaction-check.md) | after any incident, before sharing logs; when a secret may have been logged | `MCPGatewayAuthFailureSpike` |

Conventions used in the commands:

```bash
NS=mcp-gateway                 # the release namespace
RELEASE=mcp-gateway            # the Helm release name (resources are <release>, <release>-metrics, <release>-migrate)
VALUES=values-production.yaml  # your copy of deploy/helm/values-production.example.yaml
MIGRATE_URL="$(kubectl -n $NS get secret mcp-gateway-database -o jsonpath='{.data.migrate-url}' | base64 -d)"
JOBS_URL="$(kubectl -n $NS get secret mcp-gateway-database -o jsonpath='{.data.jobs-url}' | base64 -d)"
```

Read-only database access for triage goes through the **`gateway_jobs`** role (BYPASSRLS; `jobs-url`) and the `admin_*` views (migration `00007_admin_views.sql`, `security_invoker`): they project metadata only and never the envelope-encrypted columns. Never query the base tables' secret columns, never paste a connection string or a token into a ticket, and never run anything against production that a runbook does not list without recording what you ran.

Drill log: the first time each runbook is exercised on staging, record the date, the gateway version and what differed from the text in the Brain task that tracks the pilot (`pn4voyen`), and fix the runbook in the same change.
