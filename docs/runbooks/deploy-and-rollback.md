# Deploy and rollback

Install, upgrade, roll back and scale the gateway with the Helm chart. Background: [`docs/deploy.md`](../deploy.md) (Secrets, values, readiness semantics), decision `4o8myker` (chart shape), `qx0u0q1y` (schema readiness). Everything below was checked against `deploy/helm/mcp-gateway/templates/{job-migrate,deployment}.yaml`, `cmd/migrate/main.go`, `cmd/gateway/main.go` (readiness registrations) and `internal/store/store.go`.

## When to use

- First install of an environment; any release upgrade; a rollback after a bad release; changing `replicaCount`; a pod stuck not-ready.
- Alerts: `MCPGatewayScrapeDown`, `MCPGatewayNoReadyReplicas`, `MCPGatewayReplicasBelowMinimum`.

## Preconditions

- The six Secrets exist in the namespace (`docs/deploy.md` "Secrets to create"): `mcp-gateway-database` (`app-url`, `jobs-url`, `migrate-url`), `mcp-gateway-vault` (`token`), `mcp-gateway-oidc` (`<provider>-client-secret`), `mcp-gateway-app` (`log-salt`), `mcp-gateway-tls`; the file-provider Secret only on local clusters.
- Database backups are configured and a restore has been tested **before the first production deploy** (the gateway never migrates down on its own; see Rollback).
- The image tag to deploy exists in the registry and `image.tag` in your values file is pinned to it (never `latest`).
- `helm` 3.12+, `kubectl` with access to the namespace, and `helm lint --strict deploy/helm/mcp-gateway -f $VALUES` passes.
- You know the schema version the new image expects: `docker run --rm --entrypoint /migrate <image> version` prints `database schema version N (gateway expects M)` once it can reach a database; without one, `grep ExpectedSchemaVersion internal/store/store.go` at the release tag (13 at v1).

## Readiness semantics (what "ready" means)

`/readyz` (`cmd/gateway/main.go`) registers three checks: `database` (`store.Ping`), `schema` (`store.SchemaVersionReady`: the database version is **>=** `store.ExpectedSchemaVersion`; *behind* is not ready) and `key-provider` (`crypto.ReadinessCheck`: Vault transit key readable with the configured token, or the key file loaded). `/healthz` is liveness only. The **startup gate** is stricter: `cmd/gateway` refuses to start when the version differs at all (`store.SchemaVersionMatches`), so a pod restarted after a migration it was not built for stays down and is replaced by the new release.

Consequences:

- During an upgrade the old pods keep serving against the newer schema (migrations are additive within a release, see `docs/deploy.md`); the new pods become ready and the old ones drain (`GATEWAY_DRAIN_TIMEOUT`, 25 s; `terminationGracePeriodSeconds` = 35).
- A pod whose `/readyz` says `schema ... behind` means the migrate Job did not run or failed; a pod that crash-loops with `schema version` in its log means the database is at another version than the binary expects (rolled back image on a newer database, or an upgrade applied out of order).

## Steps: install

```bash
helm lint --strict deploy/helm/mcp-gateway -f $VALUES
helm install $RELEASE deploy/helm/mcp-gateway -n $NS --create-namespace -f $VALUES --wait --timeout 10m
kubectl -n $NS rollout status deploy/$RELEASE
kubectl -n $NS logs job/$RELEASE-migrate            # "database schema version N (gateway expects N)"
kubectl -n $NS port-forward svc/$RELEASE 18080:80 & sleep 1
curl -fsS localhost:18080/readyz                    # {"status":"ok","checks":[database, schema, key-provider all ok]}
curl -s -D - -o /dev/null -X POST localhost:18080/mcp | grep -i www-authenticate   # 401 + resource_metadata
kill %1
```

Then, once per environment, in the portal: sign in as a bootstrap admin (`gateway.bootstrapAdmins`, issuer|subject), register the vendor apps on `/admin/vendor-apps` ([`docs/vendor-apps.md`](../vendor-apps.md)), create roles on `/admin/roles` and flag the default role on `/admin/settings/default-role`.

## Steps: upgrade

```bash
# 1. Read the release notes for the migration list and confirm every migration is additive (no DROP/RENAME of columns the previous binary reads).
helm diff upgrade $RELEASE deploy/helm/mcp-gateway -n $NS -f $VALUES --set image.tag=$NEW_TAG   # if the diff plugin is installed
# 2. Upgrade. Helm runs the pre-upgrade hook Job (/migrate up, weight -5, backoffLimit 2, activeDeadlineSeconds 600) and waits for it before touching the Deployment.
helm upgrade $RELEASE deploy/helm/mcp-gateway -n $NS -f $VALUES --set image.tag=$NEW_TAG --wait --timeout 15m
# 3. Watch the roll (maxUnavailable 0, maxSurge 1).
kubectl -n $NS rollout status deploy/$RELEASE
kubectl -n $NS logs job/$RELEASE-migrate
```

Do not pause between the Job and the rollout (`--wait` keeps them together). If the Job fails, Helm aborts before the Deployment changes and the previous pods keep serving: read `kubectl -n $NS logs job/$RELEASE-migrate`, fix (usually a database permission or an unreachable host), and re-run the same `helm upgrade`; the hook deletes the previous Job before creating a new one (`before-hook-creation`).

## Verification (after install or upgrade)

```bash
kubectl -n $NS get pods -l app.kubernetes.io/instance=$RELEASE          # all Running, READY 1/1, replicaCount of them
kubectl -n $NS get job $RELEASE-migrate -o jsonpath='{.status.succeeded}' # 1
kubectl -n $NS run curl --rm -it --restart=Never --image=curlimages/curl -- \
  -s http://$RELEASE-metrics:19090/metrics | grep -E '^(ledger_operations_total|auth_failures_total)' | head
```

In the portal: `/account` loads, `/admin/users` lists users, `/tokens` can mint a token, a harness `tools/list` with that token returns the tools the role grants (`docs/user-guide.md`). Logs: `kubectl -n $NS logs deploy/$RELEASE | grep -E 'policy ready|ledger ready|jobs'` shows the policy version loaded and the job runner started (`ledger.reconcile`, `ledger.sweep_stale`, `approvals.expire`, `connections.keepalive`, `authserver.prune`, `authserver.rotate_keys` — `cmd/gateway/main.go`).

## Rollback

**Release without a migration** (the schema version did not change): plain Helm rollback.

```bash
helm history $RELEASE -n $NS
helm rollback $RELEASE <previous revision> -n $NS --wait
kubectl -n $NS rollout status deploy/$RELEASE
```

**Release with a migration**: migrations are **forward-only** — `helm rollback` restores the previous chart and image but never runs `migrate down`, and the previous binary refuses to start on a database whose version differs from the one it was built for (`store.SchemaVersionMatches`). Rolling back across a migration therefore has two parts, in this order:

```bash
# 1. Roll the schema back to the previous binary's version with the OLD image's /migrate.
#    N = the version the previous release expects (its release notes, or `/migrate version` from the old image).
kubectl -n $NS run migrate-down --rm -it --restart=Never --image=<previous image> \
  --env=GATEWAY_MIGRATE_DATABASE_URL="$MIGRATE_URL" --command -- /migrate down-to <N>
# prints: database schema version N (gateway expects N)   <- the old binary agrees
# 2. Roll the release back.
helm rollback $RELEASE <previous revision> -n $NS --wait
```

Only do step 1 when the `-- +goose Down` section of every migration being undone is safe for the data written since the upgrade (read `internal/store/migrations/NNNNN_*.sql` at the new tag; a Down that drops a table loses the rows written into it). If it is not safe, **roll forward** with a fixed image instead. For orientation: in v1 (`00001`..`00013`) no Down drops `ledger_operations`, `approvals`, `audit_events` or `connections`; the Downs drop added columns, indexes and views, plus the tables `connect_flows` (00011: in-flight connect flows, 10-minute lifetime) and `oauth_authorization_codes` (00013: pending OAuth codes, 10 minutes), and 00013 removes `family_id`/`rotated_at` from `oauth_refresh_tokens` (connected harnesses must sign in again). Check the Down of every migration you undo, every time. While the schema is behind, the new pods go not-ready (`schema` check) and the old ones are not up yet: expect a short outage between the two steps; do them back to back.

`migrate down` (one step) and `migrate status` are also available (`cmd/migrate`): `kubectl -n $NS run migrate-status --rm -it --restart=Never --image=<image> --env=GATEWAY_MIGRATE_DATABASE_URL="$MIGRATE_URL" --command -- /migrate status`.

## Scaling

`replicaCount` can grow at any time (`helm upgrade ... --set replicaCount=5`); the chart refuses fewer than 2. Every replica runs the job runner but each job holds a PostgreSQL lease (`job_locks`), so a job runs on one replica and moves within `Interval + Lease` when its holder dies. With the production example (3 replicas, PDB `minAvailable: 2`, hard anti-affinity) one node can be drained at a time; `kubectl drain` blocks when it would violate the PDB.

## A pod that will not become ready

```bash
kubectl -n $NS describe pod <pod> | sed -n '/Events/,$p'
kubectl -n $NS logs <pod> --previous | tail -50
kubectl -n $NS exec <any ready pod> -- wget -qO- http://127.0.0.1:18080/readyz
```

| Symptom | Cause | Action |
|---|---|---|
| `schema` check failing, log `schema version ... expects ...` at start | database behind (Job did not run) or ahead of a rolled-back image | run the migrate Job (`helm upgrade` again) or finish the rollback above |
| `key-provider` failing | Vault unreachable (NetworkPolicy `egress.keyProvider`), token expired/revoked, transit key renamed | `kubectl -n $NS get secret mcp-gateway-vault`, Vault audit log; rotate the token ([key-rotation.md](key-rotation.md)) and `kubectl -n $NS rollout restart deploy/$RELEASE` |
| `database` failing | PostgreSQL unreachable, password rotated, `egress.postgres.cidrs` wrong | fix the Secret, restart |
| Pod ready but Ingress 502 | `networkPolicy.ingress.http.from` does not match the ingress controller namespace | fix the selector in values, upgrade |
| `MCPGatewayScrapeDown` with pods ready | `networkPolicy.ingress.metrics.from` does not match Prometheus, or `metrics.prometheusRule.selector` differs from the scrape job label | `kubectl -n $NS run curl ... http://$RELEASE-metrics:19090/metrics` works → fix the selector/label |

## Record

Write the release tag, revision, migration range and start/end times in the change log; on a rollback add the `down-to` target and who approved it.
