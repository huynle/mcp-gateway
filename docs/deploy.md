# Deploying to Kubernetes

The Helm chart in [`deploy/helm/mcp-gateway`](../deploy/helm/mcp-gateway) deploys the gateway to any Kubernetes cluster with the properties the design requires (Brain plan `36bakiw8` section 7, decisions `nq8wo4g3` / `bt8ukyrd`, `ysorv868`, `dovthftx`, `p91c25vb`): one static binary in a distroless image, **at least two identical stateless replicas**, a **pre-upgrade migration Job**, public HTTPS for the harness and portal paths only, a **private metrics port**, a **NetworkPolicy** limiting egress to DNS, PostgreSQL, the key provider and the vendor APIs, **secrets referenced by name** from the cluster's secret store, non-root read-only pods, a PodDisruptionBudget and anti-affinity. Nothing in the chart is cloud-specific; provider details (ingress class, certificate issuer, database CIDRs) live in the example values files.

```
deploy/helm/mcp-gateway/            the chart (Chart.yaml, values.yaml, values.schema.json, templates/)
deploy/helm/values-local.example.yaml        kind / minikube: file key provider, fake connector, no ingress
deploy/helm/values-staging.example.yaml      stub: Vault, nginx + cert-manager, CIDRs to replace
deploy/helm/values-production.example.yaml   stub: same shape, hard anti-affinity, bigger resources
deploy/helm/helm_test.go + testdata/*.golden  make test-helm (build tag helm)
deploy/smoke/kind-smoke.sh + deploy/smoke/k8s/postgres.yaml   make kind-smoke
```

## Prerequisites

- Kubernetes >= 1.25 with an ingress controller, a CNI that enforces `NetworkPolicy` (Calico, Cilium, ...; kind's default does not) and, for TLS, cert-manager or a certificate in a Secret.
- PostgreSQL 14+ reachable from the cluster, with the database and three roles (next section).
- A key provider: HashiCorp Vault / OpenBao transit for staging and production ([`docs/crypto.md`](crypto.md)); the `file` provider is for local clusters only.
- The container image (`Dockerfile`; CI builds `mcp-gateway:ci`) pushed to a registry the cluster can pull from (`image.repository` / `image.tag`).
- One or more company identity providers registered with redirect URI `<baseURL>/auth/<name>/callback` ([README](../README.md#sign-in-users-and-the-portal)); vendor apps are registered later in the portal ([`docs/vendor-apps.md`](vendor-apps.md)).
- `helm` 3.12+ and `kubectl`.

### Database roles

Migration 00001 creates the `gateway_app` (NOBYPASSRLS) and `gateway_jobs` (BYPASSRLS) roles **without LOGIN**. Before the first install, as the database owner / a superuser:

```sql
CREATE DATABASE gateway;
CREATE ROLE gateway_app  LOGIN PASSWORD '<app password>'  NOBYPASSRLS;
CREATE ROLE gateway_jobs LOGIN PASSWORD '<jobs password>' BYPASSRLS;
```

(or run `migrate up` once and then `ALTER ROLE ... LOGIN PASSWORD ...`). The owner role used for migrations must be able to create roles and grant `BYPASSRLS`, i.e. a superuser or the database owner with `CREATEROLE` on a cluster where that suffices; see [`deploy/postgres/init/01-roles.sql`](../deploy/postgres/init/01-roles.sql) for the Compose equivalent.

## Secrets to create

The chart **never renders a Secret** and never accepts a secret value (`make test-helm` fails if a rendered manifest contains a `Secret` or a connection string). Create these before `helm install`, with your secret store (External Secrets, Sealed Secrets, Vault Agent, `kubectl create secret`):

| Secret (values key) | Keys | Used by |
|---|---|---|
| `mcp-gateway-database` (`database.existingSecret`) | `app-url` = `postgres://gateway_app:...@host:5432/gateway?sslmode=require`<br>`jobs-url` = `postgres://gateway_jobs:...`<br>`migrate-url` = `postgres://<owner>:...` | gateway pods get `app-url` + `jobs-url` (`GATEWAY_DATABASE_URL`, `GATEWAY_JOBS_DATABASE_URL`); only the migrate Job gets `migrate-url` (`GATEWAY_MIGRATE_DATABASE_URL`) |
| `mcp-gateway-vault` (`keyProvider.vault.token.existingSecret`) | `token` | `GATEWAY_VAULT_TOKEN` when `keyProvider.type=vault` |
| `mcp-gateway-keys` (`keyProvider.file.existingSecret`) | `keys.json` (output of `crypto.GenerateKeyFile`) | the file provider (local clusters only; mounted through an init container that copies it to a 0600 file in a memory-backed emptyDir, because a Secret volume cannot produce a file owned by the gateway user with that mode) |
| `mcp-gateway-oidc` (`oidc.providers[].clientSecret.secretName`) | `<provider>-client-secret` (or `clientSecret.secretKey`) | `GATEWAY_OIDC_<NAME>_CLIENT_SECRET` |
| `mcp-gateway-app` (`logSalt.existingSecret`, optional) | `log-salt` | `GATEWAY_LOG_SALT` (keeps user pseudonyms stable across replicas and restarts) |
| `mcp-gateway-tls` (`ingress.tls.secretName`) | `tls.crt`, `tls.key` | the Ingress; cert-manager fills it when the issuer annotation is set |

```bash
kubectl -n mcp-gateway create secret generic mcp-gateway-database \
  --from-literal=app-url='postgres://gateway_app:...@db:5432/gateway?sslmode=require' \
  --from-literal=jobs-url='postgres://gateway_jobs:...@db:5432/gateway?sslmode=require' \
  --from-literal=migrate-url='postgres://gateway:...@db:5432/gateway?sslmode=require'
kubectl -n mcp-gateway create secret generic mcp-gateway-vault --from-literal=token='hvs....'
kubectl -n mcp-gateway create secret generic mcp-gateway-oidc --from-literal=google-client-secret='...'
kubectl -n mcp-gateway create secret generic mcp-gateway-app --from-literal=log-salt="$(openssl rand -hex 32)"
```

`helm install` prints the list of Secrets the release expects (NOTES.txt).

## Values

Every `GATEWAY_*` variable from [`.env.example`](../.env.example) has a key under `gateway:` with the same default (`gateway.session.*`, `tokens.signinMaxAge`, `mcp.maxBody`, `rateLimits.*`, `policy.reloadInterval`, `approvals.ttl` / `wait`, `ledger.*`, `oauth.*`, `defaultRole`, `bootstrapAdmins`). The ones that shape the deployment:

| Value | Default | Notes |
|---|---|---|
| `replicaCount` | `2` | **Rendering fails below 2.** Background jobs run on every replica but each job takes a PostgreSQL lease (`job_locks`), so it runs on one replica at a time; there is no singleton deployment. |
| `gateway.baseURL` | `https://mcp-gateway.example.com` | Public origin: OAuth issuer, OIDC redirect base, portal links. The Ingress host defaults to its host. |
| `gateway.httpPort` / `metricsPort` | `18080` / `19090` | `GATEWAY_LISTEN_ADDR=:18080`; `GATEWAY_METRICS_ADDR=0.0.0.0:19090` so the metrics Service can reach the listener (the Compose default `127.0.0.1:19090` would be unreachable from the Service). |
| `gateway.drainTimeoutSeconds` | `25` | `GATEWAY_DRAIN_TIMEOUT`; `terminationGracePeriodSeconds` = drain + 10 unless `gateway.terminationGracePeriodSeconds` is set. |
| `gateway.enableFakeConnector` | `false` | **Never in staging or production.** Registers the make-believe `fake` app for every user. NOTES.txt shouts when it is on. |
| `oidc.providers[]` | `[]` | `{name, displayName, issuer, clientID, clientSecret{secretName, secretKey}, allowedDomains, allowedTenants, domainClaim}` → `GATEWAY_OIDC_PROVIDERS` and `GATEWAY_OIDC_<NAME>_*`. Without any, nobody can sign in. |
| `keyProvider.type` | `vault` | `vault` (`addr`, `transitKey`, `mount`, token Secret) or `file` (Secret + init container). |
| `migrate.*` | enabled, weight `-5`, `before-hook-creation` | The pre-install / pre-upgrade Job. |
| `ingress.*` | nginx-agnostic, TLS on | Routes only the public paths (below); `ingress.paths: [{path: /, pathType: Prefix}]` is a valid catch-all because the metrics port is not on the `http` Service. |
| `networkPolicy.*` | enabled | Ingress: http from `ingress.http.from`, metrics from `ingress.metrics.from` (empty = any peer). Egress: DNS, PostgreSQL (`egress.postgres.cidrs` or selectors), Vault (`egress.keyProvider`, only when `type=vault`), vendor APIs (`egress.vendorAPIs`). |
| `podDisruptionBudget` | `minAvailable: 1` | |
| `antiAffinity` | `soft`, per node | `hard` needs >= 2 nodes. |
| `podSecurityContext` / `containerSecurityContext` | non-root 65532, seccomp RuntimeDefault, read-only root, drop ALL, no privilege escalation | The schema refuses `runAsNonRoot: false`, `readOnlyRootFilesystem: false`, `allowPrivilegeEscalation: true`. |
| `serviceAccount.automountServiceAccountToken` | `false` | The gateway never calls the Kubernetes API. |
| `metrics.serviceMonitor.enabled` | `false` | Prometheus Operator `ServiceMonitor` on the metrics Service. |
| `extraEnv`, `extraEnvFrom`, `extraVolumes`, `extraVolumeMounts` | | Escape hatches (e.g. a CA bundle for a private Vault). |

`values.schema.json` validates types, enums and formats (durations, CIDRs, provider names) before rendering.

### Public paths

The Ingress routes `/` (exact), `/mcp`, `/oauth`, `/.well-known`, `/auth`, `/signin`, `/account`, `/tokens`, `/connections`, `/connect`, `/approvals`, `/operations`, `/harnesses`, `/activity`, `/admin`, `/static` and `/slack` to the `http` Service. `/healthz` and `/readyz` stay cluster-internal (probes), and `/metrics` is on another port and another Service that no Ingress references.

## Install, upgrade, rollback

```bash
helm lint --strict deploy/helm/mcp-gateway -f my-values.yaml
helm install mcp-gateway deploy/helm/mcp-gateway -n mcp-gateway --create-namespace -f my-values.yaml --wait
kubectl -n mcp-gateway rollout status deploy/mcp-gateway
kubectl -n mcp-gateway port-forward svc/mcp-gateway 18080:80 & curl -fsS localhost:18080/readyz
```

**Upgrade.** `helm upgrade mcp-gateway deploy/helm/mcp-gateway -n mcp-gateway -f my-values.yaml --set image.tag=<new> --wait`. The order is fixed by Helm hooks:

1. `pre-upgrade` hook, weight `-5`: Job `mcp-gateway-migrate` runs `/migrate up` from the **new** image, as the owner role (`migrate-url`). Helm waits for it to succeed; `backoffLimit: 2`, `activeDeadlineSeconds: 600`. A failed Job aborts the upgrade before the Deployment is touched; the previous pods keep serving (`kubectl -n mcp-gateway logs job/mcp-gateway-migrate`).
2. The Deployment rolls (`maxUnavailable: 0`, `maxSurge: 1`): a new pod becomes ready (`/readyz`: database reachable, schema version >= the version the binary expects, key provider reachable) before an old one is drained (`SIGTERM`, up to `drainTimeoutSeconds`, then its in-flight ledger rows are marked `unknown` for the reconciler).

Between steps 1 and 2 the *old* pods run against the *new* schema. Migrations must therefore be **additive and backward compatible with the previous release** (add columns and tables; never drop or rename what the previous binary uses in the same release). The `schema` readiness check (`store.SchemaVersionReady`) accepts a database at the binary's `store.ExpectedSchemaVersion` **or newer**, so when a release bumps the version the old pods stay ready between the migration Job and their replacement; a database that is *behind* is not ready. The startup gate (`store.SchemaVersionMatches`) stays strict: a binary never starts against a schema it was not built for, so an old pod that restarts after the Job will not come back (it is being replaced anyway). Still use `--wait` and do not pause between migration and rollout. `deploy/smoke/kind-smoke.sh` demonstrates the order (migrate down, upgrade, Job finished before the first new pod started).

**Rollback.** `helm rollback mcp-gateway <revision>` restores the previous chart and image, but **migrations are forward-only**: Helm does not run `migrate down`. Because the gateway refuses to start when the database version differs from `store.ExpectedSchemaVersion`, the previous binary will not become ready on a database migrated past it. To roll back across a migration, first run the previous image's `/migrate down-to <N>` against `migrate-url`:

```bash
kubectl -n mcp-gateway run migrate-down --rm -it --restart=Never --image=<old image> \
  --env=GATEWAY_MIGRATE_DATABASE_URL="$(kubectl -n mcp-gateway get secret mcp-gateway-database -o jsonpath='{.data.migrate-url}' | base64 -d)" \
  --command -- /migrate down-to <N>
helm rollback mcp-gateway <revision> --wait
```

Only do this when the `down` section of the migration is safe for the data written in the meantime; otherwise roll forward with a fix. Releases that carry no migration roll back freely.

**Scaling.** `replicaCount` can grow at any time; shrinking below 2 is refused by the chart. The job runner moves a job to another replica within `Interval + Lease` when its holder dies.

## Key rotation

- **Vault** (`keyProvider.type=vault`): `vault write -f transit/keys/mcp-gateway/rotate`. New envelopes use the new version at once; old versions decrypt until `min_decryption_version` is raised. Run the re-wrap job, then raise it ([`docs/crypto.md`](crypto.md#root-key-rotation)). No pod restart is needed. Rotate the **Vault token** by updating Secret `mcp-gateway-vault` and restarting the pods (`kubectl rollout restart deploy/mcp-gateway`; env vars are read at start).
- **File** (`keyProvider.type=file`): add a key to `keys.json`, move `current`, update Secret `mcp-gateway-keys`, `kubectl rollout restart deploy/mcp-gateway` (the init container copies the file at pod start), re-wrap, then remove the old key.
- **OAuth signing keys** rotate themselves (`gateway.oauth.keyRotation` / `keyGrace`); **database passwords**: update the Secret and restart; **OIDC client secrets**: same.

## Metrics

The gateway serves Prometheus metrics on `0.0.0.0:19090/metrics` inside the pod, exposed by Service `mcp-gateway-metrics` (ClusterIP, annotations `prometheus.io/scrape: "true"`, `prometheus.io/port: "19090"`). It is not on the Ingress and must never be: metric names and labels carry no user identifiers, but the endpoint is operational data. Prometheus Operator users set `metrics.serviceMonitor.enabled=true` (and `metrics.serviceMonitor.labels` to match their Prometheus selector). The NetworkPolicy admits scrapers from `networkPolicy.ingress.metrics.from` (default: any peer; narrow it to the monitoring namespace as the examples do). Inside the cluster: `kubectl -n mcp-gateway run curl --rm -it --image=curlimages/curl -- -s http://mcp-gateway-metrics:19090/metrics`.

## Network policy assumptions

- The policy selects only the gateway pods and sets `policyTypes: [Ingress, Egress]`, so everything not listed is denied **for those pods**; the migrate Job's pod is deliberately not selected (it needs the same PostgreSQL and DNS egress and runs rarely).
- Ingress: the `http` port from `networkPolicy.ingress.http.from` (set it to the ingress controller's namespace), the metrics port from `networkPolicy.ingress.metrics.from`.
- Egress: DNS (53 UDP/TCP, optionally restricted to `egress.dns.to`), PostgreSQL (`egress.postgres`: CIDRs or namespace/pod selectors; empty = any peer on that port), Vault (`egress.keyProvider`, rendered only for `type=vault`), vendor APIs on 443.
- **Core `NetworkPolicy` cannot match hostnames.** `egress.vendorAPIs.hosts` (GitHub, Slack, Atlassian, Google, Microsoft; from [`docs/vendor-apps.md`](vendor-apps.md)) is recorded on the policy as an annotation. Without `egress.vendorAPIs.cidrs`, HTTPS egress is allowed to `0.0.0.0/0` **except** the private and link-local ranges (`10/8`, `172.16/12`, `192.168/16`, `169.254/16`: no cloud metadata service, no internal services), which is the tightest cloud-neutral rule for a set of public SaaS endpoints whose addresses change. Clusters with an FQDN-aware CNI (Cilium `toFQDNs`, Calico `GlobalNetworkSet`, an egress proxy) should turn the host list into their own rule and set `cidrs` to the proxy; `egress.extra` appends raw rules.
- Your OIDC issuers must be reachable too: public ones are covered by the vendor rule; a private IdP needs an `egress.extra` entry.

## Environments

| | local (kind / minikube) | staging | production |
|---|---|---|---|
| values | `values-local.example.yaml` | `values-staging.example.yaml` | `values-production.example.yaml` |
| image | `mcp-gateway:local`, `pullPolicy: Never` (kind load) | registry, tag from CD | registry, pinned release tag |
| key provider | `file` (Secret + init container) | Vault transit, own key | Vault transit, own key |
| OIDC | dex (Compose or in-cluster) | staging client at the IdP | production client |
| vendor apps | personal/dev apps | staging apps ([`docs/vendor-apps.md`](vendor-apps.md)) | production apps |
| ingress / TLS | off (port-forward), `cookieSecure: false` | nginx + cert-manager staging issuer | nginx + cert-manager production issuer |
| network policy | off (kind has no enforcement) | on, CIDRs for the DB subnet and Vault | on |
| fake connector | **on** | off | off |
| anti-affinity / PDB | off (one node) | soft / `minAvailable: 1` | hard / `minAvailable: 1` |

`make kind-smoke` runs the local environment end to end: builds the image, creates a kind cluster, applies `deploy/smoke/k8s/postgres.yaml`, creates the three Secrets, installs the chart, checks two ready replicas, `/healthz`, `/readyz`, the OAuth discovery document, an unauthenticated MCP `initialize` (401 + `WWW-Authenticate ... resource_metadata`), the in-cluster metrics Service, then rolls the schema back one version (`/migrate down`), sees the pods go not-ready, upgrades, and verifies the hook Job finished before the first new pod started and `/readyz` is ok again. CI runs it as a non-blocking step of the `helm` job.

## Verification tooling

- `make helm-lint`: `helm lint --strict` and `helm template` with the default values and every `deploy/helm/values-*.example.yaml`.
- `make test-helm`: `go test -tags helm ./deploy/helm/` renders each example, asserts the properties above (2 replicas and the `< 2` error, hook annotations and `/migrate up`, metrics Service absent from the Ingress, public path list, NetworkPolicy rules, PDB, security contexts, no rendered Secret) and compares the output with `deploy/helm/testdata/*.golden`; `make test-helm UPDATE=1` rewrites the goldens after review. Skipped when `helm` is not on `PATH`.
- `make kind-smoke`: the cluster smoke above (needs docker, kind, kubectl, helm).
