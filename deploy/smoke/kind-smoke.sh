#!/usr/bin/env bash
# Kubernetes smoke for the Helm chart (task jqack8an): proves the chart
# installs on a plain cluster with the safety properties the design requires
# and that an upgrade with a pending migration runs the hook Job before the
# new pods start.
#
#   1. builds the image (or uses $IMAGE) and loads it into a kind cluster,
#   2. applies deploy/smoke/k8s/postgres.yaml and creates the Secrets the
#      chart expects (database URLs, key file, OIDC client secret),
#   3. helm install with deploy/helm/values-local.example.yaml, waits for the
#      2 replicas, port-forwards and curls /healthz, /readyz, an MCP
#      initialize without a token (401 + resource metadata) and the OAuth
#      discovery documents,
#   4. rolls the schema back one migration with `/migrate down` (the pods go
#      not-ready: schema mismatch), then `helm upgrade --wait`: the
#      pre-upgrade Job must complete before the new pods start, after which
#      /readyz is ok again.
#
# Usage: deploy/smoke/kind-smoke.sh            (needs docker, kind, kubectl, helm)
#   IMAGE=mcp-gateway:ci BUILD=0  KEEP=1  CLUSTER=mcp-gateway-smoke  deploy/smoke/kind-smoke.sh
# BUILD=0 skips the docker build and uses $IMAGE as is; KEEP=1 leaves the
# cluster running for inspection.
set -euo pipefail
cd "$(dirname "$0")/../.."

CLUSTER=${CLUSTER:-mcp-gateway-smoke}
NS=${NS:-mcp-gateway}
RELEASE=${RELEASE:-mcp-gateway}
IMAGE=${IMAGE:-mcp-gateway:local}
CHART=deploy/helm/mcp-gateway
VALUES=deploy/helm/values-local.example.yaml
PF_PID=""

cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
  if [ "${KEEP:-0}" != 1 ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

# 1. Image + cluster. Always rebuild unless BUILD=0 (CI passes the image it
# just built); a stale local tag would otherwise be loaded silently.
if [ "${BUILD:-1}" = 1 ]; then
  step "docker build $IMAGE"
  docker build -t "$IMAGE" --build-arg VERSION=kind-smoke .
fi
# values-local pins image.tag=local with pullPolicy Never: retag whatever was given.
docker tag "$IMAGE" mcp-gateway:local
step "kind create cluster $CLUSTER"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s
kind load docker-image mcp-gateway:local --name "$CLUSTER"
kubectl config use-context "kind-$CLUSTER" >/dev/null

# 2. PostgreSQL + Secrets.
step "postgres + secrets in namespace $NS"
kubectl create namespace "$NS"
kubectl -n "$NS" apply -f deploy/smoke/k8s/postgres.yaml
kubectl -n "$NS" rollout status statefulset/postgres --timeout=180s
PG=postgres.$NS.svc.cluster.local:5432
kubectl -n "$NS" create secret generic mcp-gateway-database \
  --from-literal=app-url="postgres://gateway_app:gateway-app-dev@$PG/gateway?sslmode=disable" \
  --from-literal=jobs-url="postgres://gateway_jobs:gateway-jobs-dev@$PG/gateway?sslmode=disable" \
  --from-literal=migrate-url="postgres://gateway:gateway-dev@$PG/gateway?sslmode=disable"
KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
kubectl -n "$NS" create secret generic mcp-gateway-keys \
  --from-literal=keys.json="{\"current\":\"kind-1\",\"keys\":[{\"id\":\"kind-1\",\"key\":\"$KEY\"}]}"
kubectl -n "$NS" create secret generic mcp-gateway-oidc --from-literal=dex-client-secret=gateway-dev-secret

# 3. Install and probe.
step "helm install"
helm install "$RELEASE" "$CHART" -n "$NS" -f "$VALUES" --wait --timeout 5m
kubectl -n "$NS" get pods,svc,job
ready=$(kubectl -n "$NS" get deploy "$RELEASE" -o jsonpath='{.status.readyReplicas}')
[ "$ready" = 2 ] || { echo "readyReplicas=$ready, want 2"; kubectl -n "$NS" describe deploy "$RELEASE"; exit 1; }
[ "$(kubectl -n "$NS" get job "$RELEASE-migrate" -o jsonpath='{.status.succeeded}')" = 1 ] || { echo "migrate hook Job did not succeed"; kubectl -n "$NS" logs job/"$RELEASE-migrate"; exit 1; }
kubectl -n "$NS" logs job/"$RELEASE-migrate" | tail -3

probe() {
  kubectl -n "$NS" port-forward "svc/$RELEASE" 18080:80 >/dev/null 2>&1 &
  PF_PID=$!
  for i in $(seq 1 30); do curl -fsS localhost:18080/healthz >/dev/null 2>&1 && break; sleep 1; done
}
unprobe() { kill "$PF_PID" 2>/dev/null || true; PF_PID=""; }
probe
step "probes"
curl -fsS localhost:18080/healthz; echo
curl -fsS localhost:18080/readyz; echo
ready=$(curl -fsS localhost:18080/readyz)
printf '%s' "$ready" | grep -q '"status":"ok"' || { echo "readyz not ok"; exit 1; }
asmeta=$(curl -fsS localhost:18080/.well-known/oauth-authorization-server)
printf '%s' "$asmeta" | grep -q '"issuer":"http://localhost:18080"' || { echo "no AS metadata"; exit 1; }
code=$(curl -sS -o /dev/null -w '%{http_code}' -D /tmp/mcp-headers localhost:18080/mcp -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}')
[ "$code" = 401 ] && grep -qi 'resource_metadata=' /tmp/mcp-headers || { echo "MCP initialize without token: $code"; cat /tmp/mcp-headers; exit 1; }
echo "MCP initialize without a token: 401 + WWW-Authenticate resource_metadata (ok)"
# Metrics: private port reachable inside the cluster through its own Service.
kubectl -n "$NS" run curl-metrics --restart=Never --image=curlimages/curl:8.10.1 --command -- \
  curl -fsS "http://$RELEASE-metrics:19090/metrics" >/dev/null
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/curl-metrics --timeout=120s >/dev/null || { kubectl -n "$NS" logs curl-metrics; echo "metrics curl pod did not succeed"; exit 1; }
# (capture first: with pipefail, `cmd | grep -q` fails on grep's early exit)
metrics=$(kubectl -n "$NS" logs curl-metrics)
printf '%s' "$metrics" | grep -q 'http_request_duration_seconds' || { echo "metrics Service not scrapeable"; printf '%s\n' "$metrics" | head; exit 1; }
kubectl -n "$NS" delete pod curl-metrics --wait=false >/dev/null
echo "metrics Service scrapeable in-cluster (ok)"
unprobe

# 4. Upgrade with a pending migration.
step "migrate down one version, then helm upgrade"
kubectl -n "$NS" run migrate-down --restart=Never --image=mcp-gateway:local --image-pull-policy=Never \
  --env="GATEWAY_MIGRATE_DATABASE_URL=postgres://gateway:gateway-dev@$PG/gateway?sslmode=disable" \
  --command -- /migrate down >/dev/null
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/migrate-down --timeout=120s >/dev/null || { kubectl -n "$NS" logs migrate-down; echo "migrate down failed"; exit 1; }
kubectl -n "$NS" logs migrate-down | tail -2
# Existing pods see a schema mismatch and report not ready.
for i in $(seq 1 30); do
  ready=$(kubectl -n "$NS" get deploy "$RELEASE" -o jsonpath='{.status.readyReplicas}')
  [ "${ready:-0}" = 0 ] && break
  sleep 2
done
echo "readyReplicas after migrate down: ${ready:-0} (want 0)"
[ "${ready:-0}" = 0 ] || { echo "pods still ready on a stale schema"; exit 1; }

helm upgrade "$RELEASE" "$CHART" -n "$NS" -f "$VALUES" --set podAnnotations.smoke=upgrade --wait --timeout 5m
kubectl -n "$NS" rollout status deploy/"$RELEASE" --timeout=180s
ready=$(kubectl -n "$NS" get deploy "$RELEASE" -o jsonpath='{.status.readyReplicas}')
[ "$ready" = 2 ] || { echo "readyReplicas after upgrade=$ready, want 2"; exit 1; }
# Ordering: the hook Job's pod finished before any pod of the new ReplicaSet started.
job_done=$(kubectl -n "$NS" get pods -l app.kubernetes.io/component=migrate -o jsonpath='{.items[*].status.containerStatuses[0].state.terminated.finishedAt}' | tr ' ' '\n' | sort | tail -1)
# Only the pods of the new revision (annotated by the --set above); old ones may still be terminating.
new_start=$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=mcp-gateway -o jsonpath='{.items[?(@.metadata.annotations.smoke=="upgrade")].status.startTime}' | tr ' ' '\n' | sort | head -1)
[ -n "$new_start" ] || { echo "no pods of the upgraded revision found"; exit 1; }
echo "migrate job finished: ${job_done:-<pod already deleted>}; first new gateway pod started: $new_start"
if [ -n "$job_done" ] && [ "$job_done" \> "$new_start" ]; then echo "migration finished after the new pods started"; exit 1; fi
helm history "$RELEASE" -n "$NS"
probe
ready=$(curl -fsS localhost:18080/readyz)
printf '%s' "$ready" | grep -q '"status":"ok"' || { echo "readyz not ok after upgrade"; exit 1; }
echo "$ready"
unprobe
echo
echo "kind smoke OK"
