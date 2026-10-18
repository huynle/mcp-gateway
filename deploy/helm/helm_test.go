//go:build helm

// Package helm_test renders the mcp-gateway chart with the example values
// files and checks the properties the design requires (Brain decisions
// nq8wo4g3 / bt8ukyrd, plan 36bakiw8 section 7), then pins the rendered
// output as golden files under testdata/.
//
//	make test-helm            # go test -tags helm ./deploy/helm/
//	make test-helm UPDATE=1   # rewrite testdata/*.golden after review
//
// The test needs the helm binary on PATH and is skipped otherwise.
package helm_test

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden from the current chart")

const chartDir = "mcp-gateway"

// examples maps a golden name to the example values file rendered for it.
var examples = map[string]string{
	"default":    "",
	"local":      "values-local.example.yaml",
	"staging":    "values-staging.example.yaml",
	"production": "values-production.example.yaml",
}

func helmBin(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not on PATH; skipping chart tests (install helm to run them)")
	}
	return path
}

// render runs `helm template` with the given values file (optional) and
// extra --set arguments and returns stdout, stderr and the error.
func render(t *testing.T, valuesFile string, set ...string) (string, string, error) {
	t.Helper()
	args := []string{"template", "mcp-gateway", chartDir, "--namespace", "mcp-gateway"}
	if valuesFile != "" {
		args = append(args, "-f", valuesFile)
	}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	cmd := exec.Command(helmBin(t), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func mustRender(t *testing.T, valuesFile string, set ...string) string {
	t.Helper()
	out, stderr, err := render(t, valuesFile, set...)
	if err != nil {
		t.Fatalf("helm template -f %q %v: %v\n%s", valuesFile, set, err, stderr)
	}
	return out
}

// object is one rendered Kubernetes manifest.
type object struct {
	Kind     string
	Name     string
	Metadata map[string]any
	Spec     map[string]any
	Raw      map[string]any
}

// parse splits a multi-document YAML stream into objects.
func parse(t *testing.T, manifest string) []object {
	t.Helper()
	var objs []object
	dec := yaml.NewDecoder(strings.NewReader(manifest))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("decode manifest: %v", err)
		}
		if doc == nil {
			continue
		}
		meta, _ := doc["metadata"].(map[string]any)
		spec, _ := doc["spec"].(map[string]any)
		name, _ := meta["name"].(string)
		objs = append(objs, object{Kind: fmt.Sprint(doc["kind"]), Name: name, Metadata: meta, Spec: spec, Raw: doc})
	}
	return objs
}

func find(objs []object, kind, name string) *object {
	for i := range objs {
		if objs[i].Kind == kind && (name == "" || objs[i].Name == name) {
			return &objs[i]
		}
	}
	return nil
}

func findAll(objs []object, kind string) []object {
	var out []object
	for _, o := range objs {
		if o.Kind == kind {
			out = append(out, o)
		}
	}
	return out
}

// dig walks nested maps/slices by keys; integers in the path index slices.
func dig(v any, path ...any) any {
	for _, p := range path {
		switch cur := v.(type) {
		case map[string]any:
			k, _ := p.(string)
			v = cur[k]
		case []any:
			i, _ := p.(int)
			if i < 0 || i >= len(cur) {
				return nil
			}
			v = cur[i]
		default:
			return nil
		}
	}
	return v
}

func containers(t *testing.T, o *object, kind string) []any {
	t.Helper()
	var c any
	switch kind {
	case "Deployment":
		c = dig(o.Spec, "template", "spec", "containers")
	case "Job":
		c = dig(o.Spec, "template", "spec", "containers")
	}
	list, _ := c.([]any)
	if len(list) == 0 {
		t.Fatalf("%s %s has no containers", kind, o.Name)
	}
	return list
}

func envMap(container any) map[string]any {
	out := map[string]any{}
	list, _ := dig(container, "env").([]any)
	for _, e := range list {
		m, _ := e.(map[string]any)
		name, _ := m["name"].(string)
		out[name] = m
	}
	return out
}

func envValue(container any, name string) string {
	e, _ := envMap(container)[name].(map[string]any)
	v, _ := e["value"].(string)
	return v
}

func envSecretRef(container any, name string) (secret, key string) {
	e, _ := envMap(container)[name].(map[string]any)
	ref, _ := dig(e, "valueFrom", "secretKeyRef").(map[string]any)
	secret, _ = ref["name"].(string)
	key, _ = ref["key"].(string)
	return secret, key
}

// --- golden files -----------------------------------------------------------

func TestGolden(t *testing.T) {
	for name, values := range examples {
		t.Run(name, func(t *testing.T) {
			out := mustRender(t, values)
			golden := filepath.Join("testdata", name+".golden")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read %s: %v (run `make test-helm UPDATE=1`)", golden, err)
			}
			if string(want) != out {
				t.Errorf("rendered output differs from %s; review the diff and run `make test-helm UPDATE=1`:\n%s", golden, diff(string(want), out))
			}
		})
	}
}

// diff is a minimal line diff good enough to see what moved.
func diff(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	var b strings.Builder
	n := len(w)
	if len(g) > n {
		n = len(g)
	}
	shown := 0
	for i := 0; i < n && shown < 40; i++ {
		var a, c string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			c = g[i]
		}
		if a != c {
			fmt.Fprintf(&b, "line %d:\n- %s\n+ %s\n", i+1, a, c)
			shown++
		}
	}
	return b.String()
}

// --- safety properties --------------------------------------------------------

func TestExamplesRenderAndSecretValuesNeverTemplated(t *testing.T) {
	for name, values := range examples {
		t.Run(name, func(t *testing.T) {
			out := mustRender(t, values)
			objs := parse(t, out)
			if o := find(objs, "Secret", ""); o != nil {
				t.Errorf("chart rendered a Secret (%s); secrets must be referenced by name only", o.Name)
			}
			if strings.Contains(out, "postgres://") {
				t.Errorf("rendered output contains a connection string; database URLs must come from the existing Secret")
			}
		})
	}
}

func TestReplicaCountAtLeastTwo(t *testing.T) {
	out := mustRender(t, "values-production.example.yaml")
	dep := find(parse(t, out), "Deployment", "mcp-gateway")
	if dep == nil {
		t.Fatal("no Deployment named mcp-gateway")
	}
	if got := dig(dep.Spec, "replicas"); got != 3 {
		t.Errorf("production replicas = %v, want 3", got)
	}
	out = mustRender(t, "")
	dep = find(parse(t, out), "Deployment", "mcp-gateway")
	if got := dig(dep.Spec, "replicas"); got != 2 {
		t.Errorf("default replicas = %v, want 2", got)
	}
	_, stderr, err := render(t, "values-production.example.yaml", "replicaCount=1")
	if err == nil {
		t.Fatal("replicaCount=1 rendered; want a template error")
	}
	if !strings.Contains(stderr, "replicaCount must be at least 2") {
		t.Errorf("replicaCount=1 error is not the clear message:\n%s", stderr)
	}
}

func TestDeploymentShape(t *testing.T) {
	out := mustRender(t, "values-production.example.yaml")
	objs := parse(t, out)
	dep := find(objs, "Deployment", "mcp-gateway")
	if dep == nil {
		t.Fatal("no Deployment")
	}
	pod := dig(dep.Spec, "template", "spec")
	c := containers(t, dep, "Deployment")[0]

	// Probes on the documented endpoints.
	if p := dig(c, "readinessProbe", "httpGet", "path"); p != "/readyz" {
		t.Errorf("readiness path = %v, want /readyz", p)
	}
	if p := dig(c, "livenessProbe", "httpGet", "path"); p != "/healthz" {
		t.Errorf("liveness path = %v, want /healthz", p)
	}
	if p := dig(c, "startupProbe", "httpGet", "path"); p != "/healthz" {
		t.Errorf("startup path = %v, want /healthz", p)
	}

	// Ports: http + metrics.
	ports := map[string]int{}
	for _, p := range dig(c, "ports").([]any) {
		m := p.(map[string]any)
		ports[m["name"].(string)] = m["containerPort"].(int)
	}
	if ports["http"] != 18080 || ports["metrics"] != 19090 {
		t.Errorf("container ports = %v, want http=18080 metrics=19090", ports)
	}

	// Metrics listener must bind every interface inside the pod.
	if v := envValue(c, "GATEWAY_METRICS_ADDR"); v != "0.0.0.0:19090" {
		t.Errorf("GATEWAY_METRICS_ADDR = %q, want 0.0.0.0:19090", v)
	}
	if v := envValue(c, "GATEWAY_LISTEN_ADDR"); v != ":18080" {
		t.Errorf("GATEWAY_LISTEN_ADDR = %q, want :18080", v)
	}

	// Drain timeout and termination grace period: grace = drain + 10s.
	if v := envValue(c, "GATEWAY_DRAIN_TIMEOUT"); v != "25s" {
		t.Errorf("GATEWAY_DRAIN_TIMEOUT = %q, want 25s", v)
	}
	if g := dig(pod, "terminationGracePeriodSeconds"); g != 35 {
		t.Errorf("terminationGracePeriodSeconds = %v, want 35 (drain 25 + 10)", g)
	}

	// Database URLs from the existing Secret, never inline.
	for env, key := range map[string]string{"GATEWAY_DATABASE_URL": "app-url", "GATEWAY_JOBS_DATABASE_URL": "jobs-url"} {
		secret, k := envSecretRef(c, env)
		if secret != "mcp-gateway-database" || k != key {
			t.Errorf("%s secretKeyRef = %s/%s, want mcp-gateway-database/%s", env, secret, k, key)
		}
	}
	if _, ok := envMap(c)["GATEWAY_MIGRATE_DATABASE_URL"]; ok {
		t.Errorf("the gateway container must not receive GATEWAY_MIGRATE_DATABASE_URL")
	}

	// Large integers must not render as floats (Helm/YAML: 1.048576e+06).
	for env, want := range map[string]string{"GATEWAY_MCP_MAX_BODY": "1048576", "GATEWAY_OAUTH_MAX_UNUSED_CLIENTS": "1000", "GATEWAY_RATE_APP_PER_MIN": "600"} {
		if v := envValue(c, env); v != want {
			t.Errorf("%s = %q, want %q", env, v, want)
		}
	}

	// Fake connector is off; OIDC providers rendered structurally.
	if v := envValue(c, "GATEWAY_ENABLE_FAKE_CONNECTOR"); v != "false" {
		t.Errorf("GATEWAY_ENABLE_FAKE_CONNECTOR = %q, want false", v)
	}
	if v := envValue(c, "GATEWAY_OIDC_PROVIDERS"); v != "google" {
		t.Errorf("GATEWAY_OIDC_PROVIDERS = %q, want google", v)
	}
	if v := envValue(c, "GATEWAY_OIDC_GOOGLE_ISSUER"); v != "https://accounts.google.com" {
		t.Errorf("GATEWAY_OIDC_GOOGLE_ISSUER = %q", v)
	}
	if secret, key := envSecretRef(c, "GATEWAY_OIDC_GOOGLE_CLIENT_SECRET"); secret != "mcp-gateway-oidc" || key != "google-client-secret" {
		t.Errorf("GATEWAY_OIDC_GOOGLE_CLIENT_SECRET ref = %s/%s", secret, key)
	}
	if secret, key := envSecretRef(c, "GATEWAY_LOG_SALT"); secret != "mcp-gateway-app" || key != "log-salt" {
		t.Errorf("GATEWAY_LOG_SALT ref = %s/%s", secret, key)
	}

	// Vault key provider by env; token from the Secret.
	if v := envValue(c, "GATEWAY_KEY_PROVIDER"); v != "vault" {
		t.Errorf("GATEWAY_KEY_PROVIDER = %q, want vault", v)
	}
	if secret, key := envSecretRef(c, "GATEWAY_VAULT_TOKEN"); secret != "mcp-gateway-vault" || key != "token" {
		t.Errorf("GATEWAY_VAULT_TOKEN ref = %s/%s", secret, key)
	}

	// Hardened pod and container.
	if v := dig(pod, "securityContext", "runAsNonRoot"); v != true {
		t.Errorf("pod runAsNonRoot = %v", v)
	}
	if v := dig(pod, "securityContext", "seccompProfile", "type"); v != "RuntimeDefault" {
		t.Errorf("seccompProfile = %v", v)
	}
	if v := dig(c, "securityContext", "readOnlyRootFilesystem"); v != true {
		t.Errorf("readOnlyRootFilesystem = %v", v)
	}
	if v := dig(c, "securityContext", "allowPrivilegeEscalation"); v != false {
		t.Errorf("allowPrivilegeEscalation = %v", v)
	}
	drop, _ := dig(c, "securityContext", "capabilities", "drop").([]any)
	if len(drop) != 1 || drop[0] != "ALL" {
		t.Errorf("capabilities.drop = %v, want [ALL]", drop)
	}
	if v := dig(pod, "automountServiceAccountToken"); v != false {
		t.Errorf("automountServiceAccountToken = %v, want false", v)
	}
	if v := dig(pod, "serviceAccountName"); v != "mcp-gateway" {
		t.Errorf("serviceAccountName = %v", v)
	}
	if a := dig(pod, "affinity", "podAntiAffinity"); a == nil {
		t.Errorf("no podAntiAffinity")
	}
}

func TestFileKeyProviderUsesInitContainerAndSecretVolume(t *testing.T) {
	out := mustRender(t, "values-local.example.yaml")
	dep := find(parse(t, out), "Deployment", "mcp-gateway")
	if dep == nil {
		t.Fatal("no Deployment")
	}
	c := containers(t, dep, "Deployment")[0]
	if v := envValue(c, "GATEWAY_KEY_PROVIDER"); v != "file" {
		t.Errorf("GATEWAY_KEY_PROVIDER = %q, want file", v)
	}
	if v := envValue(c, "GATEWAY_KEY_FILE"); v != "/var/run/mcp-gateway/keys/keys.json" {
		t.Errorf("GATEWAY_KEY_FILE = %q", v)
	}
	inits, _ := dig(dep.Spec, "template", "spec", "initContainers").([]any)
	if len(inits) != 1 {
		t.Fatalf("initContainers = %d, want 1 (copies the key file to mode 0600)", len(inits))
	}
	if v := dig(inits[0], "securityContext", "runAsNonRoot"); v != true {
		t.Errorf("init container runAsNonRoot = %v", v)
	}
	vols, _ := dig(dep.Spec, "template", "spec", "volumes").([]any)
	var secretVol bool
	for _, v := range vols {
		if dig(v, "secret", "secretName") == "mcp-gateway-keys" {
			secretVol = true
		}
	}
	if !secretVol {
		t.Errorf("no volume from Secret mcp-gateway-keys")
	}
	if v := envValue(c, "GATEWAY_ENABLE_FAKE_CONNECTOR"); v != "true" {
		t.Errorf("local example should enable the fake connector, got %q", v)
	}
}

func TestMigrateJobIsPreInstallPreUpgradeHook(t *testing.T) {
	out := mustRender(t, "values-production.example.yaml")
	job := find(parse(t, out), "Job", "mcp-gateway-migrate")
	if job == nil {
		t.Fatal("no Job mcp-gateway-migrate")
	}
	ann, _ := job.Metadata["annotations"].(map[string]any)
	if h := ann["helm.sh/hook"]; h != "pre-install,pre-upgrade" {
		t.Errorf("helm.sh/hook = %v, want pre-install,pre-upgrade", h)
	}
	if w := ann["helm.sh/hook-weight"]; w != "-5" {
		t.Errorf("helm.sh/hook-weight = %v, want -5", w)
	}
	if p := ann["helm.sh/hook-delete-policy"]; p != "before-hook-creation" {
		t.Errorf("helm.sh/hook-delete-policy = %v", p)
	}
	c := containers(t, job, "Job")[0]
	cmd, _ := dig(c, "command").([]any)
	if len(cmd) != 2 || cmd[0] != "/migrate" || cmd[1] != "up" {
		t.Errorf("migrate command = %v, want [/migrate up]", cmd)
	}
	if secret, key := envSecretRef(c, "GATEWAY_MIGRATE_DATABASE_URL"); secret != "mcp-gateway-database" || key != "migrate-url" {
		t.Errorf("GATEWAY_MIGRATE_DATABASE_URL ref = %s/%s", secret, key)
	}
	if v := dig(job.Spec, "template", "spec", "serviceAccountName"); v != nil {
		t.Errorf("migrate Job sets serviceAccountName %v; the chart's ServiceAccount does not exist during pre-install", v)
	}
	if v := dig(job.Spec, "template", "spec", "restartPolicy"); v != "Never" {
		t.Errorf("restartPolicy = %v, want Never", v)
	}
	if v := dig(c, "securityContext", "readOnlyRootFilesystem"); v != true {
		t.Errorf("migrate readOnlyRootFilesystem = %v", v)
	}
	// The migrate pod must not match the Deployment's selector (Service, PDB,
	// NetworkPolicy would otherwise pick it up).
	dep := find(parse(t, out), "Deployment", "mcp-gateway")
	sel, _ := dig(dep.Spec, "selector", "matchLabels").(map[string]any)
	podLabels, _ := dig(job.Spec, "template", "metadata", "labels").(map[string]any)
	matches := true
	for k, v := range sel {
		if podLabels[k] != v {
			matches = false
		}
	}
	if matches {
		t.Errorf("migrate pod labels %v match the Deployment selector %v", podLabels, sel)
	}
	// Other resources must not be hooks (they belong to the release).
	for _, o := range parse(t, out) {
		if o.Kind == "Job" {
			continue
		}
		a, _ := o.Metadata["annotations"].(map[string]any)
		if _, ok := a["helm.sh/hook"]; ok {
			t.Errorf("%s %s is a hook", o.Kind, o.Name)
		}
	}
}

func TestServicesAndIngress(t *testing.T) {
	out := mustRender(t, "values-production.example.yaml")
	objs := parse(t, out)
	svcs := findAll(objs, "Service")
	if len(svcs) != 2 {
		t.Fatalf("services = %d, want 2 (http + metrics)", len(svcs))
	}
	http := find(objs, "Service", "mcp-gateway")
	metrics := find(objs, "Service", "mcp-gateway-metrics")
	if http == nil || metrics == nil {
		t.Fatal("want Services mcp-gateway and mcp-gateway-metrics")
	}
	for _, p := range dig(http.Spec, "ports").([]any) {
		if dig(p, "targetPort") == "metrics" {
			t.Errorf("http Service exposes the metrics port")
		}
	}
	if dig(metrics.Spec, "ports", 0, "targetPort") != "metrics" {
		t.Errorf("metrics Service does not target the metrics port")
	}
	ann, _ := metrics.Metadata["annotations"].(map[string]any)
	if ann["prometheus.io/scrape"] != "true" || ann["prometheus.io/port"] != "19090" {
		t.Errorf("metrics Service annotations = %v", ann)
	}

	ing := find(objs, "Ingress", "mcp-gateway")
	if ing == nil {
		t.Fatal("no Ingress")
	}
	if strings.Contains(fmt.Sprint(ing.Raw), "mcp-gateway-metrics") {
		t.Errorf("Ingress references the metrics Service")
	}
	rules, _ := dig(ing.Spec, "rules").([]any)
	if len(rules) != 1 || dig(rules[0], "host") != "mcp-gateway.example.com" {
		t.Errorf("ingress rules = %v", rules)
	}
	paths, _ := dig(rules[0], "http", "paths").([]any)
	seen := map[string]bool{}
	for _, p := range paths {
		seen[fmt.Sprint(dig(p, "path"))] = true
		if dig(p, "backend", "service", "name") != "mcp-gateway" {
			t.Errorf("path %v backend = %v", dig(p, "path"), dig(p, "backend"))
		}
	}
	for _, want := range []string{"/", "/mcp", "/oauth", "/.well-known", "/auth", "/signin", "/account", "/tokens", "/connections", "/connect", "/approvals", "/operations", "/harnesses", "/activity", "/admin", "/static", "/slack"} {
		if !seen[want] {
			t.Errorf("ingress lacks path %s", want)
		}
	}
	for _, never := range []string{"/healthz", "/readyz", "/metrics"} {
		if seen[never] {
			t.Errorf("ingress exposes %s", never)
		}
	}
	tls, _ := dig(ing.Spec, "tls").([]any)
	if len(tls) != 1 || dig(tls[0], "secretName") != "mcp-gateway-tls" {
		t.Errorf("ingress tls = %v", tls)
	}
	if v := dig(ing.Spec, "ingressClassName"); v != "nginx" {
		t.Errorf("ingressClassName = %v", v)
	}
}

func TestNetworkPolicyEgress(t *testing.T) {
	out := mustRender(t, "values-production.example.yaml")
	np := find(parse(t, out), "NetworkPolicy", "mcp-gateway")
	if np == nil {
		t.Fatal("no NetworkPolicy")
	}
	types, _ := dig(np.Spec, "policyTypes").([]any)
	if fmt.Sprint(types) != "[Ingress Egress]" {
		t.Errorf("policyTypes = %v", types)
	}
	egress, _ := dig(np.Spec, "egress").([]any)
	var dns, postgres, vault, vendor bool
	for _, rule := range egress {
		ports, _ := dig(rule, "ports").([]any)
		to, _ := dig(rule, "to").([]any)
		for _, p := range ports {
			switch dig(p, "port") {
			case 53:
				dns = true
			case 5432:
				postgres = true
				if dig(to, 0, "ipBlock", "cidr") != "10.20.0.0/16" {
					t.Errorf("postgres egress to = %v", to)
				}
			case 8200:
				vault = true
			case 443:
				vendor = true
				if dig(to, 0, "ipBlock", "cidr") != "0.0.0.0/0" {
					t.Errorf("vendor egress to = %v", to)
				}
				except, _ := dig(to, 0, "ipBlock", "except").([]any)
				if len(except) < 4 {
					t.Errorf("vendor egress must exclude private ranges, got %v", except)
				}
			}
		}
	}
	if !dns || !postgres || !vault || !vendor {
		t.Errorf("egress rules: dns=%v postgres=%v vault=%v vendor=%v", dns, postgres, vault, vendor)
	}
	ann, _ := np.Metadata["annotations"].(map[string]any)
	if hosts := fmt.Sprint(ann["mcp-gateway/vendor-api-hosts"]); !strings.Contains(hosts, "api.github.com") {
		t.Errorf("vendor host list annotation = %q", hosts)
	}
	ingress, _ := dig(np.Spec, "ingress").([]any)
	if len(ingress) != 2 {
		t.Errorf("ingress rules = %d, want 2 (http, metrics)", len(ingress))
	}
}

func TestPDBAndServiceAccount(t *testing.T) {
	out := mustRender(t, "values-production.example.yaml")
	objs := parse(t, out)
	pdb := find(objs, "PodDisruptionBudget", "mcp-gateway")
	if pdb == nil {
		t.Fatal("no PodDisruptionBudget")
	}
	if v := dig(pdb.Spec, "minAvailable"); v != 2 {
		t.Errorf("production minAvailable = %v, want 2 (of 3 replicas: one voluntary disruption at a time)", v)
	}
	if pdb := find(parse(t, mustRender(t, "")), "PodDisruptionBudget", "mcp-gateway"); pdb == nil || dig(pdb.Spec, "minAvailable") != 1 {
		t.Errorf("default PDB = %v, want minAvailable 1", pdb)
	}
	if sa := find(objs, "ServiceAccount", "mcp-gateway"); sa == nil {
		t.Error("no ServiceAccount")
	}
	// Operator resources are opt-in: absent from the default render, present
	// in the production example (metrics.serviceMonitor / prometheusRule).
	defaults := parse(t, mustRender(t, ""))
	if sm := find(defaults, "ServiceMonitor", ""); sm != nil {
		t.Error("ServiceMonitor rendered although disabled by default")
	}
	if pr := find(defaults, "PrometheusRule", ""); pr != nil {
		t.Error("PrometheusRule rendered although disabled by default")
	}
	if sm := find(objs, "ServiceMonitor", "mcp-gateway"); sm == nil {
		t.Error("production example does not render a ServiceMonitor")
	}
}

func TestPrometheusRuleOptIn(t *testing.T) {
	out := mustRender(t, "values-production.example.yaml")
	pr := find(parse(t, out), "PrometheusRule", "mcp-gateway")
	if pr == nil {
		t.Fatal("no PrometheusRule in the production example (metrics.prometheusRule.enabled=true)")
	}
	groups, _ := dig(pr.Spec, "groups").([]any)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	rules, _ := dig(groups[0], "rules").([]any)
	alerts := map[string]map[string]any{}
	for _, r := range rules {
		m, _ := r.(map[string]any)
		name, _ := m["alert"].(string)
		alerts[name] = m
	}
	for _, want := range []string{"MCPGatewayUnresolvedOperations", "MCPGatewayConnectionRefreshFailures", "MCPGatewayAuthFailureSpike", "MCPGatewayVendorRateLimited", "MCPGatewayScrapeDown", "MCPGatewayNoReadyReplicas"} {
		a, ok := alerts[want]
		if !ok {
			t.Errorf("alert %s missing (have %v)", want, alerts)
			continue
		}
		if dig(a, "labels", "severity") == nil {
			t.Errorf("alert %s has no severity label", want)
		}
		if ru := fmt.Sprint(dig(a, "annotations", "runbook_url")); !strings.Contains(ru, "docs/runbooks/") {
			t.Errorf("alert %s runbook_url = %q, want a docs/runbooks/ link", want, ru)
		}
	}
	// The metric names must be the ones the gateway exports (docs/observability.md).
	for alert, metric := range map[string]string{
		"MCPGatewayUnresolvedOperations":      `ledger_operations_total{state="unresolved"`,
		"MCPGatewayConnectionRefreshFailures": "connection_refresh_failures_total",
		"MCPGatewayAuthFailureSpike":          "auth_failures_total",
		"MCPGatewayVendorRateLimited":         "vendor_rate_limited_total",
		"MCPGatewayScrapeDown":                "up{",
		"MCPGatewayNoReadyReplicas":           `kube_deployment_status_replicas_available{namespace="mcp-gateway",deployment="mcp-gateway"}`,
	} {
		if expr := fmt.Sprint(dig(alerts[alert], "expr")); !strings.Contains(expr, metric) {
			t.Errorf("%s expr = %q, want it to use %s", alert, expr, metric)
		}
	}
	if expr := fmt.Sprint(dig(alerts["MCPGatewayUnresolvedOperations"], "expr")); !strings.Contains(expr, "[30m]") {
		t.Errorf("unresolved window = %q, want 30m in the production example", expr)
	}
	if f := fmt.Sprint(dig(alerts["MCPGatewayScrapeDown"], "for")); f == "" || f == "<nil>" {
		t.Errorf("MCPGatewayScrapeDown has no for duration")
	}
	// Without kube-state-metrics the Deployment-level alerts are left out.
	out = mustRender(t, "values-production.example.yaml", "metrics.prometheusRule.kubeStateMetrics=false")
	if strings.Contains(out, "MCPGatewayNoReadyReplicas") {
		t.Errorf("kubeStateMetrics=false still renders the kube-state-metrics alerts")
	}
	// The rule must never be a hook and must carry the extra labels.
	out = mustRender(t, "values-production.example.yaml", "metrics.prometheusRule.labels.release=kube-prometheus-stack")
	pr = find(parse(t, out), "PrometheusRule", "mcp-gateway")
	if labels, _ := pr.Metadata["labels"].(map[string]any); labels["release"] != "kube-prometheus-stack" {
		t.Errorf("PrometheusRule labels = %v, want release=kube-prometheus-stack", labels)
	}
}

func TestServiceMonitorOptIn(t *testing.T) {
	out := mustRender(t, "values-production.example.yaml", "metrics.serviceMonitor.enabled=true")
	sm := find(parse(t, out), "ServiceMonitor", "mcp-gateway")
	if sm == nil {
		t.Fatal("no ServiceMonitor with metrics.serviceMonitor.enabled=true")
	}
	if dig(sm.Spec, "endpoints", 0, "port") != "metrics" {
		t.Errorf("ServiceMonitor endpoint = %v", dig(sm.Spec, "endpoints"))
	}
}

func TestLint(t *testing.T) {
	for name, values := range examples {
		t.Run(name, func(t *testing.T) {
			args := []string{"lint", "--strict", chartDir}
			if values != "" {
				args = append(args, "-f", values)
			}
			out, err := exec.Command(helmBin(t), args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm lint: %v\n%s", err, out)
			}
		})
	}
}

// TestTunnelRelay: off by default (no relay env, port or policy rule);
// enabled, it advertises the pod IP from the downward API, reads the
// secret from a Secret, opens the container port without adding it to
// any Service, and the NetworkPolicy admits it from and to the gateway's
// own pods only. Missing secret or a clashing port refuses to render.
func TestTunnelRelay(t *testing.T) {
	off := parse(t, mustRender(t, "values-production.example.yaml"))
	c := containers(t, find(off, "Deployment", "mcp-gateway"), "Deployment")[0]
	for _, name := range []string{"GATEWAY_RELAY_LISTEN_ADDR", "GATEWAY_RELAY_ADVERTISE_ADDR", "GATEWAY_RELAY_SECRET", "POD_IP"} {
		if _, ok := envMap(c)[name]; ok {
			t.Errorf("relay off: %s is set", name)
		}
	}

	on := parse(t, mustRender(t, "values-production.example.yaml", "tunnelRelay.enabled=true", "tunnelRelay.existingSecret=gw-relay"))
	dep := find(on, "Deployment", "mcp-gateway")
	c = containers(t, dep, "Deployment")[0]
	if v := envValue(c, "GATEWAY_RELAY_LISTEN_ADDR"); v != ":18081" {
		t.Errorf("GATEWAY_RELAY_LISTEN_ADDR = %q", v)
	}
	if v := envValue(c, "GATEWAY_RELAY_ADVERTISE_ADDR"); v != "http://$(POD_IP):18081" {
		t.Errorf("GATEWAY_RELAY_ADVERTISE_ADDR = %q", v)
	}
	if fp := dig(envMap(c)["POD_IP"], "valueFrom", "fieldRef", "fieldPath"); fp != "status.podIP" {
		t.Errorf("POD_IP fieldPath = %v", fp)
	}
	// POD_IP must be defined before the variable that references it.
	order, _ := dig(c, "env").([]any)
	podIdx, advIdx := -1, -1
	for i, e := range order {
		switch dig(e, "name") {
		case "POD_IP":
			podIdx = i
		case "GATEWAY_RELAY_ADVERTISE_ADDR":
			advIdx = i
		}
	}
	if podIdx < 0 || advIdx < podIdx {
		t.Errorf("POD_IP (%d) must precede GATEWAY_RELAY_ADVERTISE_ADDR (%d)", podIdx, advIdx)
	}
	if s, k := envSecretRef(c, "GATEWAY_RELAY_SECRET"); s != "gw-relay" || k != "relay-secret" {
		t.Errorf("GATEWAY_RELAY_SECRET from %s/%s", s, k)
	}
	found := false
	for _, p := range dig(c, "ports").([]any) {
		found = found || (dig(p, "name") == "tunnel-relay" && dig(p, "containerPort") == 18081)
	}
	if !found {
		t.Error("no tunnel-relay containerPort")
	}
	for _, svc := range findAll(on, "Service") {
		for _, p := range dig(svc.Spec, "ports").([]any) {
			if dig(p, "port") == 18081 || dig(p, "targetPort") == 18081 || dig(p, "targetPort") == "tunnel-relay" {
				t.Errorf("Service %s exposes the relay port", svc.Name)
			}
		}
	}
	np := find(on, "NetworkPolicy", "mcp-gateway")
	for _, dir := range []struct{ rules, peers string }{{"ingress", "from"}, {"egress", "to"}} {
		ok := false
		rules, _ := dig(np.Spec, dir.rules).([]any)
		for _, r := range rules {
			if dig(r, "ports", 0, "port") != 18081 {
				continue
			}
			peers, _ := dig(r, dir.peers).([]any)
			if len(peers) != 1 || dig(peers, 0, "podSelector", "matchLabels", "app.kubernetes.io/name") != "mcp-gateway" ||
				dig(peers, 0, "namespaceSelector") != nil || dig(peers, 0, "ipBlock") != nil {
				t.Errorf("%s relay rule peers = %v, want the gateway pods only", dir.rules, peers)
			}
			ok = true
		}
		if !ok {
			t.Errorf("no %s rule for the relay port", dir.rules)
		}
	}

	for name, set := range map[string][]string{
		"no secret":  {"tunnelRelay.enabled=true"},
		"http clash": {"tunnelRelay.enabled=true", "tunnelRelay.existingSecret=s", "tunnelRelay.port=18080"},
	} {
		if _, _, err := render(t, "values-production.example.yaml", set...); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}
