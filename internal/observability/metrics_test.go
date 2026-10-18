package observability_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/huynle/mcp-gateway/internal/observability"
)

func scrape(t *testing.T, m *observability.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status %d", rec.Code)
	}
	return rec.Body.String()
}

func observeAll(m *observability.Metrics) {
	m.ObserveHTTP("GET /healthz", http.MethodGet, http.StatusOK, 12*time.Millisecond)
	m.AuthFailure("expired")
	m.PolicyDecision("deny")
	m.Approval("approved")
	m.LedgerOperation("unknown")
	m.ConnectionRefreshFailure("github")
	m.VendorRateLimited("slack")
	m.AuditPurged(3)
}

func TestMetricsCatalogue(t *testing.T) {
	m := observability.NewMetrics()
	observeAll(m)
	out := scrape(t, m)
	for _, want := range []string{
		`http_request_duration_seconds_bucket{method="GET",route="GET /healthz",status="200"`,
		`auth_failures_total{reason="expired"} 1`,
		`policy_decisions_total{decision="deny"} 1`,
		`approvals_total{state="approved"} 1`,
		`ledger_operations_total{state="unknown"} 1`,
		`connection_refresh_failures_total{app="github"} 1`,
		`vendor_rate_limited_total{app="slack"} 1`,
		`audit_events_purged_total 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape missing %q\n%s", want, out)
		}
	}
}

// TestMetricsHaveNoUserIdentifyingLabels: every label name on every metric
// is from the fixed vocabulary; nothing like user, token, account or
// request id can appear (decision v6piaxdb).
func TestMetricsHaveNoUserIdentifyingLabels(t *testing.T) {
	m := observability.NewMetrics()
	observeAll(m)
	allowed := map[string]bool{"route": true, "method": true, "status": true, "reason": true, "decision": true, "state": true, "app": true}
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range families {
		names = append(names, f.GetName())
		for _, metric := range f.GetMetric() {
			for _, l := range metric.GetLabel() {
				if !allowed[l.GetName()] {
					t.Errorf("metric %s has label %q outside the allowed vocabulary", f.GetName(), l.GetName())
				}
				for _, bad := range []string{"user", "token", "account", "request", "email", "subject"} {
					if strings.Contains(strings.ToLower(l.GetName()), bad) {
						t.Errorf("metric %s label %q looks user-identifying", f.GetName(), l.GetName())
					}
				}
			}
		}
	}
	sort.Strings(names)
	want := []string{
		"approvals_total", "audit_events_purged_total", "auth_failures_total", "connection_refresh_failures_total",
		"http_request_duration_seconds", "ledger_operations_total", "policy_decisions_total",
		"vendor_rate_limited_total",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("metric families = %v, want %v", names, want)
	}
}

func TestMetricsUsePrivateRegistry(t *testing.T) {
	m1 := observability.NewMetrics()
	m2 := observability.NewMetrics() // must not panic with duplicate registration
	observeAll(m1)
	observeAll(m2)
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "auth_failures_total" {
			t.Error("metric leaked into the default registry")
		}
	}
	// The private registry also does not carry Go runtime/process collectors.
	if out := scrape(t, m1); strings.Contains(out, "go_goroutines") {
		t.Error("private registry carries default collectors")
	}
}

func TestHTTPMiddlewareLabelsByRoutePattern(t *testing.T) {
	m := observability.NewMetrics()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /things/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "implicit 200")
	})
	h := m.HTTPMiddleware(mux)

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/things/42"},
		{http.MethodGet, "/things/mgw_secret_value_should_not_appear"},
		{http.MethodPost, "/mcp"},
		{http.MethodGet, "/nope"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), c.method, c.path, nil))
	}
	out := scrape(t, m)
	for _, want := range []string{
		`http_request_duration_seconds_count{method="GET",route="GET /things/{id}",status="201"} 2`,
		`http_request_duration_seconds_count{method="POST",route="POST /mcp",status="200"} 1`,
		`http_request_duration_seconds_count{method="GET",route="unmatched",status="404"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, bad := range []string{"/things/42", "mgw_secret"} {
		if strings.Contains(out, bad) {
			t.Errorf("raw path %q leaked into a label", bad)
		}
	}
}

func TestHTTPMiddlewarePreservesFlusher(t *testing.T) {
	m := observability.NewMetrics()
	var flushed bool
	h := m.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err == nil {
			flushed = true
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if !flushed {
		t.Error("Flush through the metrics wrapper failed; streaming handlers need it")
	}
}

func TestMetricsAddrDefaultsToLoopback(t *testing.T) {
	t.Setenv(observability.EnvMetricsAddr, "")
	if got := observability.MetricsAddr(); got != "127.0.0.1:19090" {
		t.Errorf("default addr = %q", got)
	}
	t.Setenv(observability.EnvMetricsAddr, "0.0.0.0:9999")
	if got := observability.MetricsAddr(); got != "0.0.0.0:9999" {
		t.Errorf("env addr = %q", got)
	}
}

func TestServeMetricsServesAndStops(t *testing.T) {
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	m := observability.NewMetrics()
	observeAll(m)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- observability.ServeMetrics(ctx, addr, m.Handler()) }()

	client := &http.Client{Timeout: time.Second}
	var body string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/metrics", nil)
		resp, err := client.Do(req)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			body = string(b)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, "auth_failures_total") {
		t.Fatalf("metrics endpoint did not serve the registry: %q", body)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeMetrics returned %v after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeMetrics did not stop after cancel")
	}
}

func TestServeMetricsReportsBindFailure(t *testing.T) {
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if err := observability.ServeMetrics(t.Context(), l.Addr().String(), observability.NewMetrics().Handler()); err == nil {
		t.Error("expected bind error on an occupied port")
	}
}
