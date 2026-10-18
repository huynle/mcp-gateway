package observability

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// EnvMetricsAddr names the listen address of the private metrics endpoint.
const EnvMetricsAddr = "GATEWAY_METRICS_ADDR"

// DefaultMetricsAddr is loopback only: the metrics port is private and the
// deployment (Helm) decides what may scrape it (decision v6piaxdb).
const DefaultMetricsAddr = "127.0.0.1:19090"

// MetricsAddr returns GATEWAY_METRICS_ADDR or DefaultMetricsAddr.
func MetricsAddr() string {
	if v := os.Getenv(EnvMetricsAddr); v != "" {
		return v
	}
	return DefaultMetricsAddr
}

// Metrics is the gateway's metric catalogue on a private registry: no Go
// runtime or process collectors, no default registry, and typed helpers so
// a label can only ever be one of the fixed vocabularies below. There is
// deliberately no method that takes a user, token, account or request ID.
type Metrics struct {
	reg *prometheus.Registry

	httpDuration     *prometheus.HistogramVec
	authFailures     *prometheus.CounterVec
	policyDecisions  *prometheus.CounterVec
	approvals        *prometheus.CounterVec
	ledgerOperations *prometheus.CounterVec
	refreshFailures  *prometheus.CounterVec
	vendorRateLimit  *prometheus.CounterVec
	auditPurged      prometheus.Counter
}

// NewMetrics builds the catalogue on a fresh registry. Call it once per
// process; every call creates an independent registry.
func NewMetrics() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency by route pattern, method and status.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"route", "method", "status"}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_failures_total",
			Help: "Failed authentications by reason (expired, revoked, malformed, stale_sign_in, ...).",
		}, []string{"reason"}),
		policyDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "policy_decisions_total",
			Help: "Policy decisions by outcome (allow, deny, confirm).",
		}, []string{"decision"}),
		approvals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "approvals_total",
			Help: "Approval transitions by state (pending, approved, denied, consumed, expired).",
		}, []string{"state"}),
		ledgerOperations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ledger_operations_total",
			Help: "Ledger operation transitions by state (in_progress, succeeded, failed, unknown, unresolved).",
		}, []string{"state"}),
		refreshFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "connection_refresh_failures_total",
			Help: "Vendor token refresh failures by app.",
		}, []string{"app"}),
		vendorRateLimit: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vendor_rate_limited_total",
			Help: "Vendor 429 responses by app.",
		}, []string{"app"}),
		auditPurged: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "audit_events_purged_total",
			Help: "Audit events deleted by the retention purge (audit.purge job).",
		}),
	}
	m.reg.MustRegister(m.httpDuration, m.authFailures, m.policyDecisions, m.approvals,
		m.ledgerOperations, m.refreshFailures, m.vendorRateLimit, m.auditPurged)
	return m
}

// AuditPurged counts audit events deleted by the retention purge.
func (m *Metrics) AuditPurged(n int) { m.auditPurged.Add(float64(n)) }

// Registry exposes the private registry for tests and for optional extra
// collectors wired by main.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// Handler serves the registry in Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ObserveHTTP records one request. route must be a route pattern
// ("POST /mcp", "GET /things/{id}"), never a raw path; HTTPMiddleware does
// this automatically.
func (m *Metrics) ObserveHTTP(route, method string, status int, d time.Duration) {
	m.httpDuration.WithLabelValues(route, method, strconv.Itoa(status)).Observe(d.Seconds())
}

// AuthFailure counts a failed authentication. reason is a short fixed
// string chosen by the caller (expired, revoked, malformed, ...).
func (m *Metrics) AuthFailure(reason string) { m.authFailures.WithLabelValues(reason).Inc() }

// PolicyDecision counts a policy outcome: allow, deny or confirm.
func (m *Metrics) PolicyDecision(decision string) {
	m.policyDecisions.WithLabelValues(decision).Inc()
}

// Approval counts an approval entering state.
func (m *Metrics) Approval(state string) { m.approvals.WithLabelValues(state).Inc() }

// LedgerOperation counts a ledger operation entering state.
func (m *Metrics) LedgerOperation(state string) { m.ledgerOperations.WithLabelValues(state).Inc() }

// ConnectionRefreshFailure counts a failed vendor token refresh for app.
func (m *Metrics) ConnectionRefreshFailure(app string) {
	m.refreshFailures.WithLabelValues(app).Inc()
}

// VendorRateLimited counts a 429 from app.
func (m *Metrics) VendorRateLimited(app string) { m.vendorRateLimit.WithLabelValues(app).Inc() }

// routeUnmatched labels requests no mux pattern claimed (404s, bad methods).
const routeUnmatched = "unmatched"

// HTTPMiddleware records http_request_duration_seconds for every request,
// labelled by the ServeMux pattern that handled it. Wrap the mux directly
// (the pattern is read from the request after the mux ran, so no handler
// between this middleware and the mux may replace the *http.Request).
// Requests no pattern matched are labelled "unmatched".
func (m *Metrics) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		route := r.Pattern
		if route == "" {
			route = routeUnmatched
		}
		m.ObserveHTTP(route, r.Method, sw.status(), time.Since(start))
	})
}

// statusWriter captures the status code. Unwrap lets http.ResponseController
// reach Flush, SetWriteDeadline and friends on the underlying writer, which
// streaming handlers (/mcp) rely on.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) status() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}

// ServeMetrics serves handler (normally Metrics.Handler) at /metrics on addr
// until ctx is cancelled, then shuts the listener down and returns nil.
// addr "" means MetricsAddr(). Bind failures are returned immediately so
// main can refuse to start without its metrics port. The server is separate
// from the public one so the port can be kept off the public load balancer.
func ServeMetrics(ctx context.Context, addr string, handler http.Handler) error {
	if addr == "" {
		addr = MetricsAddr()
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("observability: metrics listen %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", handler)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 1)
	go func() {
		err := srv.Serve(l)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
	}
	<-errc
	return nil
}
