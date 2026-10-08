package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Check reports whether a dependency is ready. A nil error means ready. The
// context carries the per-check timeout; checks must honor it.
type Check func(ctx context.Context) error

// Readiness is the /readyz handler: a registry of named checks that later
// modules (store, crypto, ...) register at startup. With no checks registered
// it reports ready. It is safe for concurrent use.
type Readiness struct {
	timeout time.Duration

	mu     sync.RWMutex
	checks []namedCheck
}

type namedCheck struct {
	name  string
	check Check
}

// CheckResult is the per-check entry in the /readyz response body.
type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Report is the /readyz response body.
type Report struct {
	Status string        `json:"status"`
	Checks []CheckResult `json:"checks"`
}

// NewReadiness returns an empty registry. Each check gets at most timeout to
// answer; a check that does not return in time is reported as failed.
func NewReadiness(timeout time.Duration) *Readiness {
	if timeout <= 0 {
		panic("observability: readiness timeout must be positive")
	}
	return &Readiness{timeout: timeout}
}

// Register adds a check under a unique, non-empty name. Checks run in
// registration order. Register panics on programmer errors (empty or duplicate
// name, nil check) because registration happens once at startup.
func (r *Readiness) Register(name string, check Check) {
	if name == "" {
		panic("observability: readiness check name must not be empty")
	}
	if check == nil {
		panic(fmt.Sprintf("observability: readiness check %q is nil", name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.checks {
		if c.name == name {
			panic(fmt.Sprintf("observability: readiness check %q registered twice", name))
		}
	}
	r.checks = append(r.checks, namedCheck{name: name, check: check})
}

// Run executes every registered check and returns the aggregate report and
// whether all checks passed.
func (r *Readiness) Run(ctx context.Context) (Report, bool) {
	r.mu.RLock()
	checks := make([]namedCheck, len(r.checks))
	copy(checks, r.checks)
	r.mu.RUnlock()

	report := Report{Status: "ok", Checks: make([]CheckResult, 0, len(checks))}
	ready := true
	for _, c := range checks {
		res := CheckResult{Name: c.name, Status: "ok"}
		if err := r.runOne(ctx, c.check); err != nil {
			ready = false
			res.Status = "fail"
			res.Error = err.Error()
		}
		report.Checks = append(report.Checks, res)
	}
	if !ready {
		report.Status = "fail"
	}
	return report, ready
}

// runOne runs a single check with the timeout applied and panics converted
// into errors so one misbehaving dependency cannot take the probe down.
func (r *Readiness) runOne(ctx context.Context, check Check) (err error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("check panicked: %v", p)
			}
		}()
		done <- check(ctx)
	}()

	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("check timed out after %v", r.timeout)
	}
}

// ServeHTTP answers 200 when every check passes and 503 otherwise, always
// with a JSON Report body.
func (r *Readiness) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	report, ready := r.Run(req.Context())
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, report)
}

// Liveness is the /healthz handler. It only proves the process is serving
// HTTP; dependency state belongs to readiness.
func Liveness() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
