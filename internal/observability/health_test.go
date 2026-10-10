package observability_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/observability"
)

type readyResponse struct {
	Status string `json:"status"`
	Checks []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	} `json:"checks"`
}

func getReady(t *testing.T, h http.Handler) (int, readyResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
	var body readyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	return rec.Code, body
}

func TestLivenessAlwaysOK(t *testing.T) {
	rec := httptest.NewRecorder()
	observability.Liveness().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadinessWithNoChecksIsOKAndListsZero(t *testing.T) {
	r := observability.NewReadiness(time.Second)
	code, body := getReady(t, r)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body.Status != "ok" {
		t.Errorf("status field = %q, want ok", body.Status)
	}
	if body.Checks == nil || len(body.Checks) != 0 {
		t.Errorf("checks = %#v, want an empty (non-null) list", body.Checks)
	}
}

func TestReadinessReportsPassingChecksInRegistrationOrder(t *testing.T) {
	r := observability.NewReadiness(time.Second)
	r.Register("database", func(context.Context) error { return nil })
	r.Register("key-provider", func(context.Context) error { return nil })
	code, body := getReady(t, r)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(body.Checks) != 2 || body.Checks[0].Name != "database" || body.Checks[1].Name != "key-provider" {
		t.Fatalf("checks = %+v, want database then key-provider", body.Checks)
	}
	for _, c := range body.Checks {
		if c.Status != "ok" || c.Error != "" {
			t.Errorf("check %s = %+v, want ok with no error", c.Name, c)
		}
	}
}

func TestReadinessFailsWhenAnyCheckFails(t *testing.T) {
	r := observability.NewReadiness(time.Second)
	r.Register("database", func(context.Context) error { return nil })
	r.Register("schema", func(context.Context) error { return errors.New("schema version 3, want 4") })
	code, body := getReady(t, r)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", code)
	}
	if body.Status != "fail" {
		t.Errorf("status field = %q, want fail", body.Status)
	}
	if body.Checks[1].Status != "fail" || body.Checks[1].Error != "schema version 3, want 4" {
		t.Errorf("failing check = %+v", body.Checks[1])
	}
	if body.Checks[0].Status != "ok" {
		t.Errorf("passing check should still report ok, got %+v", body.Checks[0])
	}
}

func TestReadinessCheckTimesOut(t *testing.T) {
	r := observability.NewReadiness(20 * time.Millisecond)
	r.Register("slow", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	})
	start := time.Now()
	code, body := getReady(t, r)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("readiness took %v, the per-check timeout was not applied", elapsed)
	}
	if code != http.StatusServiceUnavailable || body.Checks[0].Status != "fail" {
		t.Fatalf("status = %d, checks = %+v; want 503 with slow marked fail", code, body.Checks)
	}
}

func TestReadinessRecoversFromPanickingCheck(t *testing.T) {
	r := observability.NewReadiness(time.Second)
	r.Register("boom", func(context.Context) error { panic("kaboom") })
	code, body := getReady(t, r)
	if code != http.StatusServiceUnavailable || body.Checks[0].Status != "fail" {
		t.Fatalf("status = %d, checks = %+v; want 503 with boom marked fail", code, body.Checks)
	}
}

func TestRegisterRejectsDuplicateAndEmptyNames(t *testing.T) {
	r := observability.NewReadiness(time.Second)
	r.Register("database", func(context.Context) error { return nil })
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected panic", name)
			}
		}()
		f()
	}
	mustPanic("duplicate", func() { r.Register("database", func(context.Context) error { return nil }) })
	mustPanic("empty", func() { r.Register("", func(context.Context) error { return nil }) })
	mustPanic("nil check", func() { r.Register("nil", nil) })
}
