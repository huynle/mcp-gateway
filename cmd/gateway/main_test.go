package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/observability"
)

func do(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))
	return rec
}

func TestMuxRoutes(t *testing.T) {
	mux := newMux(observability.NewReadiness(time.Second))

	if rec := do(t, mux, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", rec.Code)
	}

	rec := do(t, mux, http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz = %d, want 200 with no checks registered", rec.Code)
	}
	var body struct {
		Status string `json:"status"`
		Checks []any  `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("readyz body %q: %v", rec.Body.String(), err)
	}
	if body.Status != "ok" || body.Checks == nil || len(body.Checks) != 0 {
		t.Errorf("readyz body = %s, want status ok and an empty checks list", rec.Body.String())
	}

	if rec := do(t, mux, http.MethodPost, "/healthz"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz = %d, want 405", rec.Code)
	}
	if rec := do(t, mux, http.MethodGet, "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", rec.Code)
	}
}

func TestOpenStoreIsOptional(t *testing.T) {
	readiness := observability.NewReadiness(time.Second)
	st, err := openStore(t.Context(), config.Config{}, readiness, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("openStore without DatabaseURL: %v", err)
	}
	if st != nil {
		t.Fatal("openStore without DatabaseURL returned a store")
	}
	report, ready := readiness.Run(t.Context())
	if !ready || len(report.Checks) != 0 {
		t.Errorf("no checks should be registered without a database, got %+v", report)
	}
}

func TestOpenStoreRefusesUnreachableDatabase(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cfg := config.Config{
		DatabaseURL:     "postgres://gateway_app:x@127.0.0.1:1/gateway?sslmode=disable&connect_timeout=1",
		JobsDatabaseURL: "postgres://gateway_jobs:x@127.0.0.1:1/gateway?sslmode=disable&connect_timeout=1",
	}
	_, err := openStore(ctx, cfg, observability.NewReadiness(time.Second), slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("openStore with an unreachable database returned no error")
	}
}
