package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

func do(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))
	return rec
}

func TestMuxRoutes(t *testing.T) {
	mux := newMux(observability.NewReadiness(time.Second), nil)

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
	// Without a database there is no portal: the root is a plain 404.
	if rec := do(t, mux, http.MethodGet, "/"); rec.Code != http.StatusNotFound {
		t.Errorf("GET / without a portal = %d, want 404", rec.Code)
	}
}

func TestMuxMountsPortal(t *testing.T) {
	cfg := config.Default()
	cfg.OIDCProviders = []config.OIDCProvider{{
		Name: "dex", DisplayName: "Local dex", Issuer: "http://localhost:15556/dex",
		ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"},
	}}
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: cfg.TokenSignInMaxAge}, tokenstest.NewMemStore(), nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	portalHandler, err := newPortal(cfg, identitytest.NewMemStore(), noReader{}, tokenSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	mux := newMux(observability.NewReadiness(time.Second), portalHandler)

	if rec := do(t, mux, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200 (health stays outside the portal)", rec.Code)
	}
	rec := do(t, mux, http.MethodGet, "/")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin" {
		t.Errorf("GET / = %d %q, want redirect to /signin", rec.Code, rec.Header().Get("Location"))
	}
	rec = do(t, mux, http.MethodGet, "/signin")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Local dex") {
		t.Errorf("GET /signin = %d, want the sign-in page with the dex button", rec.Code)
	}
	if rec := do(t, mux, http.MethodGet, "/auth/dex/callback?code=1&state=2"); rec.Code != http.StatusBadRequest {
		t.Errorf("GET /auth/dex/callback = %d, want 400 (auth routes mounted)", rec.Code)
	}
	if rec := do(t, mux, http.MethodPost, "/auth/signout"); rec.Code != http.StatusForbidden {
		t.Errorf("anonymous POST /auth/signout = %d, want 403 (CSRF)", rec.Code)
	}
	if rec := do(t, mux, http.MethodGet, "/tokens"); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin") {
		t.Errorf("anonymous GET /tokens = %d %q, want redirect to /signin (token pages mounted)", rec.Code, rec.Header().Get("Location"))
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

// noReader is an audit.Reader with nothing to show.
type noReader struct{}

func (noReader) ListForUser(context.Context, string, audit.Filter, audit.Page) ([]audit.Record, error) {
	return nil, nil
}
func (noReader) AdminSearch(context.Context, audit.Filter, audit.Page) ([]audit.Record, error) {
	return nil, nil
}
