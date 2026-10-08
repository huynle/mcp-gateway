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
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
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
	mux := newMux(observability.NewReadiness(time.Second), nil, nil)

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
	// Without a database there is no portal and no /mcp: plain 404s.
	if rec := do(t, mux, http.MethodGet, "/"); rec.Code != http.StatusNotFound {
		t.Errorf("GET / without a portal = %d, want 404", rec.Code)
	}
	if rec := do(t, mux, http.MethodPost, "/mcp"); rec.Code != http.StatusNotFound {
		t.Errorf("POST /mcp without a database = %d, want 404", rec.Code)
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
	policySvc, err := policy.New(policytest.NewMemStore(), policy.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	registry := connectors.NewRegistry()
	accounts, err := registerConnectors(cfg, registry, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	portalHandler, err := newPortal(cfg, identitytest.NewMemStore(), noReader{}, tokenSvc, policySvc, registry, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	mcpHandler, err := newMCP(cfg, registry, accounts, tokenSvc, policySvc, audit.NopRecorder{}, observability.NewMetrics(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newMCP: %v", err)
	}
	mux := newMux(observability.NewReadiness(time.Second), portalHandler, mcpHandler)

	if rec := do(t, mux, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200 (health stays outside the portal)", rec.Code)
	}
	// /mcp is mounted behind the bearer middleware for every method, with
	// the RFC 9728 pointer in the challenge; health stays public.
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		rec := do(t, mux, method, "/mcp")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s /mcp = %d, want 401", method, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `resource_metadata="`+cfg.BaseURL+`/.well-known/oauth-protected-resource"`) {
			t.Errorf("%s /mcp WWW-Authenticate = %q", method, got)
		}
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

func TestRegisterConnectorsHonoursFakeFlag(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	off := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{}, off, log)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(off.List()); n != 0 {
		t.Errorf("flag off: %d tools registered, want 0", n)
	}
	if accts, _ := src.ListAccounts(ctx, "anyone", "fake"); len(accts) != 0 {
		t.Errorf("flag off: accounts %+v", accts)
	}

	on := connectors.NewRegistry()
	src, err = registerConnectors(config.Config{EnableFakeConnector: true}, on, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := on.Get("fake.list_accounts"); !ok {
		t.Error("flag on: fake.list_accounts missing")
	}
	if _, ok := on.Get("fake.create_item"); !ok {
		t.Error("flag on: fake.create_item missing")
	}
	// Local development: every user gets one fake company account on first use.
	accts, err := src.ListAccounts(ctx, "user-x", "fake")
	if err != nil || len(accts) != 1 || accts[0].Label != connectors.LabelCompany {
		t.Errorf("flag on: auto account = %+v, %v", accts, err)
	}
}

func TestNewMCPBuildsPipelineWithAccountStage(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	cfg.EnableFakeConnector = true
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: cfg.TokenSignInMaxAge}, tokenstest.NewMemStore(), nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	registry := connectors.NewRegistry()
	accounts, err := registerConnectors(cfg, registry, log)
	if err != nil {
		t.Fatal(err)
	}
	policySvc, err := policy.New(policytest.NewMemStore(), policy.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	h, err := newMCP(cfg, registry, accounts, tokenSvc, policySvc, audit.NopRecorder{}, observability.NewMetrics(), log)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Fatal("nil handler")
	}
	if len(registry.List()) == 0 {
		t.Error("fake connector not registered")
	}
}
