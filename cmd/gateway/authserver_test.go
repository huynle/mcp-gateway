package main

import (
	"bytes"
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
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

func TestNewAuthServerNeedsAKeyProvider(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	cfg := config.Config{BaseURL: "https://gw.example.com", TokenSignInMaxAge: 30 * 24 * time.Hour}
	svc, err := newAuthServer(cfg, nil, nil, audit.NopRecorder{}, observability.NewMetrics(), func(string) string { return "" }, log)
	if err != nil || svc != nil {
		t.Fatalf("without keys: %v, %v; want nil, nil", svc, err)
	}
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	get := func(k string) string {
		if k == "GATEWAY_OAUTH_ACCESS_TOKEN_TTL" {
			return "30m"
		}
		return ""
	}
	svc, err = newAuthServer(cfg, nil, keys, audit.NopRecorder{}, observability.NewMetrics(), get, log)
	if err != nil || svc == nil {
		t.Fatalf("with keys: %v, %v", svc, err)
	}
	if c := svc.Config(); c.Issuer != cfg.BaseURL || c.Resource() != "https://gw.example.com/mcp" || c.AccessTokenTTL != 30*time.Minute || c.SignInMaxAge != cfg.TokenSignInMaxAge {
		t.Errorf("config = %+v", c)
	}
	bad := func(k string) string {
		if k == "GATEWAY_OAUTH_REGISTER_PER_MIN" {
			return "zero"
		}
		return ""
	}
	if _, err := newAuthServer(cfg, nil, keys, audit.NopRecorder{}, observability.NewMetrics(), bad, log); err == nil {
		t.Error("bad GATEWAY_OAUTH_REGISTER_PER_MIN accepted")
	}
}

// The OAuth routes are on the public mux, the harness pages behind the
// portal, and /mcp authenticates through the composite authenticator.
func TestOAuthWiring(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	cfg := config.Config{BaseURL: "https://gw.example.com", TokenSignInMaxAge: 30 * 24 * time.Hour, OIDCProviders: nil, SessionIdleTimeout: time.Hour, SessionAbsoluteTimeout: 2 * time.Hour, DefaultRole: "member", RateUserPerMin: 60, RateAppPerMin: 600}
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	authSvc, err := newAuthServer(cfg, nil, keys, audit.NopRecorder{}, observability.NewMetrics(), func(string) string { return "" }, log)
	if err != nil {
		t.Fatal(err)
	}
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: cfg.TokenSignInMaxAge}, tokenstest.NewMemStore(), nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	policySvc, err := policy.New(policytest.NewMemStore(), policy.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	registry := connectors.NewRegistry()
	portalHandler, err := newPortal(cfg, identitytest.NewMemStore(), noReader{}, tokenSvc, policySvc, nil, nil, registry, nil, nil, log, withHarnessPages(authSvc))
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	auth := composeAuthenticator(tokenSvc, authSvc)
	if auth == tokens.Authenticator(tokenSvc) {
		t.Error("composeAuthenticator returned the bare token service with an authorization server present")
	}
	if composeAuthenticator(tokenSvc, nil) != tokens.Authenticator(tokenSvc) {
		t.Error("composeAuthenticator without an authorization server should be the token service")
	}
	mcpHandler, err := newMCP(cfg, registry, connectors.NewStaticAccountSource(), auth, policySvc, nil, audit.NopRecorder{}, observability.NewMetrics(), log)
	if err != nil {
		t.Fatal(err)
	}
	mux := newMux(observability.NewReadiness(time.Second), portalHandler, mcpHandler, nil, withOAuthRoutes(authSvc))

	rec := do(t, mux, http.MethodGet, "/.well-known/oauth-authorization-server")
	if rec.Code != http.StatusOK {
		t.Fatalf("AS metadata: %d", rec.Code)
	}
	var meta map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if meta["issuer"] != cfg.BaseURL || meta["token_endpoint"] != cfg.BaseURL+"/oauth/token" {
		t.Errorf("metadata = %v", meta)
	}
	// (/oauth/jwks needs the store; the authserver package's end-to-end
	// test covers it.)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		if rec := do(t, mux, http.MethodGet, path); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", path, rec.Code)
		}
	}
	if rec := do(t, mux, http.MethodPost, "/oauth/token"); rec.Code != http.StatusBadRequest {
		t.Errorf("POST /oauth/token without a body = %d, want 400", rec.Code)
	}
	// Harness pages are behind the portal's sign-in check.
	for _, path := range []string{"/oauth/authorize?client_id=x", "/harnesses"} {
		rec := do(t, mux, http.MethodGet, path)
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin?return_to=") {
			t.Errorf("GET %s anonymous = %d %q", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	// A JWT-shaped bearer reaches the OAuth authenticator (401 invalid_token,
	// not "malformed token").
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer aaaa.bbbb.cccc")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "resource_metadata=") {
		t.Errorf("JWT-shaped bearer on /mcp: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// Without an authorization server the routes are absent.
	plain := newMux(observability.NewReadiness(time.Second), nil, nil, nil, withOAuthRoutes(nil))
	if rec := do(t, plain, http.MethodGet, "/.well-known/oauth-authorization-server"); rec.Code != http.StatusNotFound {
		t.Errorf("metadata without an authorization server = %d", rec.Code)
	}
	if jobs := authServerJobs(nil); jobs != nil {
		t.Errorf("jobs without an authorization server = %v", jobs)
	}
	if jobs := authServerJobs(authSvc); len(jobs) != 2 {
		t.Errorf("jobs = %d, want prune + key rotation", len(jobs))
	}
}
