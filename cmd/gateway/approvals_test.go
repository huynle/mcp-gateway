package main

import (
	"bytes"
	"log/slog"
	"net/http"
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

// TestNewApprovalsNeedsAKeyProvider: without a key provider the service
// is not built (and nothing fails); with one it reads its settings from
// the environment and the portal and pipeline get wired.
func TestNewApprovalsNeedsAKeyProvider(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	svc, err := newApprovals(cfg, nil, nil, audit.NopRecorder{}, observability.NewMetrics(), get, log)
	if err != nil || svc != nil {
		t.Fatalf("without keys = %v, %v", svc, err)
	}
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	env["GATEWAY_APPROVAL_WAIT"] = "bogus"
	if _, err := newApprovals(cfg, nil, keys, audit.NopRecorder{}, observability.NewMetrics(), get, log); err == nil {
		t.Error("bad GATEWAY_APPROVAL_WAIT accepted")
	}
	env["GATEWAY_APPROVAL_WAIT"] = "10s"
	env["GATEWAY_APPROVAL_TTL"] = "20m"
	svc, err = newApprovals(cfg, nil, keys, audit.NopRecorder{}, observability.NewMetrics(), get, log)
	if err != nil || svc == nil {
		t.Fatalf("with keys = %v, %v", svc, err)
	}
	if c := svc.Config(); c.Wait != 10*time.Second || c.TTL != 20*time.Minute || svc.PortalURL() != cfg.BaseURL+"/approvals" {
		t.Errorf("config = %+v, portal %s", c, svc.PortalURL())
	}

	cfg.OIDCProviders = []config.OIDCProvider{{Name: "dex", DisplayName: "Local dex", Issuer: "http://localhost:15556/dex", ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}}
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: cfg.TokenSignInMaxAge}, tokenstest.NewMemStore(), nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	policySvc, err := policy.New(policytest.NewMemStore(), policy.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	registry := connectors.NewRegistry()
	accounts, err := registerConnectors(cfg, registry, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	portalHandler, err := newPortal(cfg, identitytest.NewMemStore(), noReader{}, tokenSvc, policySvc, svc, nil, registry, nil, nil, log)
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	for _, path := range []string{"/approvals", "/approvals/history"} {
		if rec := do(t, portalHandler, http.MethodGet, path); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin") {
			t.Errorf("anonymous GET %s = %d %q, want redirect to /signin (approval pages mounted)", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := do(t, portalHandler, http.MethodPost, "/approvals/x/approve"); rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous POST approve = %d, want redirect to sign-in (mounted behind the portal)", rec.Code)
	}
	if _, err := newMCP(cfg, registry, accounts, tokenSvc, policySvc, svc, audit.NopRecorder{}, observability.NewMetrics(), log); err != nil {
		t.Fatalf("newMCP with approvals: %v", err)
	}
}

// TestStartJobsWithNothingToRun: no jobs, no runner.
func TestStartJobsWithNothingToRun(t *testing.T) {
	r, err := startJobs(t.Context(), nil, slog.New(slog.DiscardHandler))
	if err != nil || r != nil {
		t.Errorf("startJobs() = %v, %v", r, err)
	}
}
