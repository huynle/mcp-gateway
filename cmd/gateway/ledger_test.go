package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/ledger/ledgertest"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

// TestNewLedgerReadsItsSettings: the service reads GATEWAY_LEDGER_* and
// is built with or without approvals (an approval then cannot be
// consumed, which only matters for confirmed calls).
func TestNewLedgerReadsItsSettings(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	registry := connectors.NewRegistry()
	env[ledger.EnvStaleAfter] = "bogus"
	if _, err := newLedger(cfg, ledgertest.NewMemStore(), registry, nil, audit.NopRecorder{}, observability.NewMetrics(), get, log); err == nil {
		t.Error("bad GATEWAY_LEDGER_STALE_AFTER accepted")
	}
	env[ledger.EnvStaleAfter] = "3m"
	env[ledger.EnvIdempotencyWindow] = "12h"
	svc, err := newLedger(cfg, ledgertest.NewMemStore(), registry, nil, audit.NopRecorder{}, observability.NewMetrics(), get, log)
	if err != nil || svc == nil {
		t.Fatalf("newLedger = %v, %v", svc, err)
	}
	if c := svc.Config(); c.StaleAfter != 3*time.Minute || c.IdempotencyWindow != 12*time.Hour || c.BaseURL != cfg.BaseURL {
		t.Errorf("config = %+v", c)
	}
}

// TestLedgerWiring: the stage sits before ratelimit, the confirm handler
// defers consumption to it, the jobs are registered and the portal page
// is mounted.
func TestLedgerWiring(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	cfg.EnableFakeConnector = true
	cfg.OIDCProviders = []config.OIDCProvider{{Name: "dex", DisplayName: "Local dex", Issuer: "http://localhost:15556/dex", ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}}
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
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
	accounts, err := registerConnectors(cfg, registry, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	approvalSvc, err := newApprovals(cfg, nil, keys, audit.NopRecorder{}, observability.NewMetrics(), get, log)
	if err != nil {
		t.Fatal(err)
	}
	ledgerSvc, err := newLedger(cfg, ledgertest.NewMemStore(), registry, approvalSvc, audit.NopRecorder{}, observability.NewMetrics(), get, log)
	if err != nil {
		t.Fatal(err)
	}

	stages, confirm := mcpStages(t, cfg, registry, accounts, tokenSvc, policySvc, approvalSvc, ledgerSvc, log)
	if !strings.Contains(stages, "policy,ledger,ratelimit") {
		t.Errorf("stages = %s", stages)
	}
	if !confirm {
		t.Error("the confirm handler does not defer consumption to the ledger")
	}

	list := ledgerJobs(ledgerSvc)
	var names []string
	for _, j := range list {
		names = append(names, j.Name())
	}
	if got := strings.Join(names, ","); got != "ledger.reconcile,ledger.sweep_stale" {
		t.Errorf("jobs = %s", got)
	}

	portalHandler, err := newPortal(cfg, identitytest.NewMemStore(), noReader{}, tokenSvc, policySvc, approvalSvc, nil, registry, log, withOperationsPage(ledgerSvc))
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	if rec := do(t, portalHandler, http.MethodGet, "/operations"); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin") {
		t.Errorf("anonymous GET /operations = %d %q, want redirect to /signin (page mounted)", rec.Code, rec.Header().Get("Location"))
	}
}

// mcpStages builds /mcp with the ledger stage and reports the stage order
// and whether the confirm handler is in deferred mode.
func mcpStages(t *testing.T, cfg config.Config, registry *connectors.Registry, accounts connectors.AccountSource, tokenSvc *tokens.Service, policySvc *policy.Service, approvalSvc *approvals.Service, ledgerSvc *ledger.Service, log *slog.Logger) (string, bool) {
	t.Helper()
	var stages string
	var deferred bool
	capture := func(p *mcp.Pipeline, confirm mcp.ConfirmHandler) error {
		stages = strings.Join(p.Names(), ",")
		if h, ok := confirm.(*approvals.ConfirmHandler); ok {
			deferred = h.Deferred()
		}
		return nil
	}
	if _, err := newMCP(cfg, registry, accounts, tokenSvc, policySvc, approvalSvc, audit.NopRecorder{}, observability.NewMetrics(), log, withLedgerStage(ledgerSvc), capture); err != nil {
		t.Fatalf("newMCP: %v", err)
	}
	return stages, deferred
}
