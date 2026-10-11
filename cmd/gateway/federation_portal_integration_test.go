//go:build integration

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// The servers portal and the upstream OAuth connect routes are mounted
// together on the real portal (a conflicting pattern would panic here) and
// sit behind the signed-in check.
func TestIntegrationServersPortalMounted(t *testing.T) {
	st := openFederationStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	cfg.BaseURL = "http://gateway.test"
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{5}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	policySvc, err := policy.New(policytest.NewMemStore(), policy.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	registry := connectors.NewRegistry()
	fed, err := newFederation(ctx, cfg, st, keys, registry, policySvc, observability.NewMetrics(), log)
	if err != nil || fed == nil {
		t.Fatalf("newFederation = %v, %v", fed, err)
	}
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: time.Hour}, tokenstest.NewMemStore(), nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	portalHandler, err := newPortal(cfg, identitytest.NewMemStore(), noReader{}, tokenSvc, policySvc, nil, nil, registry, log,
		withFederationPages(fed, st, cfg.BaseURL))
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	srv := httptest.NewServer(newMux(observability.NewReadiness(time.Second), portalHandler, nil, nil, withFederationRoutes(fed)))
	defer srv.Close()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, path := range []string{"/servers", "/servers/new", "/servers/00000000-0000-0000-0000-000000000001", "/servers/00000000-0000-0000-0000-000000000001/connect"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		res, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/signin") {
			t.Errorf("anonymous GET %s = %d %q, want a redirect to sign-in (route mounted behind the session)", path, res.StatusCode, res.Header.Get("Location"))
		}
	}
}
