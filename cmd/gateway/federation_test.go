package main

import (
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// Without a database or key provider the federation is not wired: no
// routes, and the decider and account source are the ones passed in.
func TestFederationNotMountedWithoutKeys(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	fed, err := newFederation(t.Context(), config.Default(), nil, nil, connectors.NewRegistry(), nil, nil, nil, log)
	if err != nil || fed != nil {
		t.Fatalf("newFederation without store/keys = %v, %v; want nil, nil", fed, err)
	}
	mux := newMux(observability.NewReadiness(time.Second), nil, nil, nil, withFederationRoutes(fed))
	for _, path := range []string{tunnel.ConnectPath, auth.ClientMetadataPath} {
		if rec := do(t, mux, http.MethodGet, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s without federation = %d, want 404", path, rec.Code)
		}
	}
	base := connectors.NewStaticAccountSource()
	if federationAccounts(fed, base) != connectors.AccountSource(base) {
		t.Error("account source replaced without a federation")
	}
	if federationDecider(fed, nil) != nil {
		t.Error("decider replaced without a federation")
	}
	p, err := mcp.NewPipeline(mcp.AuthenticateStage(), mcp.DispatchStage())
	if err != nil {
		t.Fatal(err)
	}
	if err := withFederationPrecheck(fed, log)(p, nil); err != nil || len(p.Names()) != 2 {
		t.Errorf("precheck without a federation: %v, stages %v", err, p.Names())
	}
	// No federation, no gateway.* tools: every wrapper passes through.
	reg := connectors.NewRegistry()
	gw, err := newGatewayTools(fed, nil, reg, nil, nil, "https://gw.example.com", log)
	if err != nil || gw != nil {
		t.Fatalf("newGatewayTools without federation = %v, %v", gw, err)
	}
	if len(reg.List()) != 0 {
		t.Error("gateway tools registered without a federation")
	}
	if gw.Accounts(base) != connectors.AccountSource(base) || gw.Decider(nil) != nil || gw.Setting(nil) != nil {
		t.Error("nil gateway tools changed a wrapper")
	}
}
