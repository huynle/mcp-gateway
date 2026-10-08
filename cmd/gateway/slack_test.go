package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connections/connectionstest"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// TestSlackWiringFollowsTheConnectionsModule: without the connections
// service there is no notifier and no interactions endpoint; with it,
// both exist, the notifier joins the approvals MultiNotifier and the
// endpoint is mounted on the public mux ahead of the portal catch-all,
// refusing unsigned requests.
func TestSlackWiringFollowsTheConnectionsModule(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	n, err := newSlackNotifier(cfg, nil, log)
	if err != nil || n != nil {
		t.Fatalf("notifier without connections = %v, %v", n, err)
	}
	h, err := newSlackInteractions(nil, nil, audit.NopRecorder{}, log)
	if err != nil || h != nil {
		t.Fatalf("interactions without services = %v, %v", h, err)
	}

	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	connSvc, err := connections.New(connections.Config{BaseURL: cfg.BaseURL}, connectionstest.NewMemStore(), kp, connections.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	n, err = newSlackNotifier(cfg, connSvc, log)
	if err != nil || n == nil {
		t.Fatalf("notifier with connections = %v, %v", n, err)
	}
	// The approvals service takes the extra notifier (nil-safe: a nil
	// *SlackNotifier must not be added).
	var none *approvals.SlackNotifier
	svc, err := newApprovals(cfg, nil, kp, audit.NopRecorder{}, observability.NewMetrics(), func(string) string { return "" }, log, none)
	if err != nil || svc == nil {
		t.Fatalf("newApprovals with nil extra = %v, %v", svc, err)
	}
	svc, err = newApprovals(cfg, nil, kp, audit.NopRecorder{}, observability.NewMetrics(), func(string) string { return "" }, log, n)
	if err != nil || svc == nil {
		t.Fatalf("newApprovals with notifier = %v, %v", svc, err)
	}
	h, err = newSlackInteractions(svc, connSvc, audit.NopRecorder{}, log)
	if err != nil || h == nil {
		t.Fatalf("interactions = %v, %v", h, err)
	}
	portal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	mux := newMux(observability.NewReadiness(time.Second), portal, nil, h)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/slack/interactions", strings.NewReader("payload=%7B%7D"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unsigned POST /slack/interactions = %d, want 401 (endpoint mounted, signature checked)", rec.Code)
	}
	// Everything else still reaches the portal; without the handler the
	// path falls through to it.
	if rec := do(t, mux, http.MethodGet, "/approvals"); rec.Code != http.StatusTeapot {
		t.Errorf("GET /approvals = %d, want the portal", rec.Code)
	}
	mux = newMux(observability.NewReadiness(time.Second), portal, nil, nil)
	if rec := do(t, mux, http.MethodPost, "/slack/interactions"); rec.Code != http.StatusTeapot {
		t.Errorf("POST /slack/interactions without the handler = %d, want the portal", rec.Code)
	}
}
