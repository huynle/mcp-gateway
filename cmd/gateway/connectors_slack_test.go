package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// The Slack connector is registered whenever the connections service is
// mounted, before any admin registers the Slack vendor app: its tools
// exist, list no accounts for a user who has not connected, fail with a
// clear "no connected account" error when called without one, and the
// two message writes declare reconciliation none (no marker_reconcile
// extra yet).
func TestRegisterConnectorsRegistersSlackWithConnections(t *testing.T) {
	ctx := context.Background()
	connSvc, _ := newMemConnections(t)
	registry := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"list_channels", "read_channel_history", "get_thread", "search_messages", "get_user", "post_message", "reply_in_thread", "add_reaction", "list_accounts"} {
		if _, ok := registry.Get("slack." + name); !ok {
			t.Errorf("slack.%s missing from the registry", name)
		}
	}
	accts, err := src.ListAccounts(ctx, userAlice, slack.App)
	if err != nil || len(accts) != 0 {
		t.Errorf("accounts before connecting = %+v, %v; want none", accts, err)
	}
	tool, _ := registry.Get("slack.get_user")
	_, err = tool.Handler(ctx, connectors.Call{Tool: "slack.get_user", Principal: connectors.Principal{UserID: userAlice}, Args: map[string]any{"user": "U0BOB00002"}})
	var sErr *slack.Error
	if !errors.As(err, &sErr) || sErr.Class != slack.ClassNoAccount {
		t.Errorf("get_user without an account: err = %v, want class %s", err, slack.ClassNoAccount)
	}
	for _, name := range []string{"post_message", "reply_in_thread"} {
		tool, _ := registry.Get("slack." + name)
		if tool.Reconcile.Kind != connectors.ReconcileNone {
			t.Errorf("slack.%s: Reconcile = %q, want none without marker_reconcile", name, tool.Reconcile.Kind)
		}
	}
}

// marker_reconcile=true on the Slack vendor app, present at start-up,
// turns the message writes into marker-reconciled ones.
func TestRegisterConnectorsSlackMarkerReconcileFromVendorApp(t *testing.T) {
	ctx := context.Background()
	connSvc, _ := newMemConnections(t)
	app := connections.Defaults(connections.VendorSlack, "")
	app.ClientID, app.ClientSecret = "slack-cid", "slack-secret"
	app.Extra[slack.ExtraMarkerReconcile] = "true"
	if _, err := connSvc.SaveVendorApp(ctx, userAlice, app); err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	registry := connectors.NewRegistry()
	if _, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"post_message", "reply_in_thread"} {
		tool, _ := registry.Get("slack." + name)
		if tool.Reconcile.Kind != connectors.ReconcileMarker || tool.Reconcile.Check == nil {
			t.Errorf("slack.%s: Reconcile = %q, want marker with a Check", name, tool.Reconcile.Kind)
		}
	}
}

// Without the connections service (no key provider) Slack tokens cannot
// exist, so the connector is not registered.
func TestRegisterConnectorsSkipsSlackWithoutConnections(t *testing.T) {
	registry := connectors.NewRegistry()
	if _, err := registerConnectors(config.Config{}, registry, nil, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Get("slack.list_channels"); ok {
		t.Error("slack registered without connections")
	}
}
