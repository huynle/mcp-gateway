package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// The Google connector's apps (calendar, tasks, gmail, drive, docs, sheets, contacts) are
// registered whenever the connections service is mounted, before any
// admin registers the Google vendor apps: their tools exist, list no
// accounts for a user who has not connected, and fail with a clear "no
// connected account" error rather than a crash when called without one.
func TestRegisterConnectorsRegistersGoogleWithConnections(t *testing.T) {
	ctx := context.Background()
	connSvc, _ := newMemConnections(t)
	registry := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"calendar.list_events", "calendar.get_event", "calendar.create_event", "calendar.list_accounts",
		"tasks.list", "tasks.create", "tasks.list_accounts",
		"gmail.search", "gmail.get_message", "gmail.list_labels", "gmail.send", "gmail.create_draft", "gmail.list_accounts",
	}
	for _, name := range want {
		if _, ok := registry.Get(name); !ok {
			t.Errorf("%s missing from the registry", name)
		}
	}
	for _, app := range google.Apps {
		accts, err := src.ListAccounts(ctx, userAlice, app)
		if err != nil || len(accts) != 0 {
			t.Errorf("%s accounts before connecting = %+v, %v; want none", app, accts, err)
		}
	}
	tool, _ := registry.Get("gmail.list_labels")
	_, err = tool.Handler(ctx, connectors.Call{Tool: "gmail.list_labels", Principal: connectors.Principal{UserID: userAlice}, Args: map[string]any{}})
	var gerr *google.Error
	if !errors.As(err, &gerr) || gerr.Class != google.ClassNoAccount {
		t.Errorf("list_labels without an account: err = %v, want class %s", err, google.ClassNoAccount)
	}
}
