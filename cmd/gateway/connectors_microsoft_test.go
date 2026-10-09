package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// The Microsoft connector is registered next to GitHub whenever the
// connections service is mounted: its ten tools plus list_accounts
// exist, a user who has not connected sees no accounts, and a call
// without an account fails with the connector's clear error.
func TestRegisterConnectorsRegistersMicrosoftWithConnections(t *testing.T) {
	ctx := context.Background()
	connSvc, _ := newMemConnections(t)
	registry := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"mail_search", "mail_get_message", "calendar_list_events", "drive_search", "teams_list_channels", "teams_read_channel_messages",
		"mail_send", "calendar_create_event", "drive_create_folder", "teams_post_channel_message", "list_accounts",
	} {
		if _, ok := registry.Get("microsoft." + name); !ok {
			t.Errorf("microsoft.%s missing from the registry", name)
		}
	}
	accts, err := src.ListAccounts(ctx, userAlice, microsoft.App)
	if err != nil || len(accts) != 0 {
		t.Errorf("accounts before connecting = %+v, %v; want none", accts, err)
	}
	tool, _ := registry.Get("microsoft.mail_search")
	_, err = tool.Handler(ctx, connectors.Call{Tool: "microsoft.mail_search", Principal: connectors.Principal{UserID: userAlice}, Args: map[string]any{}})
	var msErr *microsoft.Error
	if !errors.As(err, &msErr) || msErr.Class != microsoft.ClassNoAccount {
		t.Errorf("mail_search without an account: err = %v, want class %s", err, microsoft.ClassNoAccount)
	}
}
