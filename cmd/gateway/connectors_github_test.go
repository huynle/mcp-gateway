package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

// The GitHub connector is registered whenever the connections service is
// mounted (its tokens come from there), before any admin registers the
// GitHub vendor app: its tools exist, list no accounts for a user who has
// not connected, and fail with a clear "no connected account" error
// rather than a crash when called without one.
func TestRegisterConnectorsRegistersGitHubWithConnections(t *testing.T) {
	ctx := context.Background()
	connSvc, _ := newMemConnections(t)
	registry := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"get_me", "search_issues", "get_issue", "get_pull_request", "list_pull_request_files", "create_issue", "add_issue_comment", "create_pull_request", "create_branch", "list_accounts"} {
		if _, ok := registry.Get("github." + name); !ok {
			t.Errorf("github.%s missing from the registry", name)
		}
	}
	n := 0
	for _, tool := range registry.List() {
		if tool.App == github.App {
			n++
		}
	}
	if n != 10 {
		t.Errorf("registry has %d github tools, want 10 (fake flag off)", n)
	}
	accts, err := src.ListAccounts(ctx, userAlice, github.App)
	if err != nil || len(accts) != 0 {
		t.Errorf("accounts before connecting = %+v, %v; want none", accts, err)
	}
	tool, _ := registry.Get("github.get_me")
	_, err = tool.Handler(ctx, connectors.Call{Tool: "github.get_me", Principal: connectors.Principal{UserID: userAlice}, Args: map[string]any{}})
	var ghErr *github.Error
	if !errors.As(err, &ghErr) || ghErr.Class != github.ClassNoAccount {
		t.Errorf("get_me without an account: err = %v, want class %s", err, github.ClassNoAccount)
	}
}

// Without the connections service (no key provider) GitHub tokens cannot
// exist, so the connector is not registered.
func TestRegisterConnectorsSkipsGitHubWithoutConnections(t *testing.T) {
	registry := connectors.NewRegistry()
	if _, err := registerConnectors(config.Config{}, registry, nil, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if n := len(registry.List()); n != 0 {
		t.Errorf("registry has %d tools without connections, want 0", n)
	}
}
