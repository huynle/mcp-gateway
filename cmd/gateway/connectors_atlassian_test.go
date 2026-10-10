package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The Atlassian connector apps (jira, confluence) are registered whenever
// the connections service is mounted, before any admin registers the
// Atlassian vendor app: their tools exist, list no accounts for a user
// who has not connected, and fail with a clear "no connected account"
// error rather than a crash when called without one.
func TestRegisterConnectorsRegistersAtlassianWithConnections(t *testing.T) {
	ctx := context.Background()
	connSvc, _ := newMemConnections(t)
	registry := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"jira.search_issues", "jira.get_issue", "jira.list_transitions", "jira.create_issue", "jira.add_comment", "jira.transition_issue", "jira.list_accounts",
		"confluence.search", "confluence.get_page", "confluence.create_page", "confluence.list_accounts"} {
		if _, ok := registry.Get(name); !ok {
			t.Errorf("%s missing from the registry", name)
		}
	}
	for _, app := range []string{atlassian.JiraApp, atlassian.ConfluenceApp} {
		accts, err := src.ListAccounts(ctx, userAlice, app)
		if err != nil || len(accts) != 0 {
			t.Errorf("%s accounts before connecting = %+v, %v; want none", app, accts, err)
		}
	}
	tool, _ := registry.Get("jira.search_issues")
	_, err = tool.Handler(ctx, connectors.Call{Tool: "jira.search_issues", Principal: connectors.Principal{UserID: userAlice}, Args: map[string]any{"jql": "project = X"}})
	var aErr *atlassian.Error
	if !errors.As(err, &aErr) || aErr.Class != atlassian.ClassNoAccount {
		t.Errorf("search_issues without an account: err = %v, want class %s", err, atlassian.ClassNoAccount)
	}
}

// Both apps use atlassian accounts: a connection of vendor atlassian is
// listed under jira and confluence, and the site source resolves its
// cloud id from the external account id and the site URL from the
// display name the binder wrote.
func TestAtlassianSitesResolveFromTheConnection(t *testing.T) {
	ctx := context.Background()
	connSvc, mem := newMemConnections(t)
	registry := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	var connID string
	err = mem.Bypass(ctx, func(tx connections.Tx) error {
		app := &store.VendorApp{Vendor: connections.VendorAtlassian, Name: "default", ClientID: "cid", Enabled: true}
		if err := tx.UpsertVendorApp(ctx, app); err != nil {
			return err
		}
		conn := &store.Connection{
			UserID: userAlice, VendorAppID: app.ID, ExternalAccountID: "5b10ac8d82e05b22cc7d4ef5@11111111-2222-4333-8444-555555555555",
			Label: store.AccountCompany, DisplayName: "Alice Example @ https://example-site.atlassian.example.test", Status: store.ConnectionActive,
		}
		if err := tx.CreateConnection(ctx, conn); err != nil {
			return err
		}
		connID = conn.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{atlassian.JiraApp, atlassian.ConfluenceApp} {
		accts, err := src.ListAccounts(ctx, userAlice, app)
		if err != nil || len(accts) != 1 || accts[0].ID != connID || accts[0].App != app || accts[0].Label != connectors.LabelCompany {
			t.Errorf("%s accounts = %+v, %v; want the atlassian connection", app, accts, err)
		}
	}
	site, err := atlassianSites(connSvc)(ctx, userAlice, connID)
	if err != nil || site.CloudID != "11111111-2222-4333-8444-555555555555" || site.URL != "https://example-site.atlassian.example.test" {
		t.Errorf("site = %+v, %v", site, err)
	}
	if _, err := atlassianSites(connSvc)(ctx, userAlice, "00000000-0000-4000-8000-000000000000"); err == nil {
		t.Error("an unknown connection resolved to a site")
	}
	if _, err := atlassianSites(connSvc)(ctx, "someone-else", connID); err == nil {
		t.Error("another user's connection resolved to a site")
	}
}

func TestSiteURLFromDisplayName(t *testing.T) {
	for in, want := range map[string]string{
		"Alice @ https://acme.atlassian.net": "https://acme.atlassian.net",
		"Alice @ http://localhost:8080":      "http://localhost:8080",
		"Alice @ Acme":                       "",
		"Alice":                              "",
		"a @ b @ https://x.example":          "https://x.example",
	} {
		if got := siteURLFromDisplayName(in); got != want {
			t.Errorf("siteURLFromDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}
