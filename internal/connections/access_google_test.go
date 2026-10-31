package connections_test

import (
	"context"
	"slices"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// TestMissingAccessGooglePersonalSkipsDirectory: a personal Google
// account can never grant the Workspace-only scopes, so its gap neither
// asks for directory.readonly nor promises the directory tools; a company
// account's does. Connect (which cannot know the account yet) leaves the
// directory to grant more access.
func TestMissingAccessGooglePersonalSkipsDirectory(t *testing.T) {
	env := newTestEnv(t)
	app := connections.Defaults(connections.VendorGoogle, connections.GoogleExternal)
	app.ClientID, app.ClientSecret = "g-client", "g-secret"
	if _, err := env.svc.SaveVendorApp(context.Background(), userAlice, app); err != nil {
		t.Fatal(err)
	}
	env.svc.SetToolCatalog(catalogRegistry(t, env.svc), policyVisibility(t))
	ctx := context.Background()
	base := []string{"openid", google.ScopeContactsReadonly}
	info := func(label string) connections.Info {
		return connections.Info{ID: "g-1", Vendor: connections.VendorGoogle, Variant: connections.GoogleExternal, Label: label, Status: "active", Scopes: base}
	}
	directoryTools := []string{"contacts.search_directory", "contacts.list_directory"}

	personal, err := env.svc.MissingAccess(ctx, userAlice, info("personal"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range personal.Scopes {
		if google.WorkspaceOnlyScope(sc) {
			t.Errorf("personal gap asks for the Workspace-only scope %s: %v", sc, personal.Scopes)
		}
	}
	for _, tool := range directoryTools {
		if slices.Contains(personal.Tools, tool) {
			t.Errorf("personal gap promises %s: %v", tool, personal.Tools)
		}
	}
	if !slices.Contains(personal.Tools, "gmail.search") {
		t.Errorf("personal gap = %v, want the consumer tools", personal.Tools)
	}

	company, err := env.svc.MissingAccess(ctx, userAlice, info("company"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(company.Scopes, google.ScopeDirectoryReadonly) {
		t.Errorf("company gap scopes = %v, want directory.readonly", company.Scopes)
	}
	for _, tool := range directoryTools {
		if !slices.Contains(company.Tools, tool) {
			t.Errorf("company gap tools = %v, want %s", company.Tools, tool)
		}
	}

	// Every contacts scope a personal account can grant (increment 5 added
	// the contact writes and the other contacts): only the directory is
	// left, and it is not grantable.
	grantable := append(slices.Clone(base), google.ScopeContacts, google.ScopeContactsOtherReadonly)
	hint, err := env.svc.AccessHint(ctx, userAlice, connectors.Account{ID: "g-1", App: google.AppContacts, Label: connectors.LabelPersonal, Scopes: grantable})
	if err != nil || hint.LockedTools != 0 {
		t.Errorf("personal contacts hint = %+v, %v; want nothing locked (the directory is not grantable)", hint, err)
	}

	got := startScopes(t, env, connections.StartRequest{UserID: userAlice, Vendor: connections.VendorGoogle, Variant: connections.GoogleExternal})
	if slices.Contains(got, google.ScopeDirectoryReadonly) || !slices.Contains(got, google.ScopeContactsReadonly) {
		t.Errorf("connect asked for %v, want contacts.readonly without directory.readonly", got)
	}
}
