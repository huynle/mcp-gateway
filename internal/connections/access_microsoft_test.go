package connections_test

import (
	"context"
	"slices"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// microsoftCatalog registers the Microsoft connector as cmd/gateway does:
// Graph coverage, and personal accounts cannot grant Teams permissions.
func microsoftCatalog(t *testing.T, svc *connections.Service) *connectors.Registry {
	t.Helper()
	reg := connectors.NewRegistry()
	c, err := microsoft.New(microsoft.Options{Tokens: svc.TokenSource, Accounts: svc})
	if err != nil {
		t.Fatal(err)
	}
	if err := connectors.RegisterConnector(reg, c, svc); err != nil {
		t.Fatal(err)
	}
	svc.MapApp(microsoft.App, connections.VendorMicrosoft)
	reg.SetScopeCoverage(microsoft.App, microsoft.ScopeCovered)
	reg.SetScopeGrantable(microsoft.App, microsoft.ScopeGrantable)
	return reg
}

func microsoftInfo(label string, scopes ...string) connections.Info {
	return connections.Info{ID: "m-1", Vendor: connections.VendorMicrosoft, Variant: connections.DefaultVariant, Label: label, Status: "active", Scopes: scopes}
}

// TestMissingAccessMicrosoftPersonalSkipsTeams: a personal Microsoft
// account can never grant the Teams permissions, so its gap neither asks
// for them nor promises the Teams tools; a company account's does.
func TestMissingAccessMicrosoftPersonalSkipsTeams(t *testing.T) {
	env := newTestEnv(t)
	env.svc.SetToolCatalog(microsoftCatalog(t, env.svc), nil)
	ctx := context.Background()
	base := []string{"openid", "User.Read", "offline_access", microsoft.ScopeMailRead}

	personal, err := env.svc.MissingAccess(ctx, userAlice, microsoftInfo("personal", base...))
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range personal.Scopes {
		if microsoft.TeamsScope(sc) {
			t.Errorf("personal gap asks for the Teams permission %s: %v", sc, personal.Scopes)
		}
	}
	if slices.Contains(personal.Tools, "microsoft."+microsoft.ToolTeamsListChannels) || !slices.Contains(personal.Tools, "microsoft."+microsoft.ToolMailSend) {
		t.Errorf("personal unlocks %v, want mail_send without the Teams tools", personal.Tools)
	}
	company, err := env.svc.MissingAccess(ctx, userAlice, microsoftInfo("company", base...))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(company.Scopes, microsoft.ScopeTeamReadBasicAll) || !slices.Contains(company.Tools, "microsoft."+microsoft.ToolTeamsListChannels) {
		t.Errorf("company gap = %+v, want the Teams permissions and tools", company)
	}
	hint, err := env.svc.AccessHint(ctx, userAlice, connectors.Account{ID: "m-1", App: microsoft.App, Label: connectors.LabelPersonal, Scopes: base})
	if err != nil || hint.LockedTools != len(personal.Tools) {
		t.Errorf("personal hint = %+v, %v; want %d locked tools", hint, err, len(personal.Tools))
	}
}

// TestStartMicrosoftConnectLeavesTeamsOut: Connect cannot know whether
// a work or a personal account will sign in, and Microsoft refuses the
// whole consent of a personal account that is asked for a Teams
// permission, so reads first leaves every scope some account label
// cannot grant to Grant more access.
func TestStartMicrosoftConnectLeavesTeamsOut(t *testing.T) {
	env := newTestEnv(t)
	app := connections.Defaults(connections.VendorMicrosoft, "")
	app.ClientID, app.ClientSecret = "ms-client", "ms-secret"
	if _, err := env.svc.SaveVendorApp(context.Background(), userAlice, app); err != nil {
		t.Fatal(err)
	}
	env.svc.SetToolCatalog(microsoftCatalog(t, env.svc), nil)
	got := startScopes(t, env, connections.StartRequest{UserID: userAlice, Vendor: connections.VendorMicrosoft})
	for _, want := range []string{microsoft.ScopeMailRead, microsoft.ScopeCalendarsRead, microsoft.ScopeFilesReadAll, "User.Read"} {
		if !slices.Contains(got, want) {
			t.Errorf("connect asked for %v, lacks %s", got, want)
		}
	}
	for _, sc := range got {
		if microsoft.TeamsScope(sc) {
			t.Errorf("connect asked for the Teams permission %s: %v", sc, got)
		}
	}
}
