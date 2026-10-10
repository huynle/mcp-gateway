package connections_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// connectorHints are every Extra key a connector binder (or cmd/gateway)
// reads as a hint. They are configuration for the gateway and must never
// reach a vendor's authorize URL (quirk sxbr5or5). A connector that adds
// a hint adds it here; the test fails until connections reserves it.
var connectorHints = map[string]string{
	"github company_orgs":       github.ExtraCompanyOrgs,
	"google company_domains":    google.ExtraCompanyDomains,
	"atlassian company_sites":   atlassian.ExtraCompanySites,
	"microsoft company_tenants": microsoft.ExtraCompanyTenants,
	"slack company_team_id":     slack.ExtraCompanyTeamID,
	"slack company_team_domain": slack.ExtraCompanyTeamDomain,
	"slack marker_reconcile":    slack.ExtraMarkerReconcile,
	"flow scope_param":          connections.ExtraScopeParam,
	"generic default_label":     connections.ExtraDefaultLabel,
	"generic id_field":          connections.ExtraIDField,
	"generic name_field":        connections.ExtraNameField,
	"generic email_field":       connections.ExtraEmailField,
}

// TestAuthParamsExcludeEveryReservedKey: a vendor app whose Extra holds
// one hint and one real authorization parameter forwards only the
// parameter.
func TestAuthParamsExcludeEveryReservedKey(t *testing.T) {
	for name, key := range connectorHints {
		t.Run(name, func(t *testing.T) {
			app := connections.VendorApp{Extra: map[string]string{key: "hint-value", "prompt": "consent"}}
			var got []string
			for _, kv := range app.AuthParams() {
				got = append(got, kv[0]+"="+kv[1])
			}
			if strings.Join(got, ",") != "prompt=consent" {
				t.Errorf("AuthParams with %s=%q: %v, want only prompt=consent", key, "hint-value", got)
			}
		})
	}
}

// TestSlackAuthorizeURLCarriesNoBinderHints runs the flow for a Slack app
// configured as docs/connectors/slack.md describes and checks the
// authorize URL: the user scopes travel as user_scope, the hints do not
// travel at all.
func TestSlackAuthorizeURLCarriesNoBinderHints(t *testing.T) {
	env := newTestEnv(t)
	app := connections.Defaults(connections.VendorSlack, "")
	app.ClientID, app.ClientSecret = "slack-client", "slack-secret"
	app.Scopes = []string{"channels:read"}
	app.Extra[slack.ExtraCompanyTeamID] = "T0ACME"
	app.Extra[slack.ExtraCompanyTeamDomain] = "acme"
	app.Extra[slack.ExtraMarkerReconcile] = "true"
	if _, err := env.svc.SaveVendorApp(context.Background(), userAlice, app); err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	redirect, err := env.svc.Start(context.Background(), connections.StartRequest{UserID: userAlice, Vendor: connections.VendorSlack, Scopes: []string{"chat:write"}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("user_scope") != "channels:read chat:write" || q.Has("scope") {
		t.Errorf("scopes: user_scope=%q scope=%q", q.Get("user_scope"), q.Get("scope"))
	}
	for _, key := range []string{slack.ExtraCompanyTeamID, slack.ExtraCompanyTeamDomain, slack.ExtraMarkerReconcile, connections.ExtraScopeParam} {
		if q.Has(key) {
			t.Errorf("authorize URL carries binder hint %s: %s", key, redirect)
		}
	}
}
