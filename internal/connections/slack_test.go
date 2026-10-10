package connections_test

import (
	"context"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestSlackAccountIDRoundTrips(t *testing.T) {
	id := connections.SlackAccountID("T0123ABC", "U0456DEF")
	if id != "T0123ABC:U0456DEF" {
		t.Fatalf("SlackAccountID = %q", id)
	}
	team, user, ok := connections.ParseSlackAccountID(id)
	if !ok || team != "T0123ABC" || user != "U0456DEF" {
		t.Errorf("Parse = %q %q %v", team, user, ok)
	}
	for _, bad := range []string{"", "U0456DEF", ":U1", "T1:", "T1:U1:X"} {
		if _, _, ok := connections.ParseSlackAccountID(bad); ok {
			t.Errorf("Parse(%q) ok", bad)
		}
	}
}

// addConnection inserts a connection row for user on the app with the
// given external id, label and status.
func addConnection(t *testing.T, env *testEnv, user, appID, external, label, status string) {
	t.Helper()
	err := env.store.AsUser(context.Background(), user, func(tx connections.Tx) error {
		return tx.CreateConnection(context.Background(), &store.Connection{
			UserID: user, VendorAppID: appID, ExternalAccountID: external, Label: label, DisplayName: external, Status: status,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSlackIdentityNeedsAnActiveCompanySlackConnection(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	slack, err := env.svc.SaveVendorApp(ctx, userAlice, slackApp(nil))
	if err != nil {
		t.Fatal(err)
	}
	gh := connections.Defaults(connections.VendorGitHub, "")
	gh.ClientID, gh.ClientSecret = "gh", "s"
	github, err := env.svc.SaveVendorApp(ctx, userAlice, gh)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing connected.
	if u, tm, ok, err := env.svc.SlackIdentity(ctx, userAlice); ok || err != nil || u != "" || tm != "" {
		t.Errorf("no connection: %q %q %v %v", u, tm, ok, err)
	}
	// A GitHub connection, a personal Slack one and a revoked company one
	// do not count.
	addConnection(t, env, userAlice, github.ID, "12345", store.AccountCompany, store.ConnectionActive)
	addConnection(t, env, userAlice, slack.ID, connections.SlackAccountID("THOME", "UHOME"), store.AccountPersonal, store.ConnectionActive)
	addConnection(t, env, userAlice, slack.ID, connections.SlackAccountID("TOLD", "UOLD"), store.AccountCompany, store.ConnectionRevoked)
	addConnection(t, env, userAlice, slack.ID, "not-a-slack-id", store.AccountCompany, store.ConnectionActive)
	if u, _, ok, err := env.svc.SlackIdentity(ctx, userAlice); ok || err != nil {
		t.Errorf("ineligible connections: %q %v %v", u, ok, err)
	}
	// An active company Slack connection: the user and team it is bound to.
	addConnection(t, env, userAlice, slack.ID, connections.SlackAccountID("TACME", "UALICE"), store.AccountCompany, store.ConnectionActive)
	u, tm, ok, err := env.svc.SlackIdentity(ctx, userAlice)
	if !ok || err != nil || u != "UALICE" || tm != "TACME" {
		t.Errorf("company connection: %q %q %v %v", u, tm, ok, err)
	}
	// Connections are per user: bob's is his own, alice's stays hers.
	addConnection(t, env, userBob, slack.ID, connections.SlackAccountID("TACME", "UBOB"), store.AccountCompany, store.ConnectionActive)
	if u, _, ok, _ := env.svc.SlackIdentity(ctx, userBob); !ok || u != "UBOB" {
		t.Errorf("bob = %q %v", u, ok)
	}
	if u, _, ok, _ := env.svc.SlackIdentity(ctx, userAlice); !ok || u != "UALICE" {
		t.Errorf("alice after bob = %q %v", u, ok)
	}
	if _, _, ok, err := env.svc.SlackIdentity(ctx, ""); ok || err == nil {
		t.Errorf("empty user: %v %v", ok, err)
	}
}
