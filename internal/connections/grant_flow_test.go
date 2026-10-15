package connections_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// startScopes runs Start and returns the scopes the authorize URL asks
// for (Slack's user_scope, else scope).
func startScopes(t *testing.T, env *testEnv, req connections.StartRequest) []string {
	t.Helper()
	redirect, err := env.svc.Start(context.Background(), req)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	q := mustQuery(t, redirect)
	if q.Has("user_scope") {
		return connections.SplitScopes(q.Get("user_scope"))
	}
	return connections.SplitScopes(q.Get("scope"))
}

// TestStartIgnoresUnknownScopes: the query string cannot widen a grant.
// Start keeps the app's base scopes and the scopes some tool of the
// vendor requires or uses, and drops (and logs) anything else; without
// a tool catalog nothing but the base is requestable.
func TestStartIgnoresUnknownScopes(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerSlackApp(t, env, v, "identity.basic")
	env.svc.SetToolCatalog(catalogRegistry(t, env.svc), nil)

	got := startScopes(t, env, connections.StartRequest{UserID: userAlice, Vendor: connections.VendorSlack,
		Scopes: []string{"channels:write", "admin.users:write", "identity.basic", "im:read", "client"}})
	if want := []string{"channels:write", "identity.basic", "im:read"}; !slices.Equal(got, want) {
		t.Errorf("requested %v, want %v", got, want)
	}
	logs := env.logs.String()
	if !strings.Contains(logs, "connections.scopes_ignored") || !strings.Contains(logs, "admin.users:write") || !strings.Contains(logs, "client") {
		t.Errorf("ignored scopes not logged:\n%s", logs)
	}

	env.svc.SetToolCatalog(nil, nil)
	if got := startScopes(t, env, connections.StartRequest{UserID: userAlice, Vendor: connections.VendorSlack, Scopes: []string{"chat:write"}}); !slices.Equal(got, []string{"identity.basic"}) {
		t.Errorf("without a catalog requested %v, want only the base", got)
	}
}

// TestStartConnectRequestsReadsFirst: Connect (no scopes in the query)
// asks for the base plus the scopes of the read tools the user's policy
// shows, so an app whose base scopes are empty still requests something
// (Slack answers "No scopes requested" otherwise); writes come later
// through grant more access.
func TestStartConnectRequestsReadsFirst(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerSlackApp(t, env, v)
	env.svc.SetToolCatalog(catalogRegistry(t, env.svc), policyVisibility(t))

	got := startScopes(t, env, connections.StartRequest{UserID: userAlice, Vendor: connections.VendorSlack})
	for _, want := range []string{"channels:read", "groups:read", "channels:history", "groups:history", "search:read", "users:read", "pins:read", "dnd:read", "im:read", "mpim:read", "im:history", "mpim:history"} {
		if !slices.Contains(got, want) {
			t.Errorf("connect requested %v, lacks the read scope %s", got, want)
		}
	}
	for _, write := range []string{"chat:write", "channels:write", "files:write", "pins:write", "im:write", "groups:write"} {
		if slices.Contains(got, write) {
			t.Errorf("connect requested the write scope %s: %v", write, got)
		}
	}
}

// TestGrantMoreAccessUnionsAndUnlocks: a Slack connection holding the
// nine original scopes grants more access: Start asks for everything
// the connection already has plus the gap (Slack user tokens and Google
// accumulate, Microsoft must be asked again), the callback stores the
// union, and the tools the gap named have nothing missing any more.
func TestGrantMoreAccessUnionsAndUnlocks(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	v.slack = slackUserOnly
	registerSlackApp(t, env, v)
	reg := catalogRegistry(t, env.svc)
	env.svc.SetToolCatalog(reg, policyVisibility(t))
	ctx := context.Background()

	info, err := connectVendor(t, env, connections.VendorSlack, userAlice, "acct-company", oldSlackScopes...)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !slices.Equal(info.Scopes, oldSlackScopes) {
		t.Fatalf("first grant = %v", info.Scopes)
	}
	gap, err := env.svc.MissingAccess(ctx, userAlice, info)
	if err != nil || !slices.Contains(gap.Scopes, "channels:write") {
		t.Fatalf("gap = %+v, %v", gap, err)
	}

	// Without naming the connection (a new account) nothing earlier is
	// asked for; someone else's connection id is ignored the same way.
	for _, id := range []string{"", "33333333-3333-4333-8333-333333333333"} {
		got := startScopes(t, env, connections.StartRequest{UserID: userAlice, Vendor: connections.VendorSlack, ConnectionID: id, Scopes: []string{"channels:write"}})
		if !slices.Equal(got, []string{"channels:write"}) {
			t.Errorf("connection %q: requested %v, want only channels:write", id, got)
		}
	}
	if got := startScopes(t, env, connections.StartRequest{UserID: userBob, Vendor: connections.VendorSlack, ConnectionID: info.ID, Scopes: []string{"channels:write"}}); !slices.Equal(got, []string{"channels:write"}) {
		t.Errorf("bob naming alice's connection: requested %v", got)
	}

	again, err := connectFlow(t, env, connections.StartRequest{UserID: userAlice, Vendor: connections.VendorSlack, ConnectionID: info.ID, Scopes: gap.Scopes}, "acct-company")
	if err != nil {
		t.Fatalf("grant more access: %v", err)
	}
	asked := connections.SplitScopes(v.lastAuthorize().Get("user_scope"))
	for _, want := range append(slices.Clone(oldSlackScopes), gap.Scopes...) {
		if !slices.Contains(asked, want) {
			t.Errorf("user_scope %v lacks %s (previously granted or missing)", asked, want)
		}
	}
	if again.ID != info.ID {
		t.Errorf("grant more access created connection %s, want %s updated", again.ID, info.ID)
	}
	for _, want := range append(slices.Clone(oldSlackScopes), gap.Scopes...) {
		if !slices.Contains(again.Scopes, want) {
			t.Errorf("stored scopes %v lack %s", again.Scopes, want)
		}
	}
	if gap, err := env.svc.MissingAccess(ctx, userAlice, again); err != nil || !gap.Empty() {
		t.Errorf("gap after grant = %+v, %v; want none", gap, err)
	}
	tool, ok := reg.Get(slack.App + "." + slack.ToolCreateChannel)
	if !ok {
		t.Fatal("slack.create_channel not registered")
	}
	if missing := reg.MissingScopes(tool, again.Scopes); len(missing) != 0 {
		t.Errorf("slack.create_channel still misses %v", missing)
	}
	accts, err := env.svc.ListAccounts(ctx, userAlice, slack.App)
	if err != nil || len(accts) != 1 || len(reg.MissingScopes(tool, accts[0].Scopes)) != 0 {
		t.Errorf("account source = %+v, %v; want the account with create_channel's scope", accts, err)
	}
}

// TestStartGoogleIncludesGrantedScopes: Google drops earlier grants from
// a new token unless the request carries include_granted_scopes=true;
// Start adds it when the app's extras do not set it.
func TestStartGoogleIncludesGrantedScopes(t *testing.T) {
	env := newTestEnv(t)
	app := connections.Defaults(connections.VendorGoogle, connections.GoogleInternal)
	app.ClientID, app.ClientSecret = "google-client", "google-secret"
	delete(app.Extra, "include_granted_scopes")
	if _, err := env.svc.SaveVendorApp(context.Background(), userAlice, app); err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	redirect, err := env.svc.Start(context.Background(), connections.StartRequest{UserID: userAlice, Vendor: connections.VendorGoogle, Variant: connections.GoogleInternal})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := mustQuery(t, redirect).Get("include_granted_scopes"); got != "true" {
		t.Errorf("include_granted_scopes = %q in %s", got, redirect)
	}
}
