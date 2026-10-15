package connections_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
)

// oldSlackScopes are the nine user scopes production's Slack app was
// hand-filled with before the account-management tools existed.
var oldSlackScopes = []string{
	"channels:history", "channels:read", "chat:write", "groups:history", "groups:read",
	"im:write", "reactions:write", "search:read", "users:read",
}

// catalogRegistry registers the real Slack and Google connectors on a
// fresh registry the way cmd/gateway does (MapApp, Google's implied-scope
// coverage) plus a fake-vendor app whose tools need "repo" (read) and
// "write:org" (write).
func catalogRegistry(t *testing.T, svc *connections.Service) *connectors.Registry {
	t.Helper()
	reg := connectors.NewRegistry()
	sc, err := slack.New(slack.Options{Tokens: svc.TokenSource, Accounts: svc})
	if err != nil {
		t.Fatal(err)
	}
	if err := connectors.RegisterConnector(reg, sc, svc); err != nil {
		t.Fatal(err)
	}
	svc.MapApp(slack.App, connections.VendorSlack)
	gc, err := google.New(google.Options{Tokens: svc.TokenSource, Accounts: svc})
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range gc.Apps() {
		if err := connectors.RegisterConnector(reg, app, svc); err != nil {
			t.Fatal(err)
		}
		svc.MapApp(app.App(), connections.VendorGoogle)
		reg.SetScopeCoverage(app.App(), google.Grants)
	}
	noop := func(context.Context, connectors.Call) (connectors.Result, error) { return connectors.Result{}, nil }
	schema := []byte(`{"type":"object"}`)
	for _, tool := range []connectors.Tool{
		{App: connections.VendorFake, Name: "list_repos", Kind: connectors.KindRead, RequiredScopes: []string{"repo"}, InputSchema: schema, Handler: noop},
		{App: connections.VendorFake, Name: "edit_org", Kind: connectors.KindWrite, RequiredScopes: []string{"write:org"}, InputSchema: schema, Handler: noop},
	} {
		if err := reg.Register(tool); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

// policyVisibility is the production ToolVisibility over a policy service
// with roles: member sees every slack, google and fake tool; no-files
// additionally hides slack.upload_file (the only files:write tool) and
// slack.create_channel.
func policyVisibility(t *testing.T) connections.PolicyAllowance {
	t.Helper()
	st := policytest.NewMemStore()
	var rules []policy.ToolRule
	for _, app := range append([]string{slack.App, connections.VendorFake}, google.Apps...) {
		rules = append(rules, policy.ToolRule{App: app, Tool: "*", Outcome: policy.OutcomeAllow})
	}
	st.PutRole(policy.Role{Name: "member", Rules: rules})
	st.PutRole(policy.Role{Name: "no-files", Rules: append(slices.Clone(rules),
		policy.ToolRule{App: slack.App, Tool: slack.ToolUploadFile, Outcome: policy.OutcomeHidden},
		policy.ToolRule{App: slack.App, Tool: slack.ToolCreateChannel, Outcome: policy.OutcomeHidden},
	)})
	st.Assign(userAlice, "member")
	st.Assign(userBob, "no-files")
	svc, err := policy.New(st, policy.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return connections.PolicyAllowance{Service: svc}
}

func slackInfo(scopes ...string) connections.Info {
	return connections.Info{ID: "c-1", Vendor: connections.VendorSlack, Variant: connections.DefaultVariant, Scopes: scopes, Status: "active"}
}

// TestMissingAccessSlackOldScopes: a Slack connection holding the nine
// original user scopes lacks every scope the account-management tools
// added, for a user whose role allows slack.*; the gap names the tools
// it unlocks and never a scope already granted.
func TestMissingAccessSlackOldScopes(t *testing.T) {
	env := newTestEnv(t)
	env.svc.SetToolCatalog(catalogRegistry(t, env.svc), policyVisibility(t))

	gap, err := env.svc.MissingAccess(context.Background(), userAlice, slackInfo(oldSlackScopes...))
	if err != nil {
		t.Fatalf("MissingAccess: %v", err)
	}
	for _, want := range []string{"channels:write", "pins:write", "pins:read", "files:write", "users.profile:write", "dnd:read", "dnd:write", "im:read", "mpim:read", "im:history", "mpim:history"} {
		if !slices.Contains(gap.Scopes, want) {
			t.Errorf("missing scopes %v lack %s", gap.Scopes, want)
		}
	}
	for _, granted := range oldSlackScopes {
		if slices.Contains(gap.Scopes, granted) {
			t.Errorf("missing scopes %v contain the granted %s", gap.Scopes, granted)
		}
	}
	if !slices.IsSorted(gap.Scopes) || !slices.IsSorted(gap.Tools) || !slices.IsSorted(gap.Extended) {
		t.Errorf("gap not sorted: %+v", gap)
	}
	for _, want := range []string{"slack.create_channel", "slack.upload_file", "slack.set_status", "slack.pin_message"} {
		if !slices.Contains(gap.Tools, want) {
			t.Errorf("unlocked tools %v lack %s", gap.Tools, want)
		}
	}
	// Optional scopes (Tool.OptionalScopes) widen tools that already
	// work: DMs for list_conversations and the history readers, private
	// channels for the channel tools.
	for _, want := range []string{"groups:write"} {
		if !slices.Contains(gap.Scopes, want) {
			t.Errorf("missing scopes %v lack the optional %s", gap.Scopes, want)
		}
	}
	for _, want := range []string{"slack.list_conversations", "slack.read_channel_history", "slack.get_thread"} {
		if !slices.Contains(gap.Extended, want) || slices.Contains(gap.Tools, want) {
			t.Errorf("gap %+v: %s should be extended, not unlocked", gap, want)
		}
	}
	for _, usable := range []string{"slack.post_message", "slack.search_messages", "slack.list_accounts"} {
		if slices.Contains(gap.Tools, usable) {
			t.Errorf("unlocked tools %v contain %s, which already works", gap.Tools, usable)
		}
	}
	for _, tool := range gap.Tools {
		if !strings.HasPrefix(tool, "slack.") {
			t.Errorf("unlocked tool %s is not a slack tool", tool)
		}
	}

	// A role that hides upload_file (the only files:write tool) and
	// create_channel drops files:write and both names; channels:write
	// stays for the other channel tools.
	gap, err = env.svc.MissingAccess(context.Background(), userBob, slackInfo(oldSlackScopes...))
	if err != nil {
		t.Fatalf("MissingAccess(bob): %v", err)
	}
	if slices.Contains(gap.Scopes, "files:write") || !slices.Contains(gap.Scopes, "channels:write") {
		t.Errorf("bob's missing scopes = %v, want channels:write without files:write", gap.Scopes)
	}
	if slices.Contains(gap.Tools, "slack.create_channel") || slices.Contains(gap.Tools, "slack.upload_file") {
		t.Errorf("bob's unlocked tools %v contain hidden tools", gap.Tools)
	}
	if !slices.Contains(gap.Tools, "slack.rename_channel") {
		t.Errorf("bob's unlocked tools %v lack slack.rename_channel", gap.Tools)
	}

	// A connection that granted everything has no gap.
	full := slices.Clone(oldSlackScopes)
	for _, tool := range catalogRegistry(t, newTestEnv(t).svc).List() {
		if tool.App == slack.App {
			full = append(full, tool.RequiredScopes...)
			full = append(full, tool.OptionalScopes...)
		}
	}
	gap, err = env.svc.MissingAccess(context.Background(), userAlice, slackInfo(full...))
	if err != nil || len(gap.Scopes) != 0 || len(gap.Tools) != 0 || len(gap.Extended) != 0 {
		t.Errorf("full grant gap = %+v, %v; want none", gap, err)
	}
}

// TestMissingAccessGoogleImpliedScopes: Google's broader scopes cover the
// narrower ones (google.Grants); a connection with gmail.modify is not
// told it lacks gmail.readonly, gmail.labels, gmail.compose or
// gmail.send, and the internal and external variants both map to the
// Google apps.
func TestMissingAccessGoogleImpliedScopes(t *testing.T) {
	env := newTestEnv(t)
	env.svc.SetToolCatalog(catalogRegistry(t, env.svc), policyVisibility(t))
	for _, variant := range []string{connections.GoogleInternal, connections.GoogleExternal} {
		info := connections.Info{ID: "g-1", Vendor: connections.VendorGoogle, Variant: variant, Status: "active",
			Scopes: []string{"openid", google.ScopeGmailModify, google.ScopeCalendar}}
		gap, err := env.svc.MissingAccess(context.Background(), userAlice, info)
		if err != nil {
			t.Fatalf("MissingAccess(%s): %v", variant, err)
		}
		for _, covered := range []string{google.ScopeGmailReadonly, google.ScopeGmailLabels, google.ScopeGmailCompose, google.ScopeGmailSend, google.ScopeCalendarEvents, google.ScopeCalendarEventsReadonly} {
			if slices.Contains(gap.Scopes, covered) {
				t.Errorf("%s: missing scopes %v contain %s, which gmail.modify / calendar imply", variant, gap.Scopes, covered)
			}
		}
		if !slices.Contains(gap.Scopes, google.ScopeTasksReadonly) || !slices.Contains(gap.Tools, "tasks.list") {
			t.Errorf("%s: gap %+v lacks the tasks read scope and tool", variant, gap)
		}
		for _, tool := range gap.Tools {
			if strings.HasPrefix(tool, "gmail.") || strings.HasPrefix(tool, "calendar.") {
				t.Errorf("%s: unlocked tools contain %s, which already works", variant, tool)
			}
		}
	}
}

// failingVisibility stands in for a policy that cannot be evaluated.
type failingVisibility struct{}

func (failingVisibility) VisibleToUser(context.Context, string, connectors.Tool) (bool, error) {
	return false, errors.New("policy store down")
}

// TestMissingAccessEdgeCases: without a catalog nothing is missing (the
// gateway knows no tools); a connection without recorded scopes is not
// second-guessed (the scope stage does not refuse it either); a policy
// that cannot be evaluated falls back to every vendor tool (asking for
// more is safe, hiding the button is the bug) and logs it.
func TestMissingAccessEdgeCases(t *testing.T) {
	env := newTestEnv(t)
	env.svc.SetToolCatalog(nil, nil)
	ctx := context.Background()
	if gap, err := env.svc.MissingAccess(ctx, userAlice, slackInfo(oldSlackScopes...)); err != nil || len(gap.Scopes) != 0 {
		t.Errorf("no catalog: gap = %+v, %v", gap, err)
	}
	reg := catalogRegistry(t, env.svc)
	env.svc.SetToolCatalog(reg, failingVisibility{})
	gap, err := env.svc.MissingAccess(ctx, userAlice, slackInfo(oldSlackScopes...))
	if err != nil || !slices.Contains(gap.Scopes, "files:write") || !slices.Contains(gap.Tools, "slack.create_channel") {
		t.Errorf("policy unavailable: gap = %+v, %v; want every slack tool's scopes", gap, err)
	}
	if !strings.Contains(env.logs.String(), "connections.policy_unavailable") {
		t.Errorf("policy failure not logged:\n%s", env.logs.String())
	}
	if gap, err := env.svc.MissingAccess(ctx, userAlice, slackInfo()); err != nil || len(gap.Scopes) != 0 {
		t.Errorf("no recorded scopes: gap = %+v, %v; want none", gap, err)
	}
	env.svc.SetToolCatalog(reg, nil)
	if gap, err := env.svc.MissingAccess(ctx, userAlice, slackInfo(oldSlackScopes...)); err != nil || !slices.Contains(gap.Scopes, "files:write") {
		t.Errorf("nil visibility: gap = %+v, %v; want every slack tool's scopes", gap, err)
	}
}

// TestAccessHintForListAccounts: the service tells list_accounts how
// many of the account's app's visible tools stay locked and where to
// grant more access; an account of another app of the vendor only
// counts its own app's tools; nothing missing means no hint. Through
// RegisterConnector the hint reaches slack.list_accounts' output.
func TestAccessHintForListAccounts(t *testing.T) {
	env := newTestEnv(t)
	reg := catalogRegistry(t, env.svc)
	env.svc.SetToolCatalog(reg, policyVisibility(t))
	ctx := context.Background()

	hint, err := env.svc.AccessHint(ctx, userAlice, connectors.Account{ID: "c-1", App: slack.App, Scopes: oldSlackScopes})
	if err != nil {
		t.Fatal(err)
	}
	gap, _ := env.svc.MissingAccess(ctx, userAlice, slackInfo(oldSlackScopes...))
	if hint.LockedTools != len(gap.Tools) || hint.LockedTools == 0 || hint.GrantURL != "http://gw.test/connections" {
		t.Errorf("slack hint = %+v, want %d locked tools and the connections page", hint, len(gap.Tools))
	}
	gmail := connectors.Account{ID: "g-1", App: google.AppGmail, Scopes: []string{google.ScopeGmailModify}}
	if hint, err := env.svc.AccessHint(ctx, userAlice, gmail); err != nil || hint != (connectors.AccessHint{}) {
		t.Errorf("gmail hint = %+v, %v; want none (calendar's gap is not gmail's)", hint, err)
	}
	if hint, err := env.svc.AccessHint(ctx, userAlice, connectors.Account{ID: "c-2", App: slack.App}); err != nil || hint != (connectors.AccessHint{}) {
		t.Errorf("no recorded scopes: hint = %+v, %v", hint, err)
	}
	var _ connectors.AccessHinter = env.svc
}
