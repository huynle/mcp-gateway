//go:build integration || e2e || security

package security

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
	slackconn "github.com/huynle/mcp-gateway/internal/connectors/slack"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// outcome classifies a call: "allow" (the stub was reached and the
// result is not an error), "confirm" (-32032), "deny" (-32030),
// "unknown" (-32602 unknown tool), "invalid" (-32602 other), or the
// tool error text.
func (w *world) outcome(token, tool string, args map[string]any) string {
	w.t.Helper()
	_, _, body := w.rawCall(token, tool, args)
	s := string(body)
	switch {
	case strings.Contains(s, `"code":-32032`):
		return "confirm"
	case strings.Contains(s, `"code":-32030`):
		return "deny"
	case strings.Contains(s, `"code":-32602`) && strings.Contains(s, "unknown tool"):
		return "unknown"
	case strings.Contains(s, `"code":-32602`):
		return "invalid"
	case strings.Contains(s, `"isError":true`):
		return "tool_error:" + s
	case strings.Contains(s, `"error"`):
		return "error:" + s
	}
	return "allow"
}

// TestSecurityPolicyArgumentRuleEvasion: argument conditions compare
// the connector's resource identity, so what an evasion achieves
// depends on how the connector normalises. Documented per connector:
//
//   - GitHub lower-cases owner/repo/org (GitHub names are
//     case-insensitive), so case variants land on the same rule; trailing
//     whitespace is trimmed; trailing dots, URL-encoding and Unicode
//     lookalikes produce names no rule matches and are denied (deny by
//     default), never allowed. GitHub exposes no repository-id
//     alternative: owner/repo is the only identity.
//   - Slack lower-cases channel names and strips "#"; a channel given by
//     id (C...) or mention (<#C...|name>) is resolved to its name through
//     the account's conversations before policy decides (task 6br0isjh),
//     so name conditions hold whichever form the harness used: the id of
//     #eng-deploys needs the same approval as the name, the id of #random
//     is denied like the name, and an id the account cannot see is
//     denied (identity_unresolved, fail closed). A mention's own name is
//     never trusted: <#C0RANDOM01|eng-deploys> is #random.
//   - The fake keeps ids as given: conditions are exact (SECRET-1 is a
//     different, nonexistent item).
func TestSecurityPolicyArgumentRuleEvasion(t *testing.T) {
	w := newWorld(t, options{})
	alice := w.token(w.alice, tokens.CreateRequest{})
	issue := func(owner string) map[string]any {
		return map[string]any{"owner": owner, "repo": "widgets", "title": "t", "body": "b"}
	}
	cases := []struct{ owner, want string }{
		{"acme", "confirm"}, {"Acme", "confirm"}, {"ACME", "confirm"}, {" acme ", "confirm"},
		{"acme-labs", "allow"}, {"ACME-LABS", "allow"},
		{"acme.", "deny"}, {"acme%2Dlabs", "deny"}, {"acme%20", "deny"},
		{"\u0430cme", "deny"},                                   // Cyrillic а
		{"acme\u200b", "deny"},                                  // zero-width space
		{"acme\u2024", "deny"},                                  // one-dot leader
		{"acme-labs/../acme", "deny"}, {"acme-labs\n", "allow"}, // newline is whitespace: trimmed
		{"evil", "deny"}, {"", "deny"},
	}
	for _, c := range cases {
		if got := w.outcome(alice, "github.create_issue", issue(c.owner)); got != c.want {
			t.Errorf("github.create_issue owner %q = %s, want %s", c.owner, got, c.want)
		}
	}
	// Only acme-labs writes reached GitHub; every other owner was
	// stopped before the connector.
	for _, is := range w.github.created("acme/widgets") {
		t.Errorf("issue created in acme without an approval: %+v", is)
	}
	if n := len(w.github.created("acme-labs/widgets")) + len(w.github.created("ACME-LABS/widgets")); n != 3 {
		t.Errorf("issues in acme-labs = %d, want 3 (acme-labs, ACME-LABS, acme-labs\\n)", n)
	}
	if w.github.count() != 3 {
		t.Errorf("GitHub was called %d times, want 3", w.github.count())
	}

	// Slack: confirm for #eng-* by name; ids and mentions resolve to the
	// name and get the name's outcome; an id the account cannot see is
	// denied.
	post := func(channel string) map[string]any { return map[string]any{"channel": channel, "text": "x"} }
	for _, c := range []struct{ channel, want string }{
		{"#eng-deploys", "confirm"}, {"eng-deploys", "confirm"}, {"#ENG-Deploys", "confirm"}, {" #eng-deploys ", "confirm"},
		{"#random", "deny"}, {"C0RANDOM01", "deny"}, {"<#C0RANDOM01|eng-deploys>", "deny"}, // the mention's name is not trusted
		{"C0ENGDEP01", "confirm"}, {"c0engdep01", "confirm"}, {"<#C0ENGDEP01|eng-deploys>", "confirm"}, {"<#C0ENGDEP01|random>", "confirm"},
		{"C0NOWHERE1", "deny"},            // not among the account's conversations: identity_unresolved
		{"#eng\u2010deploys", "deny"},     // Unicode hyphen: no rule matches
		{"#eng-deploys\u200b", "confirm"}, // a prefix rule matches; the connector later refuses the nonexistent name
	} {
		if got := w.outcome(alice, "slack.post_message", post(c.channel)); got != c.want {
			t.Errorf("slack.post_message channel %q = %s, want %s", c.channel, got, c.want)
		}
	}
	if n := len(w.slack.list()); n != 0 {
		t.Errorf("Slack received %d posts without an approval", n)
	}
	var unresolved int
	for _, ev := range w.events(w.alice) {
		if ev.Tool == "slack.post_message" && ev.ErrorClass == "identity_unresolved" {
			unresolved++
			if ev.Decision != "deny" || ev.Outcome != "denied" || ev.ResourceIdentity["channel_id"] != "C0NOWHERE1" {
				t.Errorf("identity_unresolved audit row = %+v", ev)
			}
		}
	}
	if unresolved != 1 {
		t.Errorf("identity_unresolved audit rows = %d, want 1", unresolved)
	}
	// Deny-by-name holds for every form of the channel (the finding of
	// the security review, closed by task 6br0isjh): with "allow
	// slack.post_message; deny when channel equals eng-secrets", the
	// name, the id of #eng-secrets and the mention are all denied and
	// nothing reaches Slack; another channel by id is still allowed.
	rules := append(memberRules(),
		policy.ToolRule{App: slackconn.App, Tool: slackconn.ToolPostMessage, Outcome: policy.OutcomeAllow},
		policy.ToolRule{App: slackconn.App, Tool: slackconn.ToolPostMessage, Outcome: policy.OutcomeDeny, Conditions: []policy.Condition{{Key: "channel", Op: policy.OpEquals, Value: "eng-secrets"}}},
	)
	w.setMemberRules(rules)
	posts := len(w.slack.list())
	for _, channel := range []string{"#eng-secrets", "eng-secrets", "C0ENGSEC01", "c0engsec01", "<#C0ENGSEC01|eng-secrets>", "<#C0ENGSEC01|eng-deploys>"} {
		if got := w.outcome(alice, "slack.post_message", post(channel)); got != "deny" {
			t.Errorf("deny-by-name, channel %q = %s, want deny", channel, got)
		}
	}
	if n := len(w.slack.list()); n != posts {
		t.Errorf("Slack received %d posts to the denied channel", n-posts)
	}
	if got := w.outcome(alice, "slack.post_message", post("C0RANDOM01")); got != "allow" {
		t.Errorf("deny-by-name, another channel by id = %s, want allow", got)
	}
	if list := w.slack.list(); len(list) != posts+1 || list[len(list)-1]["channel"] != "C0RANDOM01" {
		t.Errorf("Slack posts after the allowed id = %+v", list)
	}
	// Audit rows of the denied forms carry the resolved name next to the id.
	var byID int
	for _, ev := range w.events(w.alice) {
		if ev.Tool == "slack.post_message" && ev.ResourceIdentity["channel_id"] == "C0ENGSEC01" {
			byID++
			if ev.Decision != "deny" || ev.ResourceIdentity["channel"] != "eng-secrets" {
				t.Errorf("audit row for the id of #eng-secrets = %+v", ev)
			}
		}
	}
	if byID != 4 {
		t.Errorf("audit rows naming C0ENGSEC01 = %d, want 4", byID)
	}
	w.setMemberRules(memberRules())

	// Fake: the conditional deny on id prefix "secret-" is exact.
	w.fake.SeedItems(w.aliceAcc, fake.Item{ID: "secret-1", Name: "s"}, fake.Item{ID: "SECRET-1", Name: "S"})
	for _, c := range []struct{ id, want string }{
		{"secret-1", "deny"}, {"secret-", "deny"}, {"SECRET-1", "allow"}, {" secret-1", "allow"}, {"xsecret-1", "allow"},
	} {
		got := w.outcome(alice, "fake.get_item", map[string]any{"id": c.id})
		// An allowed read of a nonexistent item is a tool error, still "allowed".
		if c.want == "allow" && strings.HasPrefix(got, "tool_error") {
			got = "allow"
		}
		if got != c.want {
			t.Errorf("fake.get_item id %q = %s, want %s", c.id, got, c.want)
		}
	}
	_ = connectors.ListAccountsName
}

// TestSecurityPolicyHiddenAdminTokenAndVersionPinning: hidden tools are
// unknown on a direct call (byte-identical to a nonexistent name), and
// so is <app>.list_accounts of an app the role grants nothing for; the
// admin role grants no tools by itself; a token's app allow-list and
// read-only flag narrow below the role and no role edit widens them;
// an approval created under policy version N is not consumable after a
// role change produced version N+1.
func TestSecurityPolicyHiddenAdminTokenAndVersionPinning(t *testing.T) {
	w := newWorld(t, options{})
	bobTok := w.token(w.bob, tokens.CreateRequest{})
	bob := w.clientWith(bobTok)

	// Hidden: fake.get_item is hidden for the restricted role.
	if names := toolNames(t, bob); contains(names, "fake.get_item") {
		t.Errorf("hidden tool listed: %v", names)
	}
	_, _, hidden := w.rawCall(bobTok, "fake.get_item", map[string]any{"id": "x", "account": w.bobAcc})
	_, _, absent := w.rawCall(bobTok, "fake.get_item_v2", map[string]any{"id": "x", "account": w.bobAcc})
	if a, b := strings.ReplaceAll(stripID(hidden), "get_item", "T"), strings.ReplaceAll(stripID(absent), "get_item_v2", "T"); a != b || !strings.Contains(a, "unknown tool") {
		t.Errorf("hidden vs absent:\n%s\n%s", hidden, absent)
	}

	// An app with no rules: its list_accounts is unknown too.
	w.setMemberRules([]policy.ToolRule{{App: fake.App, Tool: policy.Wildcard, Outcome: policy.OutcomeAllow}})
	aliceTok := w.token(w.alice, tokens.CreateRequest{})
	for _, tool := range []string{"github.list_accounts", "slack.list_accounts", "github.get_me", "slack.list_channels"} {
		if got := w.outcome(aliceTok, tool, map[string]any{}); got != "unknown" {
			t.Errorf("%s with no github/slack rules = %s, want unknown", tool, got)
		}
	}
	if names := toolNames(t, w.clientWith(aliceTok)); contains(names, "github.list_accounts") || contains(names, "slack.list_accounts") {
		t.Errorf("list_accounts listed for ungranted apps: %v", names)
	}
	w.setMemberRules(memberRules())

	// Admin: the admin role grants nothing; the admin user holds member
	// as well (default role), so removing member leaves nothing.
	adminTok := w.token(w.admin, tokens.CreateRequest{})
	if got := w.outcome(adminTok, "fake.list_items", map[string]any{}); got != "allow" && !strings.HasPrefix(got, "error:") {
		t.Errorf("admin (member) fake.list_items = %s", got) // "error:" = no fake account for the admin (-32031), also fine
	}
	if err := w.idSvc.SetUserRole(t.Context(), w.admin.id, w.admin.id, "admin"); err != nil {
		t.Fatal(err)
	}
	w.policy.Invalidate()
	for _, tool := range []string{"fake.list_items", "fake.list_accounts", "github.get_me", "slack.list_channels"} {
		if got := w.outcome(adminTok, tool, map[string]any{}); got != "unknown" {
			t.Errorf("admin-only user %s = %s, want unknown", tool, got)
		}
	}
	if names := toolNames(t, w.clientWith(adminTok)); len(names) != 0 {
		t.Errorf("admin-only tools/list = %v, want none", names)
	}

	// Token narrowing: apps allow-list and read-only, not widened by a
	// role that allows everything.
	narrow := w.token(w.alice, tokens.CreateRequest{Name: "narrow", AllowList: "github"})
	ro := w.token(w.alice, tokens.CreateRequest{Name: "ro", ReadOnly: true})
	w.setMemberRules([]policy.ToolRule{
		{App: fake.App, Tool: policy.Wildcard, Outcome: policy.OutcomeAllow},
		{App: github.App, Tool: policy.Wildcard, Outcome: policy.OutcomeAllow},
		{App: slackconn.App, Tool: policy.Wildcard, Outcome: policy.OutcomeAllow},
	})
	if got := w.outcome(narrow, "fake.list_items", map[string]any{}); got != "unknown" {
		t.Errorf("app-scoped token on fake = %s, want unknown", got)
	}
	if got := w.outcome(narrow, "slack.list_channels", map[string]any{}); got != "unknown" {
		t.Errorf("app-scoped token on slack = %s, want unknown", got)
	}
	if got := w.outcome(narrow, "github.get_me", map[string]any{}); got != "allow" {
		t.Errorf("app-scoped token on github = %s, want allow", got)
	}
	for _, write := range []string{"fake.post_note", "fake.create_item", "github.create_issue", "slack.post_message"} {
		if got := w.outcome(ro, write, map[string]any{"text": "x", "id": "x", "name": "x", "owner": "acme-labs", "repo": "w", "title": "t", "channel": "#eng-deploys"}); got != "unknown" {
			t.Errorf("read-only token on %s = %s, want unknown", write, got)
		}
	}
	if names := toolNames(t, w.clientWith(ro)); contains(names, "fake.post_note") || contains(names, "github.create_issue") {
		t.Errorf("read-only token lists writes: %v", names)
	}
	if n := len(w.fake.State().Notes(w.aliceAcc)); n != 0 || w.github.count() != 1 || len(w.slack.list()) != 0 {
		t.Errorf("a narrowed token wrote something: notes=%d github=%d slack=%d", n, w.github.count(), len(w.slack.list()))
	}
	w.setMemberRules(memberRules())

	// Version pinning: approve under version N, change the role (N+1),
	// the retry is refused and nothing runs.
	alice := w.clientWith(w.token(w.alice, tokens.CreateRequest{}))
	_, err := w.call(alice, "fake.create_item", map[string]any{"id": "pin-1", "name": "pinned"})
	id := approvalRequired(t, err)
	if code, _, _ := w.post(w.alice, "/approvals/"+id+"/approve", nil); code != 303 {
		t.Fatalf("approve = %d", code)
	}
	w.setMemberRules(append(memberRules(), policy.ToolRule{App: fake.App, Tool: fake.ToolFlakyWrite, Outcome: policy.OutcomeDeny}))
	_, err = w.call(alice, "fake.create_item", map[string]any{"id": "pin-1", "name": "pinned", "approval_id": id})
	if je := rpcError(t, err, mcp.CodeDenied); !strings.Contains(je.Message, "does not match") {
		t.Errorf("retry after a role change = %q", je.Message)
	}
	if items := w.fake.State().Items(w.aliceAcc); len(items) != 0 {
		t.Errorf("the pinned approval ran under a newer policy: %+v", items)
	}
	if a, _ := w.approval.Get(t.Context(), w.alice.id, id); a == nil || a.Status != approvals.StatusApproved {
		t.Errorf("approval after the refused retry = %+v (must stay approved, unconsumed)", a)
	}
	// A retry without approval_id does not silently pick it up either.
	_, err = w.call(alice, "fake.create_item", map[string]any{"id": "pin-1", "name": "pinned"})
	if err == nil || !strings.Contains(err.Error(), "approval") {
		t.Errorf("retry without approval_id after a role change = %v", err)
	}
	if items := w.fake.State().Items(w.aliceAcc); len(items) != 0 {
		t.Errorf("the pinned approval ran through the digest path: %+v", items)
	}
}
