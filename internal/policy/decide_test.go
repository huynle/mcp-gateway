package policy

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

func tool(name string, kind connectors.Kind) connectors.Tool {
	app, short, _ := strings.Cut(name, ".")
	return connectors.Tool{App: app, Name: short, Kind: kind}
}

var (
	read  = connectors.KindRead
	write = connectors.KindWrite
)

// decisionCase is one row of the decision tables below.
type decisionCase struct {
	name     string
	roles    []string
	user     string
	scope    tokens.Scope
	tool     connectors.Tool
	label    string
	resource map[string]string
	want     Outcome
	visible  bool
}

func runTable(t *testing.T, c *Compiled, cases []decisionCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := tc.user
			if user == "" {
				user = "u-test"
			}
			in := Input{UserID: user, Roles: tc.roles, TokenID: "tok", TokenScope: tc.scope, Tool: tc.tool, AccountLabel: tc.label, ResourceIdentity: tc.resource}
			d := c.Decide(in)
			if d.Outcome != tc.want {
				t.Errorf("Decide = %s (%s), want %s", d.Outcome, d.Reason, tc.want)
			}
			if d.Version != c.Version {
				t.Errorf("Decision.Version = %q, want %q", d.Version, c.Version)
			}
			if d.Reason == "" {
				t.Error("Decision.Reason is empty")
			}
			if got := c.Visible(in); got != tc.visible {
				t.Errorf("Visible = %v, want %v", got, tc.visible)
			}
		})
	}
}

func TestDecideEngineering(t *testing.T) {
	c := compileFixture(t, "engineering")
	eng := []string{"engineer"}
	runTable(t, c, []decisionCase{
		// Plain grants and wildcard.
		{name: "wildcard allow read", roles: eng, tool: tool("github.list_issues", read), label: "company", want: OutcomeAllow, visible: true},
		{name: "wildcard allow write", roles: eng, tool: tool("github.close_issue", write), label: "company", want: OutcomeAllow, visible: true},
		{name: "hidden tool", roles: eng, tool: tool("github.delete_repo", write), label: "company", want: OutcomeHidden, visible: false},
		{name: "unknown app", roles: eng, tool: tool("jira.search", read), label: "company", want: OutcomeHidden, visible: false},
		// Conditions: allow + conditional confirm on the same tool.
		{name: "confirm when prefix matches", roles: eng, tool: tool("github.create_issue", write), label: "company", resource: map[string]string{"repo": "acme/web"}, want: OutcomeConfirm, visible: true},
		{name: "allow when prefix does not match", roles: eng, tool: tool("github.create_issue", write), label: "company", resource: map[string]string{"repo": "other/web"}, want: OutcomeAllow, visible: true},
		{name: "allow when key absent", roles: eng, tool: tool("github.create_issue", write), label: "company", want: OutcomeAllow, visible: true},
		// Conditional deny: visible, denied only when it matches.
		{name: "deny equals", roles: eng, tool: tool("github.merge_pr", write), label: "company", resource: map[string]string{"repo": "acme/prod"}, want: OutcomeDeny, visible: true},
		{name: "deny equals no match", roles: eng, tool: tool("github.merge_pr", write), label: "company", resource: map[string]string{"repo": "acme/dev"}, want: OutcomeAllow, visible: true},
		{name: "glob deny", roles: eng, tool: tool("slack.post_message", write), label: "company", resource: map[string]string{"channel": "#exec-board"}, want: OutcomeDeny, visible: true},
		{name: "glob deny no match falls back to wildcard confirm", roles: eng, tool: tool("slack.post_message", write), label: "company", resource: map[string]string{"channel": "#eng"}, want: OutcomeConfirm, visible: true},
		{name: "conditional deny without the key falls back to wildcard", roles: eng, tool: tool("slack.post_message", write), label: "company", want: OutcomeConfirm, visible: true},
		{name: "wildcard confirm", roles: eng, tool: tool("slack.search", read), label: "company", want: OutcomeConfirm, visible: true},
		{name: "specific allow over wildcard confirm", roles: eng, tool: tool("slack.list_channels", read), label: "company", want: OutcomeAllow, visible: true},
		// Personal accounts.
		{name: "personal confirm_writes on write", roles: eng, tool: tool("github.close_issue", write), label: "personal", want: OutcomeConfirm, visible: true},
		{name: "personal confirm_writes on read", roles: eng, tool: tool("github.list_issues", read), label: "personal", want: OutcomeAllow, visible: true},
		{name: "personal deny", roles: eng, tool: tool("slack.list_channels", read), label: "personal", want: OutcomeDeny, visible: true},
		{name: "no account label (list_accounts)", roles: eng, tool: tool("github.list_accounts", read), label: "", want: OutcomeAllow, visible: true},
		// Admin role grants nothing; member sees only its reads.
		{name: "admin alone gets nothing", roles: []string{"admin"}, tool: tool("github.list_issues", read), label: "company", want: OutcomeHidden, visible: false},
		{name: "admin plus engineer is engineer", roles: []string{"admin", "engineer"}, tool: tool("github.list_issues", read), label: "company", want: OutcomeAllow, visible: true},
		{name: "no roles", roles: nil, tool: tool("github.list_issues", read), label: "company", want: OutcomeHidden, visible: false},
		{name: "member read", roles: []string{"member"}, tool: tool("fake.list_items", read), label: "company", want: OutcomeAllow, visible: true},
		{name: "member write is deny-all => hidden", roles: []string{"member"}, tool: tool("fake.create_item", write), label: "company", want: OutcomeHidden, visible: false},
		// Two roles: deny in one vetoes allow in the other.
		{name: "deny wins across roles", roles: []string{"member", "engineer"}, tool: tool("fake.create_item", write), label: "company", want: OutcomeHidden, visible: false},
		// Token narrowing.
		{name: "read-only token hides writes", roles: eng, scope: tokens.Scope{ReadOnly: true}, tool: tool("github.close_issue", write), label: "company", want: OutcomeHidden, visible: false},
		{name: "read-only token keeps reads", roles: eng, scope: tokens.Scope{ReadOnly: true}, tool: tool("github.list_issues", read), label: "company", want: OutcomeAllow, visible: true},
		{name: "app allow-list admits app", roles: eng, scope: tokens.Scope{Apps: []string{"github"}}, tool: tool("github.list_issues", read), label: "company", want: OutcomeAllow, visible: true},
		{name: "app allow-list hides other apps", roles: eng, scope: tokens.Scope{Apps: []string{"github"}}, tool: tool("slack.search", read), label: "company", want: OutcomeHidden, visible: false},
		{name: "tool allow-list admits tool", roles: eng, scope: tokens.Scope{Tools: []string{"slack.search"}}, tool: tool("slack.search", read), label: "company", want: OutcomeConfirm, visible: true},
		{name: "tool allow-list hides siblings", roles: eng, scope: tokens.Scope{Tools: []string{"slack.search"}}, tool: tool("slack.list_channels", read), label: "company", want: OutcomeHidden, visible: false},
		{name: "token cannot widen", roles: []string{"member"}, scope: tokens.Scope{Apps: []string{"github"}}, tool: tool("github.list_issues", read), label: "company", want: OutcomeHidden, visible: false},
		// User restrictions (u-carol is an engineer).
		{name: "restriction hidden", user: "u-carol", roles: eng, tool: tool("github.merge_pr", write), label: "company", resource: map[string]string{"repo": "acme/dev"}, want: OutcomeHidden, visible: false},
		{name: "restriction deny wildcard", user: "u-carol", roles: eng, tool: tool("slack.list_channels", read), label: "company", want: OutcomeHidden, visible: false},
		{name: "restriction confirm tightens allow", user: "u-carol", roles: eng, tool: tool("github.create_issue", write), label: "company", resource: map[string]string{"repo": "other/x"}, want: OutcomeConfirm, visible: true},
		{name: "restriction conditional deny", user: "u-carol", roles: eng, tool: tool("github.list_issues", read), label: "company", resource: map[string]string{"repo": "secret/x"}, want: OutcomeDeny, visible: true},
		{name: "restriction conditional deny no match", user: "u-carol", roles: eng, tool: tool("github.list_issues", read), label: "company", resource: map[string]string{"repo": "acme/x"}, want: OutcomeAllow, visible: true},
		{name: "restriction does not touch others", user: "u-alice", roles: eng, tool: tool("github.merge_pr", write), label: "company", resource: map[string]string{"repo": "acme/dev"}, want: OutcomeAllow, visible: true},
	})
}

func TestDecideWildcardConditions(t *testing.T) {
	c := compileFixture(t, "wildcards")
	r := []string{"reader"}
	runTable(t, c, []decisionCase{
		{name: "wildcard allow with condition met", roles: r, tool: tool("github.list_issues", read), label: "company", resource: map[string]string{"org": "acme"}, want: OutcomeAllow, visible: true},
		{name: "wildcard allow with condition unmet is deny but visible", roles: r, tool: tool("github.list_issues", read), label: "company", resource: map[string]string{"org": "evil"}, want: OutcomeDeny, visible: true},
		{name: "wildcard allow without the key is deny", roles: r, tool: tool("github.list_issues", read), label: "company", want: OutcomeDeny, visible: true},
		{name: "wildcard hidden", roles: r, tool: tool("slack.search", read), label: "company", want: OutcomeHidden, visible: false},
		{name: "wildcard deny with specific allow", roles: r, tool: tool("jira.search", read), label: "company", want: OutcomeAllow, visible: true},
		{name: "wildcard deny otherwise", roles: r, tool: tool("jira.create_issue", write), label: "company", want: OutcomeHidden, visible: false},
		{name: "personal allow explicit", roles: r, tool: tool("github.create_issue", write), label: "personal", resource: map[string]string{"org": "acme"}, want: OutcomeAllow, visible: true},
		{name: "conditional specific allow wins over wildcard confirm where it matches", roles: r, tool: tool("jira.get_issue", read), label: "company", resource: map[string]string{"project": "OPS"}, want: OutcomeAllow, visible: true},
		{name: "conditional specific allow leaves wildcard deny elsewhere", roles: r, tool: tool("jira.get_issue", read), label: "company", resource: map[string]string{"project": "HR"}, want: OutcomeDeny, visible: true},
	})
}

func TestDecideReasonsNamePolicies(t *testing.T) {
	c := compileFixture(t, "engineering")
	in := Input{UserID: "u-alice", Roles: []string{"engineer"}, Tool: tool("github.merge_pr", write), AccountLabel: "company", ResourceIdentity: map[string]string{"repo": "acme/prod"}}
	if d := c.Decide(in); !strings.Contains(d.Reason, "role/engineer/github.merge_pr/deny") {
		t.Errorf("deny reason = %q", d.Reason)
	}
	in.ResourceIdentity = map[string]string{"repo": "acme/x"}
	in.Tool = tool("github.create_issue", write)
	if d := c.Decide(in); !strings.Contains(d.Reason, "role/engineer/github.create_issue/confirm") {
		t.Errorf("confirm reason = %q", d.Reason)
	}
	in.Tool = tool("github.delete_repo", write)
	if d := c.Decide(in); !strings.Contains(d.Reason, "not visible") {
		t.Errorf("hidden reason = %q", d.Reason)
	}
}

func TestDecideEmptyPolicyHidesEverything(t *testing.T) {
	c, err := Compile(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{UserID: "u", Roles: []string{"admin"}, Tool: tool("github.list_issues", read)}
	if d := c.Decide(in); d.Outcome != OutcomeHidden {
		t.Errorf("empty policy: %+v", d)
	}
	if c.Visible(in) {
		t.Error("empty policy makes a tool visible")
	}
}
