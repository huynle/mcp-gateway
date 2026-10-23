package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

func secretsTool() connectors.Tool {
	return connectors.Tool{App: SecretsApp, Name: "request", Kind: connectors.KindRead, InputSchema: json.RawMessage(`{"type":"object"}`)}
}

// secrets.request (design correction 6) needs no role grant: the secrets
// layer lets every user list and call it. A read-only token neither sees
// nor calls it, although it is a read; a token allow-list that leaves the
// app out hides it; an admin's role deny and a user restriction still win.
func TestSecretsLayer(t *testing.T) {
	roles := []Role{
		{Name: "member", Rules: []ToolRule{{App: "github", Tool: Wildcard, Outcome: OutcomeAllow}}},
		{Name: "no-secrets", Rules: []ToolRule{{App: SecretsApp, Tool: Wildcard, Outcome: OutcomeDeny}}},
	}
	restrictions := []UserRestriction{{UserID: "carol", Rules: []ToolRule{{App: SecretsApp, Tool: "request", Outcome: OutcomeDeny}}}}
	c, err := Compile(roles, []Assignment{{UserID: "alice", Role: "member"}, {UserID: "bob", Role: "no-secrets"}}, restrictions)
	if err != nil {
		t.Fatal(err)
	}
	req := secretsTool()
	decide := func(user string, scope tokens.Scope) Outcome {
		return c.Decide(Input{UserID: user, Roles: c.RolesFor(user), Tool: req, TokenScope: scope}).Outcome
	}
	visible := func(user string, scope tokens.Scope) bool {
		return c.Visible(Input{UserID: user, Roles: c.RolesFor(user), Tool: req, TokenScope: scope})
	}
	for _, tc := range []struct {
		name  string
		user  string
		scope tokens.Scope
		want  Outcome
	}{
		{"member", "alice", tokens.Scope{}, OutcomeAllow},
		{"no role", "nobody", tokens.Scope{}, OutcomeAllow},
		{"read-only token", "alice", tokens.Scope{ReadOnly: true}, OutcomeHidden},
		{"allow-list without secrets", "alice", tokens.Scope{Apps: []string{"github"}}, OutcomeHidden},
		{"allow-list with secrets", "alice", tokens.Scope{Apps: []string{"github", SecretsApp}}, OutcomeAllow},
	} {
		if got := decide(tc.user, tc.scope); got != tc.want {
			t.Errorf("%s: Decide = %s, want %s", tc.name, got, tc.want)
		}
		if got, want := visible(tc.user, tc.scope), tc.want != OutcomeHidden; got != want {
			t.Errorf("%s: Visible = %v, want %v", tc.name, got, want)
		}
	}
	for _, user := range []string{"bob", "carol"} {
		if got := decide(user, tokens.Scope{}); got != OutcomeHidden && got != OutcomeDeny {
			t.Errorf("%s (denied by role or restriction): Decide = %s, want deny or hidden", user, got)
		}
	}
	// Other apps are untouched: a read-only token still reads elsewhere.
	other := connectors.Tool{App: "github", Name: "list_issues", Kind: connectors.KindRead}
	if got := c.Decide(Input{UserID: "alice", Roles: c.RolesFor("alice"), Tool: other, TokenScope: tokens.Scope{ReadOnly: true}}).Outcome; got != OutcomeAllow {
		t.Errorf("read-only github read = %s, want allow", got)
	}
	for _, id := range []string{`@id("secrets/request")`, `@id("secrets/read_only")`} {
		if !strings.Contains(c.Cedar, id) {
			t.Errorf("compiled text lacks %s:\n%s", id, c.Cedar)
		}
	}
}
