package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

func gatewayTool(name string, kind connectors.Kind) connectors.Tool {
	return connectors.Tool{App: GatewayApp, Name: name, Kind: kind, InputSchema: json.RawMessage(`{"type":"object"}`)}
}

// The gateway.* management tools (Brain task 99b5yzdb) need no role
// grant: the gateway layer lets every user list and call them (the
// connector's gate hides them unless the user is permitted AND switched
// them on), reads and add_server allow, delete_server confirms. Nothing
// outside the gateway app changes.
func TestGatewayLayerDefaults(t *testing.T) {
	roles := []Role{{Name: "member", Rules: []ToolRule{{App: "github", Tool: Wildcard, Outcome: OutcomeAllow}}}}
	c, err := Compile(roles, []Assignment{{UserID: "alice", Role: "member"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user string
		tool connectors.Tool
		want Outcome
	}{
		{"alice", gatewayTool("list_servers", connectors.KindRead), OutcomeAllow},
		{"alice", gatewayTool("add_server", connectors.KindWrite), OutcomeAllow},
		{"alice", gatewayTool(GatewayConfirmTool, connectors.KindWrite), OutcomeConfirm},
		// A user with no role at all.
		{"nobody", gatewayTool("get_server", connectors.KindRead), OutcomeAllow},
		{"nobody", gatewayTool(GatewayConfirmTool, connectors.KindWrite), OutcomeConfirm},
		// Other apps are untouched.
		{"nobody", connectors.Tool{App: "fake", Name: "list_items", Kind: connectors.KindRead}, OutcomeHidden},
	} {
		in := Input{UserID: tc.user, Roles: c.RolesFor(tc.user), Tool: tc.tool}
		if got := c.Decide(in).Outcome; got != tc.want {
			t.Errorf("%s %s: Decide = %s, want %s", tc.user, tc.tool.FullName(), got, tc.want)
		}
		if got, want := c.Visible(in), tc.want != OutcomeHidden; got != want {
			t.Errorf("%s %s: Visible = %v, want %v", tc.user, tc.tool.FullName(), got, want)
		}
	}
	if !strings.Contains(c.Cedar, `@id("gateway/management")`) {
		t.Errorf("compiled text lacks the gateway layer:\n%s", c.Cedar)
	}
}

// A role cannot lift delete_server's confirmation, but can deny the
// tools; token narrowing and user restrictions still apply; the admin
// role gets nothing extra.
func TestGatewayLayerNarrowing(t *testing.T) {
	roles := []Role{
		{Name: "admin", Rules: []ToolRule{{App: GatewayApp, Tool: Wildcard, Outcome: OutcomeAllow}}},
		{Name: "no-delete", Rules: []ToolRule{{App: GatewayApp, Tool: GatewayConfirmTool, Outcome: OutcomeDeny}}},
	}
	restrictions := []UserRestriction{{UserID: "carol", Rules: []ToolRule{{App: GatewayApp, Tool: "add_server", Outcome: OutcomeDeny}}}}
	c, err := Compile(roles, []Assignment{{UserID: "root", Role: "admin"}, {UserID: "bob", Role: "no-delete"}}, restrictions)
	if err != nil {
		t.Fatal(err)
	}
	del := gatewayTool(GatewayConfirmTool, connectors.KindWrite)
	add := gatewayTool("add_server", connectors.KindWrite)
	list := gatewayTool("list_servers", connectors.KindRead)
	decide := func(user string, tool connectors.Tool, scope tokens.Scope) Outcome {
		return c.Decide(Input{UserID: user, Roles: c.RolesFor(user), Tool: tool, TokenScope: scope}).Outcome
	}
	if got := decide("root", del, tokens.Scope{}); got != OutcomeConfirm {
		t.Errorf("admin delete_server = %s, want confirm (admin never bypasses)", got)
	}
	if got := decide("bob", del, tokens.Scope{}); got != OutcomeHidden && got != OutcomeDeny {
		t.Errorf("role-denied delete_server = %s, want deny or hidden", got)
	}
	if got := decide("carol", add, tokens.Scope{}); got != OutcomeHidden && got != OutcomeDeny {
		t.Errorf("restricted add_server = %s, want deny or hidden", got)
	}
	readOnly := tokens.Scope{ReadOnly: true}
	if got := decide("alice", add, readOnly); got != OutcomeHidden {
		t.Errorf("read-only token add_server = %s, want hidden", got)
	}
	if got := decide("alice", list, readOnly); got != OutcomeAllow {
		t.Errorf("read-only token list_servers = %s, want allow", got)
	}
	other := tokens.Scope{Apps: []string{"github"}}
	if !other.IsRestricted() {
		t.Fatal("scope with apps is not restricted")
	}
	if got := decide("alice", list, other); got != OutcomeHidden {
		t.Errorf("token restricted to github: list_servers = %s, want hidden", got)
	}
}
