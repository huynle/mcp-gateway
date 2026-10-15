package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Resources and prompts of a user-added MCP server are two per-server
// actions (Brain task bdb5zcud, decision q7vbxlyk point 2):
// "<server>.resources/read" and "<server>.prompts/get".
func TestServerAccessToolNames(t *testing.T) {
	r, p := ServerAccessTool("notes", ResourcesReadTool), ServerAccessTool("notes", PromptsGetTool)
	if r.FullName() != "notes.resources/read" || p.FullName() != "notes.prompts/get" {
		t.Errorf("names = %q, %q", r.FullName(), p.FullName())
	}
	if r.Kind != connectors.KindRead || p.Kind != connectors.KindRead {
		t.Errorf("kinds = %s, %s; want read", r.Kind, p.Kind)
	}
	if !IsServerAccessTool("resources/read") || !IsServerAccessTool("prompts/get") || IsServerAccessTool("search") {
		t.Error("IsServerAccessTool")
	}
}

func TestRuleValidationAcceptsServerAccessTools(t *testing.T) {
	for _, tool := range []string{ResourcesReadTool, PromptsGetTool} {
		r := Role{Name: "x", Rules: []ToolRule{{App: "notes", Tool: tool, Outcome: OutcomeAllow}}}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", tool, err)
		}
	}
	for _, tool := range []string{"resources/list", "foo/bar", "resources/", "/read"} {
		r := Role{Name: "x", Rules: []ToolRule{{App: "notes", Tool: tool, Outcome: OutcomeAllow}}}
		if err := r.Validate(); !errors.Is(err, ErrInvalidRole) {
			t.Errorf("%s: %v, want ErrInvalidRole", tool, err)
		}
	}
}

func TestServerAccessToolsPolicy(t *testing.T) {
	roles := []Role{
		{Name: "member"},
		{Name: "readers", Rules: []ToolRule{{App: "notes", Tool: ResourcesReadTool, Outcome: OutcomeAllow}}},
		{Name: "wild", Rules: []ToolRule{{App: "notes", Tool: Wildcard, Outcome: OutcomeAllow}}},
		{Name: "confirmers", Rules: []ToolRule{{App: "notes", Tool: Wildcard, Outcome: OutcomeConfirm}}},
		{Name: "deny-notes", Rules: []ToolRule{{App: "notes", Tool: Wildcard, Outcome: OutcomeDeny}}},
	}
	assignments := []Assignment{
		{UserID: "alice", Role: "member"}, {UserID: "bob", Role: "member"}, {UserID: "carol", Role: "readers"},
		{UserID: "dave", Role: "wild"}, {UserID: "erin", Role: "confirmers"}, {UserID: "frank", Role: "deny-notes"},
	}
	owners := []OwnerGrant{{UserID: "alice", App: "notes"}, {UserID: "frank", App: "notes"}}
	c, err := CompileWithOwners(roles, assignments, nil, owners)
	if err != nil {
		t.Fatal(err)
	}
	res, pr := ServerAccessTool("notes", ResourcesReadTool), ServerAccessTool("notes", PromptsGetTool)
	for _, tc := range []struct {
		user  string
		tool  connectors.Tool
		scope tokens.Scope
		want  bool
	}{
		{"alice", res, tokens.Scope{}, true}, // owner layer
		{"alice", pr, tokens.Scope{}, true},
		{"alice", res, tokens.Scope{ReadOnly: true}, true}, // a read
		{"alice", res, tokens.Scope{Apps: []string{"github"}}, false},
		{"alice", res, tokens.Scope{Tools: []string{"notes.resources/read"}}, true},
		{"bob", res, tokens.Scope{}, false}, // nothing granted
		{"bob", pr, tokens.Scope{}, false},
		{"carol", res, tokens.Scope{}, true}, // granted explicitly
		{"carol", pr, tokens.Scope{}, false},
		{"dave", res, tokens.Scope{}, true}, // the wildcard covers both
		{"dave", pr, tokens.Scope{}, true},
		{"erin", res, tokens.Scope{}, false},  // confirm cannot be asked for: refused
		{"frank", res, tokens.Scope{}, false}, // role deny beats the owner layer
		{"frank", pr, tokens.Scope{}, false},
	} {
		in := Input{UserID: tc.user, Roles: c.RolesFor(tc.user), Tool: tc.tool, TokenScope: tc.scope}
		if got := c.Permits(in); got != tc.want {
			t.Errorf("%s %s %+v: Permits = %v, want %v", tc.user, tc.tool.FullName(), tc.scope, got, tc.want)
		}
	}
}

func TestServicePermits(t *testing.T) {
	st := &snapStore{snap: Snapshot{
		Roles:       []StoredRole{{Role: Role{Name: "member"}}},
		Assignments: []Assignment{{UserID: "alice", Role: "member"}, {UserID: "bob", Role: "member"}},
		Owners:      []OwnerGrant{{UserID: "alice", App: "notes"}},
	}}
	svc, err := New(st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ok, err := svc.Permits(ctx, Input{UserID: "alice", Roles: []string{"admin"}, Tool: ServerAccessTool("notes", ResourcesReadTool)}); err != nil || !ok {
		t.Errorf("owner: %v, %v", ok, err)
	}
	// Claimed roles are ignored: the compiled assignments decide.
	if ok, err := svc.Permits(ctx, Input{UserID: "bob", Roles: []string{"admin"}, Tool: ServerAccessTool("notes", ResourcesReadTool)}); err != nil || ok {
		t.Errorf("bob: %v, %v", ok, err)
	}
}

// snapStore is a Store serving a fixed snapshot.
type snapStore struct{ snap Snapshot }

func (s *snapStore) Load(context.Context) (Snapshot, error)       { return s.snap, nil }
func (s *snapStore) SaveRole(context.Context, Role) error         { return nil }
func (s *snapStore) DeleteRole(context.Context, string) error     { return nil }
func (s *snapStore) SetDefaultRole(context.Context, string) error { return nil }
func (s *snapStore) SetAppAsk(context.Context, string, string, []string) error {
	return nil
}
func (s *snapStore) SaveVersion(_ context.Context, v Version) (Version, error) {
	v.ID = "v1"
	return v, nil
}
