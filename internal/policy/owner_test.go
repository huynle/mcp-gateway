package policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

func ownerTool(name string, kind connectors.Kind) connectors.Tool {
	const app = "notes"
	return connectors.Tool{App: app, Name: name, Kind: kind, InputSchema: json.RawMessage(`{"type":"object"}`)}
}

// ownerFixture: alice owns the private server "notes"; bob is a member
// whose role allows every notes tool (a role naming a private server has
// no effect for non-owners in production, because server visibility
// hides it, but the policy layer itself is still role-driven for them).
func ownerFixture(t *testing.T, restrictions ...UserRestriction) *Compiled {
	t.Helper()
	roles := []Role{
		{Name: "member", Rules: []ToolRule{{App: "github", Tool: Wildcard, Outcome: OutcomeAllow}}},
		{Name: "notes-writer", Rules: []ToolRule{{App: "notes", Tool: "create", Outcome: OutcomeAllow}}},
	}
	assignments := []Assignment{{UserID: "alice", Role: "member"}, {UserID: "bob", Role: "member"}, {UserID: "carol", Role: "notes-writer"}}
	c, err := CompileWithOwners(roles, assignments, restrictions, []OwnerGrant{{UserID: "alice", App: "notes"}, {UserID: "dave", App: "notes"}})
	if err != nil {
		t.Fatalf("CompileWithOwners: %v", err)
	}
	return c
}

func TestOwnerGrantDefaults(t *testing.T) {
	c := ownerFixture(t)
	read, write := ownerTool("search", connectors.KindRead), ownerTool("create", connectors.KindWrite)

	for _, tc := range []struct {
		user string
		tool connectors.Tool
		want Outcome
	}{
		{"alice", read, OutcomeAllow},
		{"alice", write, OutcomeConfirm},
		{"bob", read, OutcomeHidden},
		{"bob", write, OutcomeHidden},
		// A user with no role at all who owns the server.
		{"dave", read, OutcomeAllow},
		{"dave", write, OutcomeConfirm},
	} {
		in := Input{UserID: tc.user, Roles: c.RolesFor(tc.user), Tool: tc.tool}
		if got := c.Decide(in).Outcome; got != tc.want {
			t.Errorf("%s %s: Decide = %s, want %s", tc.user, tc.tool.FullName(), got, tc.want)
		}
		if got, want := c.Visible(in), tc.want != OutcomeHidden; got != want {
			t.Errorf("%s %s: Visible = %v, want %v", tc.user, tc.tool.FullName(), got, want)
		}
	}
	if !c.KnowsUser("dave") {
		t.Error("an owner without roles is unknown to the compiled policy (would reload on every call)")
	}
	if !strings.Contains(c.Cedar, `@id("owner/alice/notes")`) {
		t.Errorf("compiled text lacks the owner policy:\n%s", c.Cedar)
	}
}

// A role that allows a write tool cannot lift the confirmation of a write
// in approval mode "ask" (the default; confirm beats allow). Only the
// server's approval mode "auto" does (approval_test.go).
func TestOwnerGrantWriteStaysConfirmWithRoleAllow(t *testing.T) {
	roles := []Role{{Name: "notes-writer", Rules: []ToolRule{{App: "notes", Tool: "create", Outcome: OutcomeAllow}}}}
	c, err := CompileWithOwners(roles, []Assignment{{UserID: "alice", Role: "notes-writer"}}, nil, []OwnerGrant{{UserID: "alice", App: "notes"}})
	if err != nil {
		t.Fatal(err)
	}
	in := Input{UserID: "alice", Roles: c.RolesFor("alice"), Tool: ownerTool("create", connectors.KindWrite)}
	if got := c.Decide(in).Outcome; got != OutcomeConfirm {
		t.Errorf("owner write with a role allow = %s, want confirm", got)
	}
}

// Token narrowing and user restrictions still apply to owners.
func TestOwnerGrantNarrowedByTokenAndRestrictions(t *testing.T) {
	c := ownerFixture(t, UserRestriction{UserID: "alice", Rules: []ToolRule{{App: "notes", Tool: "search", Outcome: OutcomeDeny}}})
	read, write := ownerTool("search", connectors.KindRead), ownerTool("create", connectors.KindWrite)

	// An unconditional deny restriction also forbids list: hidden.
	if got := c.Decide(Input{UserID: "alice", Roles: c.RolesFor("alice"), Tool: read}).Outcome; got != OutcomeHidden {
		t.Errorf("restricted owner read = %s, want hidden", got)
	}
	ro := Input{UserID: "alice", Roles: c.RolesFor("alice"), Tool: write, TokenScope: tokens.Scope{ReadOnly: true}}
	if c.Visible(ro) {
		t.Error("a read-only token sees the owner's write tool")
	}
	scoped := Input{UserID: "alice", Roles: c.RolesFor("alice"), Tool: write, TokenScope: tokens.Scope{Apps: []string{"github"}}}
	if c.Visible(scoped) {
		t.Error("a token restricted to github sees the owner's notes tool")
	}
}

func TestOwnerGrantValidation(t *testing.T) {
	for _, g := range []OwnerGrant{{UserID: "", App: "notes"}, {UserID: "alice", App: "Bad App"}} {
		if _, err := CompileWithOwners(nil, nil, nil, []OwnerGrant{g}); !errors.Is(err, ErrInvalidRole) {
			t.Errorf("grant %+v: err = %v, want ErrInvalidRole", g, err)
		}
	}
	// Compile (no owners) is unchanged: equal inputs, equal versions.
	a, err := Compile(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CompileWithOwners(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != b.Version {
		t.Error("CompileWithOwners without owners differs from Compile")
	}
	// Order of grants does not change the version.
	x, _ := CompileWithOwners(nil, nil, nil, []OwnerGrant{{"u1", "a"}, {"u2", "b"}})
	y, _ := CompileWithOwners(nil, nil, nil, []OwnerGrant{{"u2", "b"}, {"u1", "a"}, {"u1", "a"}})
	if x.Version != y.Version {
		t.Error("grant order or duplicates change the version")
	}
}

// The Service compiles the owners its store reports.
func TestServiceCompilesOwnerGrants(t *testing.T) {
	st := &ownerStore{owners: []OwnerGrant{{UserID: "alice", App: "notes"}}}
	svc, err := New(st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.Decide(context.Background(), Input{UserID: "alice", Tool: ownerTool("search", connectors.KindRead)})
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != OutcomeAllow {
		t.Errorf("Decide = %s, want allow from the owner layer", d.Outcome)
	}
}

// ownerStore is a minimal Store that reports owner grants.
type ownerStore struct{ owners []OwnerGrant }

func (s *ownerStore) Load(context.Context) (Snapshot, error) {
	return Snapshot{Owners: s.owners}, nil
}
func (s *ownerStore) SaveRole(context.Context, Role) error         { return nil }
func (s *ownerStore) DeleteRole(context.Context, string) error     { return nil }
func (s *ownerStore) SetDefaultRole(context.Context, string) error { return nil }
func (s *ownerStore) SaveVersion(_ context.Context, v Version) (Version, error) {
	v.ID = "v1"
	return v, nil
}
