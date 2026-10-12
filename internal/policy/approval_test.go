package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// approvalFixture: alice owns the server "notes" (private or published:
// the owner layer is the same); carol holds notes-writer (allow notes.*),
// erin notes-confirm (confirm notes.create), gina owns notes too but also
// holds notes-deny (deny notes.create), hal only github-writer. The
// server's approval modes put the tools in auto (all other writes ask).
func approvalFixture(t *testing.T, auto []string, restrictions ...UserRestriction) *Compiled {
	t.Helper()
	roles := []Role{
		{Name: "notes-writer", Rules: []ToolRule{{App: "notes", Tool: Wildcard, Outcome: OutcomeAllow}}},
		{Name: "notes-confirm", Rules: []ToolRule{{App: "notes", Tool: "create", Outcome: OutcomeConfirm}}},
		{Name: "notes-deny", Rules: []ToolRule{{App: "notes", Tool: "create", Outcome: OutcomeDeny}}},
		{Name: "github-writer", Rules: []ToolRule{{App: "github", Tool: Wildcard, Outcome: OutcomeAllow}}},
	}
	assignments := []Assignment{
		{UserID: "carol", Role: "notes-writer"}, {UserID: "erin", Role: "notes-confirm"},
		{UserID: "gina", Role: "notes-deny"}, {UserID: "gina", Role: "notes-writer"},
		{UserID: "hal", Role: "github-writer"},
	}
	c, err := CompileWithLayers(roles, assignments, restrictions, Layers{
		Owners:  []OwnerGrant{{UserID: "alice", App: "notes"}, {UserID: "gina", App: "notes"}},
		Servers: []ServerApproval{{App: "notes", AutoRun: auto}},
	})
	if err != nil {
		t.Fatalf("CompileWithLayers: %v", err)
	}
	return c
}

func decideFor(c *Compiled, user string, tool connectors.Tool) Outcome {
	return c.Decide(Input{UserID: user, Roles: c.RolesFor(user), Tool: tool}).Outcome
}

// The truth table of approval modes (Brain decision, task auto-approve).
func TestApprovalModeTruthTable(t *testing.T) {
	c := approvalFixture(t, []string{"create"})
	create, purge, search := ownerTool("create", connectors.KindWrite), ownerTool("purge", connectors.KindWrite), ownerTool("search", connectors.KindRead)
	ghWrite := connectors.Tool{App: "github", Name: "create_issue", Kind: connectors.KindWrite}
	for _, tc := range []struct {
		name string
		user string
		tool connectors.Tool
		want Outcome
	}{
		{"owner auto write runs", "alice", create, OutcomeAllow},
		{"owner ask write confirms", "alice", purge, OutcomeConfirm},
		{"owner read runs", "alice", search, OutcomeAllow},
		{"role allow + auto runs", "carol", create, OutcomeAllow},
		{"role allow + ask confirms", "carol", purge, OutcomeConfirm},
		{"role allow read runs", "carol", search, OutcomeAllow},
		{"role confirm + auto still confirms", "erin", create, OutcomeConfirm},
		{"role deny beats auto (also for an owner)", "gina", create, OutcomeHidden},
		{"built-in apps are not affected", "hal", ghWrite, OutcomeAllow},
	} {
		if got := decideFor(c, tc.user, tc.tool); got != tc.want {
			t.Errorf("%s: %s %s = %s, want %s", tc.name, tc.user, tc.tool.FullName(), got, tc.want)
		}
	}
}

// Without any auto tool (a review stored before approval modes, or all
// ask) owner and role writes confirm, exactly as before.
func TestApprovalModeDefaultAskConfirms(t *testing.T) {
	for _, c := range []*Compiled{approvalFixture(t, nil), ownerFixture(t)} {
		if got := decideFor(c, "alice", ownerTool("create", connectors.KindWrite)); got != OutcomeConfirm {
			t.Errorf("owner write without auto = %s, want confirm", got)
		}
	}
	if got := decideFor(approvalFixture(t, nil), "carol", ownerTool("create", connectors.KindWrite)); got != OutcomeConfirm {
		t.Errorf("role allow write without auto = %s, want confirm", got)
	}
}

// User restrictions and token narrowing still win over auto.
func TestApprovalModeNarrowedByRestrictionsAndTokens(t *testing.T) {
	create := ownerTool("create", connectors.KindWrite)
	c := approvalFixture(t, []string{"create"}, UserRestriction{UserID: "alice", Rules: []ToolRule{{App: "notes", Tool: "create", Outcome: OutcomeConfirm}}})
	if got := decideFor(c, "alice", create); got != OutcomeConfirm {
		t.Errorf("restriction confirm + auto = %s, want confirm", got)
	}
	c = approvalFixture(t, []string{"create"}, UserRestriction{UserID: "alice", Rules: []ToolRule{{App: "notes", Tool: "create", Outcome: OutcomeDeny}}})
	if got := decideFor(c, "alice", create); got != OutcomeHidden {
		t.Errorf("restriction deny + auto = %s, want hidden", got)
	}
	c = approvalFixture(t, []string{"create"})
	ro := Input{UserID: "alice", Roles: c.RolesFor("alice"), Tool: create, TokenScope: tokens.Scope{ReadOnly: true}}
	if got := c.Decide(ro).Outcome; got != OutcomeHidden {
		t.Errorf("read-only token + auto = %s, want hidden", got)
	}
}

// The compiled text names the auto tools (auditable, versioned); order
// and duplicates do not change the version; a mode change does.
func TestApprovalModeCompiledText(t *testing.T) {
	a := approvalFixture(t, []string{"create", "zap"})
	b := approvalFixture(t, []string{"zap", "create", "create"})
	if a.Version != b.Version {
		t.Error("auto list order or duplicates change the version")
	}
	if approvalFixture(t, []string{"create"}).Version == a.Version {
		t.Error("a mode change does not change the version")
	}
	if !strings.Contains(a.Cedar, `@id("server/notes/confirm_writes")`) || !strings.Contains(a.Cedar, `"notes.create"`) {
		t.Errorf("compiled text lacks the server approval policy:\n%s", a.Cedar)
	}
	for _, bad := range []ServerApproval{{App: "Bad App"}, {App: "notes", AutoRun: []string{`x"y`}}} {
		if _, err := CompileWithLayers(nil, nil, nil, Layers{Servers: []ServerApproval{bad}}); !errors.Is(err, ErrInvalidRole) {
			t.Errorf("%+v: err = %v, want ErrInvalidRole", bad, err)
		}
	}
	// CompileWithOwners is CompileWithLayers with owners only.
	x, _ := CompileWithOwners(nil, nil, nil, []OwnerGrant{{"u1", "a"}})
	y, _ := CompileWithLayers(nil, nil, nil, Layers{Owners: []OwnerGrant{{"u1", "a"}}})
	if x.Version != y.Version {
		t.Error("CompileWithOwners differs from CompileWithLayers with owners only")
	}
}

// The Service compiles the server approvals its store reports.
func TestServiceCompilesServerApprovals(t *testing.T) {
	st := &layerStore{snap: Snapshot{
		Owners:  []OwnerGrant{{UserID: "alice", App: "notes"}},
		Servers: []ServerApproval{{App: "notes", AutoRun: []string{"create"}}},
	}}
	svc, err := New(st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.Decide(context.Background(), Input{UserID: "alice", Tool: ownerTool("create", connectors.KindWrite)})
	if err != nil || d.Outcome != OutcomeAllow {
		t.Errorf("Decide = %v, %v; want allow from the auto mode", d.Outcome, err)
	}
}

type layerStore struct {
	ownerStore
	snap Snapshot
}

func (s *layerStore) Load(context.Context) (Snapshot, error) { return s.snap, nil }
