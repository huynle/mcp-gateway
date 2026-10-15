package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

func ghTool(name string, kind connectors.Kind) connectors.Tool {
	return connectors.Tool{App: "github", Name: name, Kind: kind}
}

// appFixture: writer holds github-writer (allow github.*), confirmer
// github-confirm (confirm github.create_issue), denier github-deny (deny
// github.create_issue next to allow github.*). The vendor app approval
// layer sets ask on the given github tools.
func appFixture(t *testing.T, ask []string, restrictions ...UserRestriction) *Compiled {
	t.Helper()
	roles := []Role{
		{Name: "github-writer", Rules: []ToolRule{{App: "github", Tool: Wildcard, Outcome: OutcomeAllow}}},
		{Name: "github-confirm", Rules: []ToolRule{{App: "github", Tool: "create_issue", Outcome: OutcomeConfirm}}},
		{Name: "github-deny", Rules: []ToolRule{{App: "github", Tool: "create_issue", Outcome: OutcomeDeny}}},
	}
	assignments := []Assignment{
		{UserID: "writer", Role: "github-writer"}, {UserID: "confirmer", Role: "github-confirm"},
		{UserID: "denier", Role: "github-deny"}, {UserID: "denier", Role: "github-writer"},
	}
	c, err := CompileWithLayers(roles, assignments, restrictions, Layers{Apps: []AppApproval{{App: "github", Ask: ask}}})
	if err != nil {
		t.Fatalf("CompileWithLayers: %v", err)
	}
	return c
}

// The truth table of vendor app approval modes: Ask only adds a
// confirmation; Auto (the default) never removes one.
func TestAppApprovalTruthTable(t *testing.T) {
	c := appFixture(t, []string{"create_issue", "list_issues"})
	create, comment, list := ghTool("create_issue", connectors.KindWrite), ghTool("add_comment", connectors.KindWrite), ghTool("list_issues", connectors.KindRead)
	for _, tc := range []struct {
		name string
		user string
		tool connectors.Tool
		want Outcome
	}{
		{"allow + ask confirms", "writer", create, OutcomeConfirm},
		{"allow + auto runs", "writer", comment, OutcomeAllow},
		{"read tool named ask still runs", "writer", list, OutcomeAllow},
		{"role confirm + ask confirms", "confirmer", create, OutcomeConfirm},
		{"deny + ask stays denied", "denier", create, OutcomeHidden},
		{"no grant + ask is not a grant", "nobody", create, OutcomeHidden},
	} {
		if got := decideFor(c, tc.user, tc.tool); got != tc.want {
			t.Errorf("%s: %s %s = %s, want %s", tc.name, tc.user, tc.tool.FullName(), got, tc.want)
		}
	}
	auto := appFixture(t, nil)
	if got := decideFor(auto, "confirmer", create); got != OutcomeConfirm {
		t.Errorf("role confirm + auto = %s, want confirm (auto never lifts a role confirm)", got)
	}
	if got := decideFor(auto, "writer", create); got != OutcomeAllow {
		t.Errorf("allow + auto = %s, want allow", got)
	}
}

// Restrictions and token narrowing still win over the layer.
func TestAppApprovalNarrowing(t *testing.T) {
	create := ghTool("create_issue", connectors.KindWrite)
	c := appFixture(t, []string{"create_issue"}, UserRestriction{UserID: "writer", Rules: []ToolRule{{App: "github", Tool: "create_issue", Outcome: OutcomeDeny}}})
	if got := decideFor(c, "writer", create); got != OutcomeHidden {
		t.Errorf("restriction deny + ask = %s, want hidden", got)
	}
	c = appFixture(t, []string{"create_issue"})
	ro := Input{UserID: "writer", Roles: c.RolesFor("writer"), Tool: create, TokenScope: tokens.Scope{ReadOnly: true}}
	if got := c.Decide(ro).Outcome; got != OutcomeHidden {
		t.Errorf("read-only token + ask = %s, want hidden", got)
	}
}

// Without app layers (or with empty ask lists) the compiled text is
// byte-identical to Compile's; the layer is named and versioned.
func TestAppApprovalCompiledText(t *testing.T) {
	roles := []Role{{Name: "github-writer", Rules: []ToolRule{{App: "github", Tool: Wildcard, Outcome: OutcomeAllow}}}}
	plain, err := Compile(roles, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := CompileWithLayers(roles, nil, nil, Layers{Apps: []AppApproval{{App: "github"}}})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Cedar != empty.Cedar {
		t.Errorf("empty app layer changes the text:\n%s\n---\n%s", plain.Cedar, empty.Cedar)
	}
	a := appFixture(t, []string{"create_issue", "zap"})
	b := appFixture(t, []string{"zap", "create_issue", "create_issue"})
	if a.Version != b.Version {
		t.Error("ask list order or duplicates change the version")
	}
	if appFixture(t, []string{"create_issue"}).Version == a.Version {
		t.Error("a mode change does not change the version")
	}
	if !strings.Contains(a.Cedar, `@id("app/github/ask_writes")`) || !strings.Contains(a.Cedar, `"github.create_issue"`) {
		t.Errorf("compiled text lacks the app approval policy:\n%s", a.Cedar)
	}
	for _, bad := range []AppApproval{{App: "Bad App", Ask: []string{"x"}}, {App: "github", Ask: []string{`x"y`}}, {App: GatewayApp, Ask: []string{"delete_server"}}} {
		if _, err := CompileWithLayers(nil, nil, nil, Layers{Apps: []AppApproval{bad}}); !errors.Is(err, ErrInvalidRole) {
			t.Errorf("%+v: err = %v, want ErrInvalidRole", bad, err)
		}
	}
}

// A user-added server app keeps its own ServerApproval: an app layer
// naming it is ignored.
func TestAppApprovalIgnoresServerApps(t *testing.T) {
	with, err := CompileWithLayers(nil, nil, nil, Layers{
		Owners:  []OwnerGrant{{UserID: "alice", App: "notes"}},
		Servers: []ServerApproval{{App: "notes", AutoRun: []string{"create"}}},
		Apps:    []AppApproval{{App: "notes", Ask: []string{"create"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := decideFor(with, "alice", ownerTool("create", connectors.KindWrite)); got != OutcomeAllow {
		t.Errorf("server auto tool with a stray app layer = %s, want allow", got)
	}
	if strings.Contains(with.Cedar, "app/notes/") {
		t.Errorf("app layer compiled for a server app:\n%s", with.Cedar)
	}
}

// --- service ---------------------------------------------------------------

type fakeCatalog struct{ tools []connectors.Tool }

func (f fakeCatalog) List() []connectors.Tool { return f.tools }
func (f fakeCatalog) IsServerApp(app string) bool {
	return app == "notes"
}

func catalog() fakeCatalog {
	return fakeCatalog{tools: []connectors.Tool{
		ghTool("create_issue", connectors.KindWrite), ghTool("add_comment", connectors.KindWrite), ghTool("list_issues", connectors.KindRead),
		{App: "notes", Name: "create", Kind: connectors.KindWrite},
		{App: GatewayApp, Name: "delete_server", Kind: connectors.KindWrite},
	}}
}

type recorder struct{ events []audit.Event }

func (r *recorder) Record(_ context.Context, ev audit.Event) error {
	r.events = append(r.events, ev)
	return nil
}

func appService(t *testing.T) (*Service, *appStore, *recorder) {
	t.Helper()
	st := &appStore{}
	st.snap.Roles = []StoredRole{{Role: Role{Name: "github-writer", Rules: []ToolRule{{App: "github", Tool: Wildcard, Outcome: OutcomeAllow}}}}}
	st.snap.Assignments = []Assignment{{UserID: "writer", Role: "github-writer"}}
	rec := &recorder{}
	svc, err := New(st, Options{Audit: rec, Tools: catalog()})
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, rec
}

func TestServiceAppApprovalModes(t *testing.T) {
	ctx := context.Background()
	svc, st, rec := appService(t)
	modes, err := svc.AppApprovalModes(ctx, "github")
	if err != nil {
		t.Fatal(err)
	}
	if len(modes) != 2 || modes[0].Tool != "add_comment" || modes[0].Mode != snapshot.ApprovalAuto || modes[1].Tool != "create_issue" {
		t.Fatalf("modes = %+v, want the two writes in auto, by name", modes)
	}
	before, _ := svc.Current(ctx)
	if d, _ := svc.Decide(ctx, Input{UserID: "writer", Tool: ghTool("create_issue", connectors.KindWrite)}); d.Outcome != OutcomeAllow {
		t.Fatalf("before = %s, want allow", d.Outcome)
	}
	ch, err := svc.SetAppApprovalModes(ctx, "admin-1", "github", map[string]snapshot.Approval{"create_issue": snapshot.ApprovalAsk})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Changed != 1 || ch.Ask != 1 || ch.Auto != 1 {
		t.Errorf("change = %+v, want changed 1, ask 1, auto 1", ch)
	}
	if d, _ := svc.Decide(ctx, Input{UserID: "writer", Tool: ghTool("create_issue", connectors.KindWrite)}); d.Outcome != OutcomeConfirm {
		t.Errorf("after ask = %s, want confirm (recompiled at once)", d.Outcome)
	}
	after, _ := svc.Current(ctx)
	if after.Version == before.Version {
		t.Error("the change did not produce a new policy version")
	}
	if len(st.saved) == 0 || st.saved[len(st.saved)-1].CreatedBy != "admin-1" {
		t.Errorf("new version not recorded under the admin: %+v", st.saved)
	}
	if len(rec.events) != 1 || rec.events[0].ResourceIdentity["action"] != AppApprovalModesChangedEvent ||
		rec.events[0].ResourceIdentity["app"] != "github" || rec.events[0].ResourceIdentity["changed"] != "1" || rec.events[0].UserID != "admin-1" {
		t.Errorf("audit = %+v", rec.events)
	}
	// Back to auto; a no-op change is still fine.
	if ch, err = svc.SetAppApprovalModes(ctx, "admin-1", "github", map[string]snapshot.Approval{"create_issue": snapshot.ApprovalAuto, "add_comment": snapshot.ApprovalAuto}); err != nil || ch.Changed != 1 || ch.Ask != 0 {
		t.Errorf("back to auto: %+v, %v", ch, err)
	}
	if got := st.snap.Apps; len(got) != 0 {
		t.Errorf("stored asks after all auto = %+v, want none", got)
	}
}

func TestServiceAppApprovalModesRefusals(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := appService(t)
	for _, tc := range []struct {
		app   string
		modes map[string]snapshot.Approval
		want  error
	}{
		{"github", map[string]snapshot.Approval{"list_issues": snapshot.ApprovalAsk}, ErrApprovalTool},
		{"github", map[string]snapshot.Approval{"nope": snapshot.ApprovalAsk}, ErrApprovalTool},
		{"github", map[string]snapshot.Approval{"create_issue": "maybe"}, ErrApprovalMode},
		{GatewayApp, map[string]snapshot.Approval{"delete_server": snapshot.ApprovalAuto}, ErrApprovalApp},
		{"notes", map[string]snapshot.Approval{"create": snapshot.ApprovalAsk}, ErrApprovalApp},
		{"unknown", map[string]snapshot.Approval{"x": snapshot.ApprovalAsk}, ErrApprovalApp},
	} {
		if _, err := svc.SetAppApprovalModes(ctx, "admin-1", tc.app, tc.modes); !errors.Is(err, tc.want) {
			t.Errorf("%s %v: err = %v, want %v", tc.app, tc.modes, err, tc.want)
		}
	}
	if len(st.snap.Apps) != 0 {
		t.Errorf("a refused change was stored: %+v", st.snap.Apps)
	}
	for _, app := range []string{GatewayApp, "notes", "unknown"} {
		if _, err := svc.AppApprovalModes(ctx, app); !errors.Is(err, ErrApprovalApp) {
			t.Errorf("AppApprovalModes(%s) err = %v, want ErrApprovalApp", app, err)
		}
	}
}

// appStore is an in-memory Store with app approvals.
type appStore struct {
	ownerStore
	snap  Snapshot
	saved []Version
}

func (s *appStore) Load(context.Context) (Snapshot, error) { return s.snap, nil }

func (s *appStore) SetAppAsk(_ context.Context, _ string, app string, ask []string) error {
	var out []AppApproval
	for _, a := range s.snap.Apps {
		if a.App != app {
			out = append(out, a)
		}
	}
	if len(ask) > 0 {
		out = append(out, AppApproval{App: app, Ask: ask})
	}
	s.snap.Apps = out
	return nil
}

func (s *appStore) SaveVersion(_ context.Context, v Version) (Version, error) {
	v.ID = "v" + v.Hash[:8]
	s.saved = append(s.saved, v)
	return v, nil
}
