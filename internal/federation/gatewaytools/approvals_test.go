package gatewaytools

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// vendorCatalog is the registry the policy service validates against.
type vendorCatalog []connectors.Tool

func (c vendorCatalog) List() []connectors.Tool { return c }
func (c vendorCatalog) IsServerApp(app string) bool {
	return app == "notes"
}

type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *fakeAudit) Record(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

// approvalWorld: alice is an admin, bob is not; the policy service knows
// github (two writes, one read) and gmail (google).
func approvalWorld(t *testing.T) (*world, *policy.Service, *fakeAudit) {
	t.Helper()
	w := newWorld(t)
	write := func(app, name string) connectors.Tool {
		return connectors.Tool{App: app, Name: name, Kind: connectors.KindWrite}
	}
	pol, err := policy.New(policytest.NewMemStore(), policy.Options{Tools: vendorCatalog{
		write("github", "create_issue"), write("github", "add_comment"), {App: "github", Name: "list_issues", Kind: connectors.KindRead},
		write("gmail", "send_message"), write("notes", "create"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	rec := &fakeAudit{}
	w.conn.d.Approvals = pol
	w.conn.d.Admin = admins{alice: true}
	w.conn.d.Audit = rec
	w.conn.d.VendorOf = func(app string) string {
		if app == "gmail" {
			return "google"
		}
		return app
	}
	return w, pol, rec
}

func vendorMode(t *testing.T, pol *policy.Service, app, tool string) snapshot.Approval {
	t.Helper()
	modes, err := pol.AppApprovalModes(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range modes {
		if m.Tool == tool {
			return m.Mode
		}
	}
	t.Fatalf("no %s.%s", app, tool)
	return ""
}

func TestToolApprovalToolsRegistered(t *testing.T) {
	w, _, _ := approvalWorld(t)
	get, ok := w.reg.Get(App + "." + ToolGetToolApprovals)
	if !ok || get.Kind != connectors.KindRead {
		t.Fatalf("get_tool_approvals = %+v, %v", get, ok)
	}
	set, ok := w.reg.Get(App + "." + ToolSetToolApproval)
	if !ok || set.Kind != connectors.KindWrite || set.Reconcile.Kind != connectors.ReconcileNone {
		t.Fatalf("set_tool_approval = %+v, %v", set, ok)
	}
	if d := strings.ToLower(set.Description); !strings.Contains(d, "approval") || !strings.Contains(d, "browser") {
		t.Errorf("set_tool_approval description must say the change needs an approval in the browser: %q", set.Description)
	}
	var schema map[string]any
	if err := json.Unmarshal(set.InputSchema, &schema); err != nil || schema["additionalProperties"] != false {
		t.Errorf("schema %s must close additionalProperties", set.InputSchema)
	}
	// Policy: reading allows; changing always confirms, even under a role
	// allow of gateway.*; a read-only token hides the setter.
	roles := []policy.Role{{Name: "admin", Rules: []policy.ToolRule{{App: App, Tool: policy.Wildcard, Outcome: policy.OutcomeAllow}}}}
	c, err := policy.Compile(roles, []policy.Assignment{{UserID: alice, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Decide(policy.Input{UserID: bob, Tool: get}).Outcome; got != policy.OutcomeAllow {
		t.Errorf("get = %s, want allow", got)
	}
	for _, user := range []string{alice, bob} {
		if got := c.Decide(policy.Input{UserID: user, Roles: c.RolesFor(user), Tool: set}).Outcome; got != policy.OutcomeConfirm {
			t.Errorf("%s set = %s, want confirm", user, got)
		}
	}
	ro := policy.Input{UserID: alice, Roles: c.RolesFor(alice), Tool: set, TokenScope: tokens.Scope{ReadOnly: true}}
	if got := c.Decide(ro).Outcome; got != policy.OutcomeHidden {
		t.Errorf("read-only token set = %s, want hidden", got)
	}
}

func TestGetToolApprovalsVendor(t *testing.T) {
	w, pol, _ := approvalWorld(t)
	if _, err := pol.SetAppApprovalModes(t.Context(), alice, "github", map[string]snapshot.Approval{"create_issue": snapshot.ApprovalAsk}); err != nil {
		t.Fatal(err)
	}
	out := w.ok(bob, ToolGetToolApprovals, map[string]any{"app": "github"})
	if out["type"] != "vendor_app" || out["can_change"] != false || out["link"] != base+"/admin/vendor-apps/github" {
		t.Errorf("bob github = %s", jsonString(out))
	}
	tools, _ := out["tools"].([]any)
	if len(tools) != 2 || jsonString(tools[1]) != `{"kind":"write","mode":"ask","name":"github.create_issue"}` {
		t.Errorf("tools = %s", jsonString(tools))
	}
	if c := jsonString(out["counts"]); c != `{"ask":1,"auto":1,"write_tools":2}` {
		t.Errorf("counts = %s", c)
	}
	out = w.ok(alice, ToolGetToolApprovals, map[string]any{"app": "gmail"})
	if out["can_change"] != true || out["link"] != base+"/admin/vendor-apps/google" || out["vendor"] != "google" {
		t.Errorf("alice gmail = %s", jsonString(out))
	}
	if class, _ := w.fail(alice, ToolGetToolApprovals, map[string]any{"app": "nope"}); class != "app_not_found" {
		t.Errorf("unknown app class = %s", class)
	}
	if class, _ := w.fail(alice, ToolGetToolApprovals, map[string]any{"app": App}); class != "args_invalid" {
		t.Errorf("gateway app class = %s", class)
	}
}

func TestSetToolApprovalVendor(t *testing.T) {
	w, pol, _ := approvalWorld(t)
	if class, _ := w.fail(bob, ToolSetToolApproval, map[string]any{"app": "github", "all": "ask"}); class != "not_permitted" {
		t.Errorf("member class = %s, want not_permitted", class)
	}
	if got := vendorMode(t, pol, "github", "create_issue"); got != snapshot.ApprovalAuto {
		t.Fatalf("member changed the mode: %s", got)
	}
	out := w.ok(alice, ToolSetToolApproval, map[string]any{"app": "github", "tools": map[string]any{"create_issue": "ask", "github.add_comment": "auto"}})
	if out["changed"] != float64(1) || out["ask"] != float64(1) || out["auto"] != float64(1) {
		t.Errorf("result = %s", jsonString(out))
	}
	if got := vendorMode(t, pol, "github", "create_issue"); got != snapshot.ApprovalAsk {
		t.Errorf("create_issue = %s, want ask", got)
	}
	w.ok(alice, ToolSetToolApproval, map[string]any{"app": "github", "all": "ask"})
	if got := vendorMode(t, pol, "github", "add_comment"); got != snapshot.ApprovalAsk {
		t.Errorf("after all=ask add_comment = %s", got)
	}
	for _, args := range []map[string]any{
		{"app": "github", "tools": map[string]any{"list_issues": "ask"}},
		{"app": "github", "tools": map[string]any{"nope": "ask"}},
		{"app": "github", "tools": map[string]any{"create_issue": "sometimes"}},
		{"app": "github", "tools": map[string]any{}},
		{"app": "github", "all": "never"},
		{"app": "github", "all": "ask", "tools": map[string]any{"create_issue": "ask"}},
		{"app": "github"},
		{"app": App, "all": "auto"},
		{"app": "github", "all": "ask", "extra": true},
	} {
		if class, _ := w.fail(alice, ToolSetToolApproval, args); class != "args_invalid" {
			t.Errorf("%s: class = %s, want args_invalid", jsonString(args), class)
		}
	}
	if class, _ := w.fail(alice, ToolSetToolApproval, map[string]any{"app": "nope", "all": "ask"}); class != "app_not_found" {
		t.Errorf("unknown app class = %s", class)
	}
	// A tool name that merely looks like a credential is still a tool name.
	if class, _ := w.fail(alice, ToolSetToolApproval, map[string]any{"app": "github", "tools": map[string]any{"rotate_token": "ask"}}); class != "args_invalid" {
		t.Errorf("credential-looking tool name class = %s, want args_invalid (unknown tool)", class)
	}
}

// approvedKinds gives a server an approved snapshot with tool kinds.
func (f *fakeSnapshots) approvedKinds(id string, version int, tools map[string]snapshot.ToolReview) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec := &snapshot.Record{ServerID: id, Version: version, Status: store.MCPSnapshotApproved, Snapshot: &snapshot.Snapshot{}, Review: snapshot.Review{}}
	for name, tr := range tools {
		rec.Snapshot.Tools = append(rec.Snapshot.Tools, snapshot.Tool{Name: name})
		rec.Review[name] = tr
	}
	f.current[id], f.latest[id] = rec, rec
}

func TestToolApprovalsServer(t *testing.T) {
	w, _, rec := approvalWorld(t)
	notes := w.servers.add(store.MCPServer{Name: "notes", OwnerUserID: bob})
	pub := w.servers.add(store.MCPServer{Name: "wiki", OwnerUserID: bob, Audience: store.MCPAudiencePublished})
	w.servers.sharedWith[pub.ID] = []string{alice}
	tools := map[string]snapshot.ToolReview{
		"create": {Enabled: true, Kind: snapshot.KindWrite},
		"search": {Enabled: true, Kind: snapshot.KindRead},
		"purge":  {Enabled: false, Kind: snapshot.KindWrite},
	}
	w.snaps.approvedKinds(notes.ID, 3, tools)
	w.snaps.approvedKinds(pub.ID, 1, tools)

	if class, _ := w.fail(alice, ToolGetToolApprovals, map[string]any{"app": "notes"}); class != "app_not_found" {
		t.Errorf("invisible server class = %s, want app_not_found", class)
	}
	out := w.ok(bob, ToolGetToolApprovals, map[string]any{"app": "notes"})
	if out["type"] != "server" || out["can_change"] != true || out["link"] != base+fedportal.ServerPath(notes.ID) {
		t.Errorf("bob notes = %s", jsonString(out))
	}
	if got := jsonString(out["tools"]); got != `[{"kind":"write","mode":"ask","name":"create"}]` {
		t.Errorf("tools = %s", got)
	}

	out = w.ok(bob, ToolSetToolApproval, map[string]any{"app": notes.ID, "tools": map[string]any{"create": "auto"}})
	if out["changed"] != float64(1) {
		t.Errorf("result = %s", jsonString(out))
	}
	cur, _ := w.snaps.Current(t.Context(), snapshot.Actor{}, notes.ID)
	if cur.Review["create"].Mode() != snapshot.ApprovalAuto {
		t.Errorf("create mode = %s", cur.Review["create"].Mode())
	}
	if len(rec.events) != 1 || rec.events[0].ResourceIdentity["action"] != fedportal.ApprovalModesChangedEvent || rec.events[0].UserID != bob {
		t.Errorf("audit = %+v", rec.events)
	}
	if n := len(w.mgr.changed); n == 0 || w.mgr.changed[n-1] != notes.ID {
		t.Errorf("ServerChanged not called: %v", w.mgr.changed)
	}
	for _, tool := range []string{"search", "purge", "nope"} {
		if class, _ := w.fail(bob, ToolSetToolApproval, map[string]any{"app": "notes", "tools": map[string]any{tool: "auto"}}); class != "args_invalid" {
			t.Errorf("%s: class = %s, want args_invalid", tool, class)
		}
	}
	// Published: only an admin changes the modes.
	if class, _ := w.fail(bob, ToolSetToolApproval, map[string]any{"app": "wiki", "all": "auto"}); class != "not_permitted" {
		t.Errorf("owner of a published server class = %s, want not_permitted", class)
	}
	if out := w.ok(bob, ToolGetToolApprovals, map[string]any{"app": "wiki"}); out["can_change"] != false {
		t.Errorf("published can_change for the owner = %v", out["can_change"])
	}
	w.ok(alice, ToolSetToolApproval, map[string]any{"app": "wiki", "all": "auto"})
	if by := w.snaps.modesBy; len(by) == 0 || !by[len(by)-1].Admin || by[len(by)-1].UserID != alice {
		t.Errorf("published change actor = %+v, want the admin", by)
	}
}
