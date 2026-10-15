//go:build integration

package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

type approvalSession struct{ tools []*mcp.Tool }

func (s approvalSession) Capabilities() *mcp.ServerCapabilities {
	return &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}}
}
func (s approvalSession) ListTools(context.Context) ([]*mcp.Tool, error) { return s.tools, nil }
func (approvalSession) ListResources(context.Context) ([]*mcp.Resource, error) {
	return nil, errors.New("no")
}
func (approvalSession) ListResourceTemplates(context.Context) ([]*mcp.ResourceTemplate, error) {
	return nil, errors.New("no")
}
func (approvalSession) ListPrompts(context.Context) ([]*mcp.Prompt, error) {
	return nil, errors.New("no")
}

// The production store reads the approval modes of every active server's
// approved snapshot, under the registry's tool names (upstream
// "saveNote" is registered as "save_note"), and the compiled policy
// lets the owner run an auto write without a confirmation.
func TestIntegrationServerApprovalsLoaded(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	var owner string
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		u := &store.User{DisplayName: "Owner", Status: store.UserActive}
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		owner = u.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := &store.MCPServer{Name: "notes", URL: "https://notes.example.com/mcp", OwnerUserID: owner,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone}
	if err := st.WithUser(ctx, owner, func(tx store.Tx) error { return store.CreateMCPServer(ctx, tx, srv) }); err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewService(st)
	a := snapshot.Actor{UserID: owner}
	obj := json.RawMessage(`{"type":"object"}`)
	if _, err := snaps.Create(ctx, a, srv.ID, approvalSession{tools: []*mcp.Tool{
		{Name: "saveNote", InputSchema: obj}, {Name: "purge", InputSchema: obj},
		{Name: "search", InputSchema: obj, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
	}}); err != nil {
		t.Fatal(err)
	}
	on, auto := true, snapshot.ApprovalAuto
	if _, err := snaps.Approve(ctx, a, srv.ID, 1, snapshot.ReviewDecisions{EnableReads: true, Tools: map[string]snapshot.Decision{
		"saveNote": {Enabled: &on, Approval: &auto}, "purge": {Enabled: &on},
	}}); err != nil {
		t.Fatal(err)
	}

	snap, err := policy.NewPostgresStore(st).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(snap.Servers, func(s policy.ServerApproval) bool { return s.App == "notes" })
	if i < 0 || !slices.Equal(snap.Servers[i].AutoRun, []string{"save_note"}) {
		t.Fatalf("Servers = %+v, want notes: [save_note]", snap.Servers)
	}

	svc, err := policy.New(policy.NewPostgresStore(st), policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	save := connectors.Tool{App: "notes", Name: "save_note", Kind: connectors.KindWrite}
	purge := connectors.Tool{App: "notes", Name: "purge", Kind: connectors.KindWrite}
	if d, err := svc.Decide(ctx, policy.Input{UserID: owner, Tool: save}); err != nil || d.Outcome != policy.OutcomeAllow {
		t.Errorf("owner auto write = %v, %v; want allow", d.Outcome, err)
	}
	if d, err := svc.Decide(ctx, policy.Input{UserID: owner, Tool: purge}); err != nil || d.Outcome != policy.OutcomeConfirm {
		t.Errorf("owner ask write = %v, %v; want confirm", d.Outcome, err)
	}
}

type integrationCatalog []connectors.Tool

func (c integrationCatalog) List() []connectors.Tool { return c }
func (integrationCatalog) IsServerApp(string) bool   { return false }

// Vendor app approval modes round-trip through vendor_tool_approvals: the
// Ask set is stored, loaded into the compiled policy (a role allow now
// confirms) and versioned under the admin; Auto deletes the row; the
// table refuses the gateway app.
func TestIntegrationVendorToolApprovals(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	var admin, member string
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		for _, id := range []*string{&admin, &member} {
			u := &store.User{DisplayName: "U", Status: store.UserActive}
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
			*id = u.ID
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	create := connectors.Tool{App: "github", Name: "create_issue", Kind: connectors.KindWrite}
	svc, err := policy.New(policy.NewPostgresStore(st), policy.Options{Tools: integrationCatalog{create}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SaveRole(ctx, admin, policy.Role{Name: "dev", Rules: []policy.ToolRule{{App: "github", Tool: policy.Wildcard, Outcome: policy.OutcomeAllow}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'dev'`, member)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	svc.Invalidate()
	if d, err := svc.Decide(ctx, policy.Input{UserID: member, Tool: create}); err != nil || d.Outcome != policy.OutcomeAllow {
		t.Fatalf("before = %v, %v; want allow", d.Outcome, err)
	}
	if _, err := svc.SetAppApprovalModes(ctx, admin, "github", map[string]snapshot.Approval{"create_issue": snapshot.ApprovalAsk}); err != nil {
		t.Fatal(err)
	}
	snap, err := policy.NewPostgresStore(st).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gh := appAsk(snap.Apps, "github"); !slices.Equal(gh, []string{"create_issue"}) {
		t.Fatalf("Apps = %+v", snap.Apps)
	}
	d, err := svc.Decide(ctx, policy.Input{UserID: member, Tool: create})
	if err != nil || d.Outcome != policy.OutcomeConfirm {
		t.Fatalf("after ask = %v, %v; want confirm", d.Outcome, err)
	}
	var createdBy *string
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT created_by FROM policy_versions WHERE id = $1`, d.VersionID).Scan(&createdBy)
	}); err != nil || createdBy == nil || *createdBy != admin {
		t.Errorf("version created_by = %v, %v; want the admin", createdBy, err)
	}
	if _, err := svc.SetAppApprovalModes(ctx, admin, "github", map[string]snapshot.Approval{"create_issue": snapshot.ApprovalAuto}); err != nil {
		t.Fatal(err)
	}
	if snap, _ := policy.NewPostgresStore(st).Load(ctx); appAsk(snap.Apps, "github") != nil {
		t.Errorf("Apps after auto = %+v, want no github entry", snap.Apps)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.ReplaceVendorToolApprovals(ctx, tx, policy.GatewayApp, []string{"delete_server"}, admin)
	}); err == nil {
		t.Error("the table accepted the gateway app")
	}
}

// appAsk returns the Ask tools of app among the loaded layers, nil when
// the app has none (migration 00020 seeds Slack rows, so other apps may
// be present).
func appAsk(apps []policy.AppApproval, app string) []string {
	for _, a := range apps {
		if a.App == app {
			return a.Ask
		}
	}
	return nil
}

// Migration 00020 seeds Ask for every Slack write added with decision
// aud38ptd (channel management, message edits, pins, files, status, DND)
// while post_message, reply_in_thread and add_reaction stay Auto: a role
// allow on slack.* confirms the new writes and still allows the old ones
// and the reads.
func TestIntegrationSlackNewWritesDefaultToAsk(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	// openTestStore truncates users CASCADE, which empties
	// vendor_tool_approvals (updated_by references users): run 00020's
	// Down and Up again to observe exactly what the migration does.
	u, err := url.Parse(os.Getenv("GATEWAY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + policyTestDB
	if err := migrations.DownTo(ctx, u.String(), 19); err != nil {
		t.Fatalf("down to 19: %v", err)
	}
	if snap, err := policy.NewPostgresStore(st).Load(ctx); err != nil || appAsk(snap.Apps, "slack") != nil {
		t.Fatalf("after Down: slack Ask = %v, %v; want none", appAsk(snap.Apps, "slack"), err)
	}
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatalf("up: %v", err)
	}
	snap, err := policy.NewPostgresStore(st).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ask := appAsk(snap.Apps, "slack")
	for _, tool := range []string{"create_channel", "archive_channel", "invite_to_channel", "remove_from_channel", "delete_message",
		"update_message", "schedule_message", "pin_message", "upload_file", "set_status", "set_dnd", "end_dnd"} {
		if !slices.Contains(ask, tool) {
			t.Errorf("slack Ask %v lacks %s", ask, tool)
		}
	}
	for _, tool := range []string{"post_message", "reply_in_thread", "add_reaction"} {
		if slices.Contains(ask, tool) {
			t.Errorf("slack Ask %v contains %s, which stays Auto", ask, tool)
		}
	}

	var member string
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		u := &store.User{DisplayName: "M", Status: store.UserActive}
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		member = u.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	create := connectors.Tool{App: "slack", Name: "create_channel", Kind: connectors.KindWrite}
	post := connectors.Tool{App: "slack", Name: "post_message", Kind: connectors.KindWrite}
	pins := connectors.Tool{App: "slack", Name: "list_pins", Kind: connectors.KindRead}
	svc, err := policy.New(policy.NewPostgresStore(st), policy.Options{Tools: integrationCatalog{create, post, pins}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SaveRole(ctx, member, policy.Role{Name: "slacker", Rules: []policy.ToolRule{{App: "slack", Tool: policy.Wildcard, Outcome: policy.OutcomeAllow}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'slacker'`, member)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	svc.Invalidate()
	for _, tc := range []struct {
		tool connectors.Tool
		want policy.Outcome
	}{{create, policy.OutcomeConfirm}, {post, policy.OutcomeAllow}, {pins, policy.OutcomeAllow}} {
		if d, err := svc.Decide(ctx, policy.Input{UserID: member, Tool: tc.tool}); err != nil || d.Outcome != tc.want {
			t.Errorf("%s = %v, %v; want %v", tc.tool.Name, d.Outcome, err, tc.want)
		}
	}
}
