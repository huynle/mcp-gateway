//go:build integration

package policy_test

import (
	"net/url"
	"os"
	"slices"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// Migration 00025 seeds Ask for the Jira and Confluence writes added to
// close the Rovo MCP gap while jira create_issue / add_comment /
// transition_issue and confluence create_page stay Auto: a role allow on
// jira.* confirms the new writes and still allows the old ones and the
// reads.
func TestIntegrationAtlassianNewWritesDefaultToAsk(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	// openTestStore empties vendor_tool_approvals (see the Slack test):
	// run 00025's Down and Up again to observe what the migration does.
	u, err := url.Parse(os.Getenv("GATEWAY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + policyTestDB
	if err := migrations.DownTo(ctx, u.String(), 24); err != nil {
		t.Fatalf("down to 24: %v", err)
	}
	if n := vendorAskRows(t, st, "jira", "confluence"); n != 0 {
		t.Fatalf("after Down: %d jira/confluence Ask rows; want none", n)
	}
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatalf("up: %v", err)
	}
	snap, err := policy.NewPostgresStore(st).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	jira, conf := appAsk(snap.Apps, "jira"), appAsk(snap.Apps, "confluence")
	for _, tool := range []string{"update_issue", "assign_issue", "edit_comment", "add_worklog", "link_issues", "add_watcher",
		"remove_watcher", "add_issues_to_sprint", "add_remote_link"} {
		if !slices.Contains(jira, tool) {
			t.Errorf("jira Ask %v lacks %s", jira, tool)
		}
	}
	for _, tool := range []string{"update_page", "add_page_comment", "add_page_labels"} {
		if !slices.Contains(conf, tool) {
			t.Errorf("confluence Ask %v lacks %s", conf, tool)
		}
	}
	for _, tool := range []string{"create_issue", "add_comment", "transition_issue"} {
		if slices.Contains(jira, tool) {
			t.Errorf("jira Ask %v contains %s, which stays Auto", jira, tool)
		}
	}
	if slices.Contains(conf, "create_page") {
		t.Errorf("confluence Ask %v contains create_page, which stays Auto", conf)
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
	update := connectors.Tool{App: "jira", Name: "update_issue", Kind: connectors.KindWrite}
	create := connectors.Tool{App: "jira", Name: "create_issue", Kind: connectors.KindWrite}
	read := connectors.Tool{App: "jira", Name: "list_remote_links", Kind: connectors.KindRead}
	svc, err := policy.New(policy.NewPostgresStore(st), policy.Options{Tools: integrationCatalog{update, create, read}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SaveRole(ctx, member, policy.Role{Name: "jira-user", Rules: []policy.ToolRule{{App: "jira", Tool: policy.Wildcard, Outcome: policy.OutcomeAllow}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'jira-user'`, member)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	svc.Invalidate()
	for _, tc := range []struct {
		tool connectors.Tool
		want policy.Outcome
	}{{update, policy.OutcomeConfirm}, {create, policy.OutcomeAllow}, {read, policy.OutcomeAllow}} {
		if d, err := svc.Decide(ctx, policy.Input{UserID: member, Tool: tc.tool}); err != nil || d.Outcome != tc.want {
			t.Errorf("%s = %v, %v; want %v", tc.tool.Name, d.Outcome, err, tc.want)
		}
	}
}
