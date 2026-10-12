//go:build integration || e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// approvalsFor counts the user's approval rows.
func (w *world) approvalsFor(u user) int {
	w.t.Helper()
	var n int
	err := w.st.WithJobs(w.t.Context(), func(tx store.Tx) error {
		return tx.QueryRow(w.t.Context(), `SELECT count(*) FROM approvals WHERE user_id = $1`, u.id).Scan(&n)
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return n
}

// TestE2EPluginsApprovalModes (task auto-approve): a write tool set to
// "run without asking" runs in one call through the MCP client, still
// ledgered and audited; "ask" still asks. On a published server the
// admin's mode is the default for granted roles: role allow + auto runs,
// role allow + ask asks, role confirm always asks.
func TestE2EPluginsApprovalModes(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	id := w.addServer(w.alice, url.Values{"name": {"jot"}, "url_mode": {"https"}, "url": {newJotUpstream(t)},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	w.approve(w.alice, id, w.refresh(w.alice, id), "search", "save")

	// Default: the write asks.
	alice := w.client(w.alice)
	_, err := w.call(alice, "jot.save", map[string]any{"text": "first"})
	_ = approvalRequired(t, err)
	if n := w.approvalsFor(w.alice); n != 1 {
		t.Fatalf("approvals after an ask write = %d, want 1", n)
	}

	// The server page shows the modes; one click sets everything to auto.
	p := w.page(w.alice, "/servers/"+id)
	if p.status != http.StatusOK || !strings.Contains(p.body, "1 ask") || !strings.Contains(p.body, `name="all" value="auto"`) {
		t.Fatalf("server page without approval modes (%d):\n%s", p.status, snippet(p.body))
	}
	version := versionRE.FindStringSubmatch(p.body)
	if version == nil {
		t.Fatalf("server page without the modes version:\n%s", snippet(p.body))
	}
	mustRedirect(t, "all auto", w.submit(w.alice, "/servers/"+id+"/approval", url.Values{"version": {version[1]}, "all": {"auto"}}),
		"/servers/"+id+"?modes=1")
	if p := w.page(w.alice, "/servers/"+id); !strings.Contains(p.body, "0 ask") {
		t.Errorf("server page after all auto:\n%s", snippet(p.body))
	}

	// The write now runs in one call, without an approval.
	alice = w.client(w.alice)
	if got := w.toolText(alice, "jot.save", map[string]any{"text": "x"}); got != "saved x" {
		t.Errorf("auto write = %q, want saved x", got)
	}
	if n := w.approvalsFor(w.alice); n != 1 {
		t.Errorf("approvals after an auto write = %d, want still 1", n)
	}
	if op := w.opFor(w.alice, "jot.save", store.LedgerSucceeded); op == nil {
		t.Error("auto write not ledgered as succeeded")
	}
	if !w.hasAudit(w.alice, "jot.save", "succeeded", "") {
		t.Error("auto write not audited")
	}
	changed := false
	for _, ev := range w.events(w.alice) {
		if ev.ResourceIdentity["action"] == "mcp_server.approval_modes_changed" && ev.ResourceIdentity["server_id"] == id {
			changed = true
		}
	}
	if !changed {
		t.Error("mode change not audited")
	}

	// Published: the owner can no longer change the modes; the admin can.
	mustRedirect(t, "publish", w.submit(w.admin, "/admin/servers/"+id+"/publish", url.Values{"roles": {w.roleID(roleRestricted)}}),
		"/admin/servers/"+id+"?done=")
	if p := w.submit(w.alice, "/servers/"+id+"/approval", url.Values{"version": {version[1]}, "all": {"ask"}}); p.status != http.StatusForbidden {
		t.Errorf("owner mode edit of a published server = %d, want 403", p.status)
	}
	w.grant(roleRestricted, policy.ToolRule{App: "jot", Tool: policy.Wildcard, Outcome: policy.OutcomeAllow})
	bob := w.client(w.bob)
	if got := w.toolText(bob, "jot.save", map[string]any{"text": "b"}); got != "saved b" {
		t.Errorf("role allow + auto = %q, want saved b", got)
	}

	mustRedirect(t, "admin ask", w.submit(w.admin, "/admin/servers/"+id+"/approval", url.Values{"version": {version[1]}, "all": {"ask"}}),
		"/admin/servers/"+id+"?done=modes")
	_, err = w.call(w.client(w.bob), "jot.save", map[string]any{"text": "b2"})
	_ = approvalRequired(t, err)
	_, err = w.call(w.client(w.alice), "jot.save", map[string]any{"text": "a2"})
	_ = approvalRequired(t, err)

	// Back to auto, but the role confirms: still asks.
	mustRedirect(t, "admin auto", w.submit(w.admin, "/admin/servers/"+id+"/approval", url.Values{"version": {version[1]}, "all": {"auto"}}),
		"/admin/servers/"+id+"?done=modes")
	w.grant(roleRestricted, policy.ToolRule{App: "jot", Tool: "save", Outcome: policy.OutcomeConfirm})
	_, err = w.call(w.client(w.bob), "jot.save", map[string]any{"text": "b3"})
	_ = approvalRequired(t, err)
	if got := w.toolText(w.client(w.alice), "jot.save", map[string]any{"text": "a3"}); got != "saved a3" {
		t.Errorf("owner auto write after publish = %q", got)
	}
}
