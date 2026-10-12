//go:build security

package security

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// TestSecurityFedApprovalModes (task auto-approve): approval modes only
// lift the confirmation the server layer adds. A write in "ask" mode
// still asks; "auto" never widens access: a read-only token, a role
// deny and a stranger stay refused; a member without a grant still sees
// nothing; and only the owner of a private server (or an admin) can
// change the modes: the owner of a published server is refused by the
// page and by row-level security underneath.
func TestSecurityFedApprovalModes(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	up := newUpstream(t, notesServer)
	s := w.addServer(w.alice, "modenotes", up.URL(), nil)
	w.review(w.alice, s, "search", "create_note", "purge")
	owner := snapshot.Actor{UserID: w.alice.id}
	cur, err := w.fed.Snapshots.Current(ctx, owner, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	index := map[string]int{}
	for i, tl := range cur.Snapshot.Tools {
		index[tl.Name] = i
	}
	version := strconv.Itoa(cur.Version)

	// Ask (the default) still confirms.
	alice := w.client(w.alice)
	_ = approvalRequired(t, firstErr(w.call(alice, "modenotes.create_note", map[string]any{"title": "a"})))

	// The owner sets create_note to auto; a forged mode for the read tool
	// is ignored.
	code, _, body := w.post(w.alice, "/servers/"+s.ID+"/approval", url.Values{"version": {version},
		"mode_" + strconv.Itoa(index["create_note"]): {"auto"}, "mode_" + strconv.Itoa(index["search"]): {"ask"}})
	if code != http.StatusSeeOther {
		t.Fatalf("owner mode edit = %d:\n%s", code, body)
	}
	alice = w.client(w.alice)
	if res, err := w.call(alice, "modenotes.create_note", map[string]any{"title": "b"}); err != nil || res.IsError {
		t.Errorf("auto write: %v %+v", err, res)
	}
	_ = approvalRequired(t, firstErr(w.call(alice, "modenotes.purge", map[string]any{"title": "c"})))
	if res, err := w.call(alice, "modenotes.search", map[string]any{"q": "x"}); err != nil || res.IsError {
		t.Errorf("read after forged mode: %v %+v", err, res)
	}
	if got := w.queryString(`SELECT count(*)::text FROM ledger_operations WHERE user_id = $1 AND tool = 'modenotes.create_note' AND state = 'succeeded'`, w.alice.id); got != "1" {
		t.Errorf("auto write ledger rows = %s, want 1", got)
	}

	// Auto does not widen a read-only token.
	ro := w.token(w.alice, tokens.CreateRequest{Name: "ro-modes", ReadOnly: true})
	if got := w.outcome(ro, "modenotes.create_note", map[string]any{"title": "d"}); got != "unknown" {
		t.Errorf("read-only token on an auto write = %s, want unknown", got)
	}

	// Published to the restricted role without a grant: bob sees nothing.
	w.publish(s, nil, roleRestricted)
	if names := toolNames(t, w.client(w.bob)); contains(names, "modenotes.create_note") {
		t.Errorf("auto write visible to a role without a grant: %v", names)
	}
	// The owner of a published server cannot change the modes, neither
	// through the page nor through the service (row-level security).
	if code, _, _ := w.post(w.alice, "/servers/"+s.ID+"/approval", url.Values{"version": {version}, "all": {"auto"}}); code != http.StatusForbidden {
		t.Errorf("owner edit of a published server = %d, want 403", code)
	}
	if _, _, err := w.fed.Snapshots.SetApprovalModes(ctx, owner, s.ID, map[string]snapshot.Approval{"purge": snapshot.ApprovalAuto}); !errors.Is(err, snapshot.ErrReviewNotAllowed) {
		t.Errorf("service edit by the owner of a published server = %v, want ErrReviewNotAllowed", err)
	}
	// A user outside the role (the admin, acting as a plain user) does not even see it.
	if _, _, err := w.fed.Snapshots.SetApprovalModes(ctx, snapshot.Actor{UserID: w.admin.id}, s.ID, map[string]snapshot.Approval{"purge": snapshot.ApprovalAuto}); err == nil {
		t.Error("a stranger changed the modes")
	}

	// A role deny on the owner's role still wins over auto.
	w.setMemberRules([]policy.ToolRule{{App: "modenotes", Tool: "create_note", Outcome: policy.OutcomeDeny}})
	if got := w.outcome(w.token(w.alice, tokens.CreateRequest{Name: "after-deny"}), "modenotes.create_note", map[string]any{"title": "e"}); got != "unknown" {
		t.Errorf("role deny + auto = %s, want unknown (hidden)", got)
	}
}
