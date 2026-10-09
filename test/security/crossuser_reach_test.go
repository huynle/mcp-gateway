//go:build integration || e2e || security

package security

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// TestSecurityCrossUserReach: nothing of bob's is reachable with alice's
// token or session through any connector path or portal page, and every
// refusal is byte-identical to the one for a nonexistent id, so neither
// existence nor ownership leaks.
func TestSecurityCrossUserReach(t *testing.T) {
	w := newWorld(t, options{})
	aliceToken := w.token(w.alice, tokens.CreateRequest{})
	alice, bob := w.clientWith(aliceToken), w.client(w.bob)
	random := "9b2d1c1e-0d5b-4f8a-9a1c-5b9f3d2e1a00"

	// bob's artefacts to point at: a pending approval, a succeeded
	// operation with a stored result, a token, a harness family.
	_, err := w.call(bob, "fake.create_item", map[string]any{"id": "b-1", "name": "bob item", "account": w.bobAcc})
	bobApproval := approvalRequired(t, err)
	if res, err := w.call(bob, "fake.post_note", map[string]any{"text": "bob's note 7f3a", "account": w.bobAcc}); err != nil || res.IsError {
		t.Fatalf("bob post_note: err=%v res=%+v", err, res)
	}
	w.forbid("bob's note 7f3a", "bob's note text")
	bobOp := w.opFor(w.bob, "fake.post_note", store.LedgerSucceeded)
	if bobOp == nil {
		t.Fatal("no bob op")
	}
	bobTokenID := w.queryString(`SELECT id::text FROM tokens WHERE user_id = $1 LIMIT 1`, w.bob.id)
	bobFamily := w.harnessFamily(w.bob)

	// 1. Naming bob's connection id as account, for every connector:
	// the same answer as a random id.
	for _, c := range []struct{ tool, bobAccount string }{
		{"fake.list_items", w.bobAcc}, {"fake.list_items", w.bobPersonal},
		{"github.get_me", w.bobGH}, {"github.search_issues", w.bobGH},
		{"slack.list_channels", w.bobSlack},
	} {
		_, _, gotB := w.rawCall(aliceToken, c.tool, map[string]any{"account": c.bobAccount, "q": "x"})
		_, _, gotR := w.rawCall(aliceToken, c.tool, map[string]any{"account": random, "q": "x"})
		a, b := strings.ReplaceAll(stripID(gotB), c.bobAccount, "X"), strings.ReplaceAll(stripID(gotR), random, "X")
		if a != b || !strings.Contains(a, "unknown account") {
			t.Errorf("%s with bob's account vs random:\n%s\n%s", c.tool, gotB, gotR)
		}
	}
	if w.github.count() != 0 || w.slack.count() != 0 {
		t.Errorf("a vendor was called with another user's account: github=%d slack=%d", w.github.count(), w.slack.count())
	}
	// Alice (member) using her own GitHub account works, so the refusals
	// above are about ownership, not a broken connector.
	if res, err := w.call(alice, "github.get_me", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("alice get_me: err=%v res=%+v", err, res)
	}

	// 2. bob's approval id on alice's retry: the same answer as an
	// unknown id, and bob's approval stays pending.
	_, _, gotB := w.rawCall(aliceToken, "fake.create_item", map[string]any{"id": "x", "name": "x", "approval_id": bobApproval})
	_, _, gotR := w.rawCall(aliceToken, "fake.create_item", map[string]any{"id": "x", "name": "x", "approval_id": random})
	if a, b := stripID(gotB), stripID(gotR); a != b || !strings.Contains(a, "does not match") {
		t.Errorf("bob's approval vs random:\n%s\n%s", gotB, gotR)
	}
	if a, err := w.approval.Get(t.Context(), w.bob.id, bobApproval); err != nil || a.Status != approvals.StatusPending {
		t.Errorf("bob's approval touched: %v %v", a, err)
	}
	if items := w.fake.State().Items(w.bobAcc); len(items) != 0 {
		t.Errorf("bob's account written through alice: %+v", items)
	}

	// 3. Replay of bob's stored result: alice posting the very same note
	// text is not served bob's operation (idempotency keys are scoped
	// by user and account); she gets her own, new operation.
	res, err := w.call(alice, "fake.post_note", map[string]any{"text": "bob's note 7f3a"})
	if err != nil || res.IsError {
		t.Fatalf("alice post_note: err=%v res=%+v", err, res)
	}
	if strings.Contains(text(t, res), "replayed") || strings.Contains(text(t, res), bobOp.ID) {
		t.Errorf("alice was served bob's stored result: %s", text(t, res))
	}
	aliceOp := w.opFor(w.alice, "fake.post_note", store.LedgerSucceeded)
	if aliceOp == nil || aliceOp.ID == bobOp.ID {
		t.Errorf("alice op = %+v", aliceOp)
	}

	// 4. Personal account where the role forbids it: bob (restricted)
	// is denied on his personal account; the company one runs.
	_, err = w.call(bob, "fake.post_note", map[string]any{"text": "from home", "account": w.bobPersonal})
	_ = rpcError(t, err, mcp.CodeDenied)
	if notes := w.fake.State().Notes(w.bobPersonal); len(notes) != 0 {
		t.Errorf("personal notes = %+v", notes)
	}

	// 5. list_accounts never shows another user's accounts, for every app.
	for _, app := range []string{"fake", "github", "slack"} {
		res, err := w.call(alice, app+".list_accounts", map[string]any{})
		if err != nil || res.IsError {
			t.Fatalf("%s.list_accounts: err=%v res=%+v", app, err, res)
		}
		body := text(t, res)
		for _, id := range []string{w.bobAcc, w.bobPersonal, w.bobGH, w.bobSlack, "bob-gh", "bob@acme", "Bob at"} {
			if strings.Contains(body, id) {
				t.Errorf("%s.list_accounts for alice shows bob's %s: %s", app, id, body)
			}
		}
		var out struct {
			Accounts []map[string]any `json:"accounts"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Accounts) != 1 {
			t.Errorf("%s.list_accounts for alice = %s", app, body)
		}
		for _, a := range out.Accounts {
			for k := range a {
				if strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "scope") {
					t.Errorf("list_accounts exposes %q", k)
				}
			}
		}
	}

	// 6. Portal pages with bob's ids under alice's session: 404 with the
	// same body as a random id (no existence leak), and bob's rows stay.
	type probe struct{ path, bobID string }
	for _, pr := range []probe{
		{"/approvals/%s/approve", bobApproval}, {"/approvals/%s/deny", bobApproval},
		{"/connections/%s/disconnect", w.bobAcc}, {"/connections/%s/disconnect", w.bobGH},
		{"/harnesses/%s/revoke", bobFamily}, {"/tokens/%s/revoke", bobTokenID},
	} {
		codeB, _, bodyB := w.post(w.alice, strings.Replace(pr.path, "%s", pr.bobID, 1), nil)
		codeR, _, bodyR := w.post(w.alice, strings.Replace(pr.path, "%s", random, 1), nil)
		codeN, _, bodyN := w.post(w.alice, strings.Replace(pr.path, "%s", "not-a-uuid", 1), nil)
		if codeB != 404 || codeR != 404 || codeN != 404 || bodyB != bodyR || bodyB != bodyN {
			t.Errorf("alice POST %s: bob's %d %q, random %d %q, malformed %d %q", pr.path, codeB, bodyB, codeR, bodyR, codeN, bodyN)
		}
	}
	if a, _ := w.approval.Get(t.Context(), w.bob.id, bobApproval); a == nil || a.Status != approvals.StatusPending {
		t.Errorf("bob's approval changed through alice's session")
	}
	if st := w.queryString(`SELECT status FROM connections WHERE id = $1`, w.bobGH); st != store.ConnectionActive {
		t.Errorf("bob's github connection = %s", st)
	}
	if revoked := w.queryString(`SELECT (revoked_at IS NOT NULL)::text FROM tokens WHERE id = $1`, bobTokenID); revoked != "false" {
		t.Errorf("bob's token revoked through alice's session")
	}
	if revoked := w.queryString(`SELECT (revoked_at IS NOT NULL)::text FROM oauth_refresh_tokens WHERE family_id = $1`, bobFamily); revoked != "false" {
		t.Errorf("bob's harness revoked through alice's session")
	}
	// Listing pages never show bob's rows or identifiers.
	for _, path := range []string{"/approvals", "/approvals/history", "/operations", "/tokens", "/connections", "/harnesses", "/activity"} {
		code, _, body := w.get(w.alice, path)
		if code != 200 {
			t.Errorf("alice GET %s = %d", path, code)
		}
		for what, id := range map[string]string{"approval": bobApproval, "operation": bobOp.ID[:8], "token": bobTokenID, "harness": bobFamily, "fake account": w.bobAcc, "github account": w.bobGH, "slack account": w.bobSlack, "github login": "bob-gh", "slack name": "bob@acme", "fake name": "Bob at", "item id": "b-1"} {
			if strings.Contains(body, id) {
				t.Errorf("alice GET %s shows bob's %s %q", path, what, id)
			}
		}
	}
	// The admin audit view sees both; alice's /activity cannot be widened.
	if code, _, body := w.get(w.alice, "/activity?user_id="+w.bob.id); code != 200 || strings.Contains(body, "b-1") {
		t.Errorf("alice /activity?user_id=bob = %d widened=%v", code, strings.Contains(body, "b-1"))
	}
	if code, _, _ := w.get(w.alice, "/admin/audit"); code != 404 {
		t.Errorf("alice /admin/audit = %d, want 404", code)
	}
	// Bob's own view still works (the refusals are not a broken portal).
	if code, _, body := w.get(w.bob, "/operations"); code != 200 || !strings.Contains(body, bobOp.ID[:8]) {
		t.Errorf("bob GET /operations = %d, missing his own", code)
	}
	_ = fake.App
}

// harnessFamily inserts an OAuth client and a refresh-token family for
// u, as a completed MCP OAuth sign-in leaves them, and returns the
// family id.
func (w *world) harnessFamily(u user) string {
	w.t.Helper()
	client := w.queryString(`INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES ('gwc_sec_' || gen_random_uuid()::text, 'Harness of ' || $1, '{https://app.example.com/cb}') RETURNING id::text`, u.id)
	return w.queryString(`WITH ids AS (SELECT gen_random_uuid() AS id)
		INSERT INTO oauth_refresh_tokens (id, family_id, user_id, client_id, token_hash, expires_at)
		SELECT id, id, $1, $2, decode(md5(id::text), 'hex'), now() + interval '30 days' FROM ids RETURNING id::text`, u.id, client)
}
