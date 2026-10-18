//go:build integration || e2e

package e2e

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// TestE2EReadsVisibilityAndDeny: allowed reads run; a hidden tool is absent
// from tools/list and a call to it is byte-identical to a call to a tool
// that does not exist; a conditional deny refuses by resource identity;
// several accounts must be named.
func TestE2EReadsVisibilityAndDeny(t *testing.T) {
	w := newWorld(t, options{})
	alice, bob := w.client(w.alice), w.client(w.bob)

	// Visibility: alice (member) sees every fake tool, bob (restricted)
	// everything but get_item.
	aliceTools, bobTools := toolNames(t, alice), toolNames(t, bob)
	for _, name := range []string{"fake.list_accounts", "fake.list_items", "fake.get_item", "fake.create_item", "fake.post_note", "fake.flaky_write"} {
		if !contains(aliceTools, name) {
			t.Errorf("alice does not see %s: %v", name, aliceTools)
		}
		if name != "fake.get_item" && !contains(bobTools, name) {
			t.Errorf("bob does not see %s: %v", name, bobTools)
		}
	}
	if contains(bobTools, "fake.get_item") {
		t.Errorf("bob sees the hidden get_item: %v", bobTools)
	}

	// Allowed reads: list_accounts, list_items, get_item (one account:
	// auto-resolved).
	w.fake.SeedItems(w.aliceAcc, fake.Item{ID: "it-1", Name: "first"}, fake.Item{ID: "it-2", Name: "second"})
	res, err := w.call(alice, "fake.list_accounts", nil)
	if err != nil || res.IsError || !strings.Contains(text(t, res), w.aliceAcc) || strings.Contains(text(t, res), w.bobAcc) {
		t.Fatalf("list_accounts: err=%v text=%s", err, text(t, res))
	}
	res, err = w.call(alice, "fake.list_items", w.args("page_size", 10))
	if err != nil || res.IsError || !strings.Contains(text(t, res), `"it-1"`) {
		t.Fatalf("list_items: err=%v res=%+v", err, res)
	}
	res, err = w.call(alice, "fake.get_item", w.args("id", "it-2"))
	if err != nil || res.IsError || !strings.Contains(text(t, res), "second") {
		t.Fatalf("get_item: err=%v res=%+v", err, res)
	}

	// Deny by condition: get_item of an id starting with "secret-".
	_, err = w.call(alice, "fake.get_item", w.args("id", "secret-1"))
	_ = rpcError(t, err, mcp.CodeDenied)

	// Hidden == not found, byte for byte on the wire (bob's token).
	bobToken := w.token(w.bob, tokens.CreateRequest{})
	hidden := w.rawCall(bobToken, "fake.get_item", map[string]any{"id": "it-1"})
	missing := w.rawCall(bobToken, "fake.get_item_v2", map[string]any{"id": "it-1"})
	if got, want := strings.ReplaceAll(stripID(hidden), "fake.get_item_v2", "fake.get_item"), strings.ReplaceAll(stripID(missing), "fake.get_item_v2", "fake.get_item"); got != want || !strings.Contains(got, `"code":-32602`) {
		t.Errorf("hidden tool answer differs from a nonexistent tool's:\n%s\n%s", hidden, missing)
	}

	// Several accounts: bob must name one, and only his are offered.
	_, err = w.call(bob, "fake.list_items", nil)
	je := rpcError(t, err, mcp.CodeInvalidParams)
	if !strings.Contains(je.Message, "account required") || !strings.Contains(je.Message, w.bobAcc) || !strings.Contains(je.Message, w.bobPersonal) || strings.Contains(je.Message, w.aliceAcc) {
		t.Errorf("account required message = %q", je.Message)
	}
	res, err = w.call(bob, "fake.list_items", map[string]any{"account": w.bobAcc})
	if err != nil || res.IsError {
		t.Fatalf("bob list_items on his company account: err=%v res=%+v", err, res)
	}

	// Audit: one tool_call row per call with the resource identity, the
	// decision and the outcome; hidden and denied are on record too.
	var denied, hidden2, allowedGet int
	for _, ev := range w.events(w.alice) {
		if ev.EventType != audit.EventTypeToolCall {
			continue
		}
		switch {
		case ev.Tool == "fake.get_item" && ev.ResourceIdentity["id"] == "secret-1" && ev.Decision == "deny" && ev.Outcome == "denied":
			denied++
		case ev.Tool == "fake.get_item" && ev.ResourceIdentity["id"] == "it-2" && ev.Decision == "allow" && ev.Outcome == "succeeded" && ev.AccountID == w.aliceAcc && ev.AccountLabel == "company":
			allowedGet++
		}
	}
	// A hidden tool is audited exactly like an unknown one: the resolve
	// stage cannot (and must not) tell them apart.
	for _, ev := range w.events(w.bob) {
		if ev.EventType == audit.EventTypeToolCall && ev.Tool == "fake.get_item" && ev.Decision == "deny" && ev.Outcome == "denied" && ev.ErrorClass == "tool_not_found" {
			hidden2++
		}
	}
	if denied != 1 || allowedGet != 1 || hidden2 != 1 {
		t.Errorf("audit rows: denied=%d allowed get=%d hidden=%d", denied, allowedGet, hidden2)
	}
}

// TestE2EConfirmPortalApproveRetry: confirm -> approval required -> the
// user approves in the portal (session cookie + CSRF) -> the retry with
// approval_id runs the stored arguments once.
func TestE2EConfirmPortalApproveRetry(t *testing.T) {
	w := newWorld(t, options{})
	alice := w.client(w.alice)

	_, err := w.call(alice, "fake.create_item", w.args("id", "it-1", "name", "first", "body", "the original body"))
	id := approvalRequired(t, err)

	// The pending list shows it to alice only.
	// (The pending page shows the decrypted argument summary: that is the
	// one place the content is meant to be seen.)
	if code, body := w.get(w.alice, "/approvals"); code != 200 || !strings.Contains(body, id) || !strings.Contains(body, "original body") {
		t.Errorf("alice GET /approvals = %d, contains id %v", code, strings.Contains(body, id))
	}
	if _, body := w.get(w.bob, "/approvals"); strings.Contains(body, id) {
		t.Errorf("bob's pending list shows alice's approval")
	}
	// Without the CSRF token the form is refused and nothing changes.
	if code, _ := w.post(w.alice, "/approvals/"+id+"/approve", false); code != 403 {
		t.Errorf("approve without CSRF = %d, want 403", code)
	}
	// Bob cannot approve it (404: it does not exist for him).
	if code, _ := w.post(w.bob, "/approvals/"+id+"/approve", true); code != 404 {
		t.Errorf("bob approves alice's = %d, want 404", code)
	}
	if a, _ := w.approval.Get(t.Context(), w.alice.id, id); a.Status != approvals.StatusPending {
		t.Fatalf("status after refused posts = %s", a.Status)
	}
	// Anonymous: redirected to sign-in, never a decision.
	if code, _ := w.post(user{}, "/approvals/"+id+"/approve", false); code != 303 && code != 403 {
		t.Errorf("anonymous approve = %d", code)
	}
	// Alice approves.
	if code, _ := w.post(w.alice, "/approvals/"+id+"/approve", true); code != 303 {
		t.Fatalf("approve = %d, want 303", code)
	}
	// The harness retries with drifted arguments: the stored ones run.
	res, err := w.call(alice, "fake.create_item", w.args("id", "it-1", "name", "first, reworded", "body", "drifted", "approval_id", id))
	if err != nil || res.IsError {
		t.Fatalf("retry: err=%v res=%+v", err, res)
	}
	items := w.fake.State().Items(w.aliceAcc)
	if len(items) != 1 || items[0].Name != "first" || items[0].Body != "the original body" {
		t.Fatalf("connector received %+v, want the stored arguments", items)
	}
	// Single use.
	_, err = w.call(alice, "fake.create_item", w.args("id", "it-2", "name", "again", "approval_id", id))
	if je := rpcError(t, err, mcp.CodeDenied); !strings.Contains(je.Message, "already used") {
		t.Errorf("second use: %q", je.Message)
	}
	// Ledger and portal.
	op := w.opFor(w.alice, "fake.create_item", store.LedgerSucceeded)
	if op == nil || op.ApprovalID == nil || *op.ApprovalID != id || !strings.Contains(string(op.ResultIDs), "it-1") {
		t.Fatalf("ledger op = %+v", op)
	}
	if code, body := w.get(w.alice, "/operations"); code != 200 || !strings.Contains(body, "fake.create_item") || !strings.Contains(body, "succeeded") {
		t.Errorf("GET /operations = %d", code)
	}
	if code, body := w.get(w.alice, "/approvals/history"); code != 200 || !strings.Contains(body, id[:8]) || strings.Contains(body, "original body") {
		t.Errorf("history = %d, shows arguments: %v", code, strings.Contains(body, "original body"))
	}
	// Audit: the tool calls carry the approval id; approve is a user event.
	var withApproval, approved int
	for _, ev := range w.events(w.alice) {
		if ev.EventType == audit.EventTypeToolCall && ev.ApprovalID == id {
			withApproval++
		}
		if ev.EventType == audit.EventTypeUser && ev.ResourceIdentity["action"] == "approval_approved" && ev.ApprovalID == id {
			approved++
		}
	}
	if withApproval < 2 || approved != 1 {
		t.Errorf("audit: tool calls with approval = %d, approve events = %d", withApproval, approved)
	}
}

// TestE2EConfirmSlackApproveRetry: the approval is DM'd to the user's
// connected company Slack; a signed button press from the right Slack
// user approves it; strangers are refused; the retry runs the stored
// arguments.
func TestE2EConfirmSlackApproveRetry(t *testing.T) {
	w := newWorld(t, options{})
	alice := w.client(w.alice)

	_, err := w.call(alice, "fake.create_item", w.args("id", "it-1", "name", "first", "body", "the original body"))
	id := approvalRequired(t, err)
	post := w.slack.lastPost()
	if post == nil || post["channel"] != "D-"+w.aliceSlackUser || post["token"] != slackBotToken || !strings.Contains(post["blocks"], `"value":"`+id+`"`) {
		t.Fatalf("DM = %v", post)
	}
	// Wrong Slack user, wrong team: 403, still pending, audited.
	if code := w.press("approve", id, "UBOB", w.team); code != 403 {
		t.Errorf("stranger press = %d", code)
	}
	if code := w.press("approve", id, w.aliceSlackUser, "TOTHER"); code != 403 {
		t.Errorf("other-team press = %d", code)
	}
	// A tampered signature is refused before anything is parsed.
	if code := w.pressBadSignature("approve", id); code != 401 {
		t.Errorf("bad signature = %d", code)
	}
	if a, _ := w.approval.Get(t.Context(), w.alice.id, id); a.Status != approvals.StatusPending {
		t.Fatalf("status after refused presses = %s", a.Status)
	}
	// Alice presses Approve.
	if code := w.press("approve", id, w.aliceSlackUser, w.team); code != 200 {
		t.Fatalf("approve press = %d", code)
	}
	if up := w.slack.lastUpdate(); up == nil || !strings.Contains(up["blocks"], "Approved") {
		t.Errorf("DM update = %v", up)
	}
	res, err := w.call(alice, "fake.create_item", w.args("id", "it-1", "name", "drifted", "body", "drifted", "approval_id", id))
	if err != nil || res.IsError {
		t.Fatalf("retry: err=%v res=%+v", err, res)
	}
	if items := w.fake.State().Items(w.aliceAcc); len(items) != 1 || items[0].Body != "the original body" {
		t.Fatalf("connector received %+v", items)
	}
	// Audit: two refused presses against the owner, one approve.
	var refused, approved int
	for _, ev := range w.events(w.alice) {
		switch ev.ResourceIdentity["action"] {
		case "approval_slack_rejected":
			if ev.ApprovalID == id && ev.ErrorClass == "slack_user_mismatch" {
				refused++
			}
		case "approval_approved":
			approved++
		}
	}
	if refused != 2 || approved != 1 {
		t.Errorf("audit: refused=%d approved=%d", refused, approved)
	}
	// Bob has no Slack: portal only, no API call.
	before := len(w.slack.posts)
	bob := w.client(w.bob)
	_, err = w.call(bob, "fake.create_item", w.args("id", "b-1", "name", "bob's first item", "account", w.bobAcc))
	approvalRequired(t, err)
	if len(w.slack.posts) != before {
		t.Errorf("Slack DM sent for a user without Slack")
	}
}

// pressBadSignature sends a press with a wrong signature.
func (w *world) pressBadSignature(action, approvalID string) int {
	w.t.Helper()
	payload := url.Values{"payload": {`{"type":"block_actions","actions":[{"action_id":"` + action + `","value":"` + approvalID + `"}]}`}}.Encode()
	code, _ := w.postRaw("/slack/interactions", payload, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "X-Slack-Request-Timestamp": "1700000000", "X-Slack-Signature": "v0=deadbeef",
	})
	return code
}

// TestE2EBoundedWait: the user approves while the call waits; the call
// completes in one round trip.
func TestE2EBoundedWait(t *testing.T) {
	w := newWorld(t, options{approvalWait: 8 * time.Second})
	alice := w.client(w.alice)
	go func() {
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			pend, _ := w.approval.Pending(t.Context(), w.alice.id)
			if len(pend) == 1 {
				// Through the portal, as a browser would.
				w.post(w.alice, "/approvals/"+pend[0].ID+"/approve", true)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	started := time.Now()
	res, err := w.call(alice, "fake.create_item", w.args("id", "it-1", "name", "first"))
	if err != nil || res.IsError {
		t.Fatalf("call: err=%v res=%+v", err, res)
	}
	if time.Since(started) > 6*time.Second {
		t.Errorf("the call took %v: did not complete while waiting", time.Since(started))
	}
	if items := w.fake.State().Items(w.aliceAcc); len(items) != 1 || items[0].ID != "it-1" {
		t.Errorf("items = %+v", items)
	}
	hist, _ := w.approval.History(t.Context(), w.alice.id, 10)
	if len(hist) != 1 || hist[0].Status != approvals.StatusConsumed {
		t.Errorf("history = %+v", hist)
	}
}

// TestE2EDuplicateWritesReplayAndWindow: the same unconfirmed write inside
// the idempotency window replays the stored result ids; once the first
// operation is older than the window it is a new operation.
func TestE2EDuplicateWritesReplayAndWindow(t *testing.T) {
	w := newWorld(t, options{})
	alice := w.client(w.alice)
	args := w.args("text", "LGTM, shipping it")
	res, err := w.call(alice, "fake.post_note", args)
	if err != nil || res.IsError {
		t.Fatalf("first: err=%v res=%+v", err, res)
	}
	var note fake.Note
	if err := json.Unmarshal([]byte(text(t, res)), &note); err != nil {
		t.Fatal(err)
	}
	res, err = w.call(alice, "fake.post_note", args)
	if err != nil || res.IsError {
		t.Fatalf("duplicate: err=%v res=%+v", err, res)
	}
	var replay struct {
		Ledger      string            `json:"_ledger"`
		OperationID string            `json:"operation_id"`
		Tool        string            `json:"tool"`
		Message     string            `json:"message"`
		Result      map[string]string `json:"result"`
	}
	if err := json.Unmarshal([]byte(text(t, res)), &replay); err != nil {
		t.Fatal(err)
	}
	if replay.Ledger != "replayed" || replay.Result["id"] != note.ID || replay.OperationID == "" || replay.Tool != "fake.post_note" {
		t.Errorf("replay = %+v (note %s)", replay, note.ID)
	}
	// The answer says what happened and how to run it again.
	if !strings.Contains(replay.Message, "not run again") || !strings.Contains(replay.Message, replay.OperationID) || !strings.Contains(replay.Message, "id="+note.ID) {
		t.Errorf("replay message = %q", replay.Message)
	}
	if notes := w.fake.State().Notes(w.aliceAcc); len(notes) != 1 {
		t.Errorf("notes = %d, want 1", len(notes))
	}
	// Whitespace and key order do not change the digest: still a replay.
	res, err = w.call(alice, "fake.post_note", map[string]any{"text": "LGTM, shipping it"})
	if err != nil || res.IsError || !strings.Contains(text(t, res), "replayed") {
		t.Errorf("reordered duplicate: err=%v res=%+v", err, res)
	}
	// Age the first operation past the window: a new operation runs.
	w.exec(`UPDATE ledger_operations SET created_at = created_at - interval '25 hours', updated_at = updated_at - interval '25 hours' WHERE id = $1`, replay.OperationID)
	res, err = w.call(alice, "fake.post_note", args)
	if err != nil || res.IsError || strings.Contains(text(t, res), "replayed") {
		t.Fatalf("after window: err=%v res=%+v", err, res)
	}
	if notes := w.fake.State().Notes(w.aliceAcc); len(notes) != 2 {
		t.Errorf("notes after window = %d, want 2", len(notes))
	}
	// Audit: the replay is on record as such, without the note's text.
	var replayed int
	for _, ev := range w.events(w.alice) {
		if ev.Tool == "fake.post_note" && ev.ErrorClass == "replayed" {
			replayed++
		}
	}
	if replayed != 2 {
		t.Errorf("replayed audit rows = %d, want 2", replayed)
	}
	// Bob's identical note is his own operation.
	bob := w.client(w.bob)
	if res, err := w.call(bob, "fake.post_note", map[string]any{"text": "LGTM, shipping it", "account": w.bobAcc}); err != nil || res.IsError || strings.Contains(text(t, res), "replayed") {
		t.Errorf("bob: err=%v res=%+v", err, res)
	}
}

// TestE2EDoubleApprovalUse8Way: eight concurrent retries with the same
// approval id yield exactly one execution.
func TestE2EDoubleApprovalUse8Way(t *testing.T) {
	w := newWorld(t, options{})
	alice := w.client(w.alice)
	_, err := w.call(alice, "fake.create_item", w.args("id", "it-race", "name", "racer"))
	id := approvalRequired(t, err)
	if code, _ := w.post(w.alice, "/approvals/"+id+"/approve", true); code != 303 {
		t.Fatal(code)
	}
	const n = 8
	clients := make([]*sdk.ClientSession, n)
	for i := range n {
		clients[i] = w.client(w.alice)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	results := make([]*sdk.CallToolResult, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = w.call(clients[i], "fake.create_item", map[string]any{"id": "it-race", "name": "racer", "approval_id": id})
		}()
	}
	close(start)
	wg.Wait()
	var winners, used int
	for i := range n {
		switch {
		case errs[i] == nil && !results[i].IsError:
			winners++
		case errs[i] != nil && strings.Contains(errs[i].Error(), "already used"):
			used++
		default:
			t.Errorf("retry %d: err=%v res=%+v", i, errs[i], results[i])
		}
	}
	if winners != 1 || used != n-1 {
		t.Errorf("winners = %d, already-used = %d (of %d)", winners, used, n)
	}
	if items := w.fake.State().Items(w.aliceAcc); len(items) != 1 {
		t.Errorf("items = %+v", items)
	}
	if rows := w.ops(w.alice); len(rows) != 1 || rows[0].State != store.LedgerSucceeded {
		t.Errorf("ledger rows = %+v", rows)
	}
	if a, _ := w.approval.Get(t.Context(), w.alice.id, id); a.Status != approvals.StatusConsumed {
		t.Errorf("approval = %s", a.Status)
	}
}

// TestE2EUnknownOutcomes: an unknown outcome of a reconcilable write is
// resolved to succeeded by the reconciler job; one of a non-reconcilable
// write is unresolved at once, the user is notified and the block lifts.
func TestE2EUnknownOutcomes(t *testing.T) {
	w := newWorld(t, options{})
	alice := w.client(w.alice)

	// create_item (confirmed): approve, then the write applies but the
	// reply is lost.
	_, err := w.call(alice, "fake.create_item", w.args("id", "it-lost", "name", "lost item"))
	id := approvalRequired(t, err)
	if code, _ := w.post(w.alice, "/approvals/"+id+"/approve", true); code != 303 {
		t.Fatal(code)
	}
	w.fake.InjectFault(fake.ToolCreateItem, fake.Fault{Mode: fake.FaultUnknown, Applied: true, Remaining: 1})
	res, err := w.call(alice, "fake.create_item", map[string]any{"id": "it-lost", "name": "lost item", "approval_id": id})
	if err != nil || !res.IsError || !strings.Contains(text(t, res), "outcome unknown") {
		t.Fatalf("unknown write: err=%v res=%+v", err, res)
	}
	createOp := w.opFor(w.alice, "fake.create_item", store.LedgerUnknown)
	if createOp == nil {
		t.Fatalf("no unknown create_item op: %+v", w.ops(w.alice))
	}
	// post_note: the reply is lost; the same note is blocked meanwhile.
	w.fake.InjectFault(fake.ToolPostNote, fake.Fault{Mode: fake.FaultUnknown, Applied: true, Remaining: 1})
	noteArgs := w.args("text", "a note whose reply was lost")
	if res, err := w.call(alice, "fake.post_note", noteArgs); err != nil || !res.IsError {
		t.Fatalf("unknown note: err=%v res=%+v", err, res)
	}
	_, err = w.call(alice, "fake.post_note", noteArgs)
	je := rpcError(t, err, mcp.CodePendingVerification)
	var data map[string]any
	_ = json.Unmarshal(je.Data, &data)
	noteOp := w.opFor(w.alice, "fake.post_note", store.LedgerUnknown)
	if noteOp == nil || data["operation_id"] != noteOp.ID {
		t.Fatalf("pending verification data = %v, ops = %+v", data, w.ops(w.alice))
	}

	// The reconciler job runs on the real runner.
	w.runJobs(jobs.NewReconcilerJob(w.ledger, 100*time.Millisecond))
	w.eventually("post_note unresolved + notified", 10*time.Second, func() bool {
		return w.op(noteOp.ID).State == store.LedgerUnresolved && len(w.notifier.list()) == 1
	})
	if notified := w.notifier.list(); len(notified) != 1 || notified[0].ID != noteOp.ID || notified[0].UserID != w.alice.id {
		t.Errorf("notified = %+v", notified)
	}
	if row := w.op(noteOp.ID); row.ErrorCode == nil || *row.ErrorCode != ledger.ClassNotReconcilable {
		t.Errorf("unresolved row = %+v", row)
	}
	// The block is lifted: a deliberate retry posts the note again.
	if res, err := w.call(alice, "fake.post_note", noteArgs); err != nil || res.IsError {
		t.Errorf("note after unresolved: err=%v res=%+v", err, res)
	}
	// The create_item is not due until a minute has passed; then it is
	// found and succeeded.
	if row := w.op(createOp.ID); row.State != store.LedgerUnknown {
		t.Fatalf("create_item reconciled too early: %+v", row)
	}
	w.advance(time.Minute)
	w.eventually("create_item reconciled", 10*time.Second, func() bool { return w.op(createOp.ID).State == store.LedgerSucceeded })
	if row := w.op(createOp.ID); !strings.Contains(string(row.ResultIDs), "it-lost") || row.FinishedAt == nil {
		t.Errorf("create op = %+v", row)
	}
	// The used approval cannot run again.
	_, err = w.call(alice, "fake.create_item", map[string]any{"id": "it-lost", "name": "lost item", "approval_id": id})
	if je := rpcError(t, err, mcp.CodeDenied); !strings.Contains(je.Message, "already used") {
		t.Errorf("retry with the used approval: %q", je.Message)
	}
	// Audit and portal.
	var unresolved, reconciled int
	for _, ev := range w.events(w.alice) {
		switch {
		case ev.OperationID == noteOp.ID && ev.Outcome == "unresolved" && ev.ErrorClass == ledger.ClassNotReconcilable:
			unresolved++
		case ev.OperationID == createOp.ID && ev.Outcome == "succeeded" && ev.ErrorClass == "reconciled":
			reconciled++
		}
	}
	if unresolved != 1 || reconciled != 1 {
		t.Errorf("audit: unresolved=%d reconciled=%d", unresolved, reconciled)
	}
	code, body := w.get(w.alice, "/operations")
	if code != 200 || !strings.Contains(body, "unresolved") || !strings.Contains(body, "verify in the app") || !strings.Contains(body, "succeeded") || !strings.Contains(body, "it-lost") {
		t.Errorf("GET /operations = %d", code)
	}
	if _, body := w.get(w.bob, "/operations"); strings.Contains(body, createOp.ID[:8]) || strings.Contains(body, noteOp.ID[:8]) {
		t.Errorf("bob's /operations lists alice's operations")
	}
}

// TestE2ECrashMidCall: a write hangs in the connector, the row stays
// in_progress, the replica is "lost" (the row is backdated past the
// staleness window), the stale sweep job marks it unknown, the
// reconciler finds the applied marker and a retry replays it.
func TestE2ECrashMidCall(t *testing.T) {
	w := newWorld(t, options{})
	hung := w.client(w.alice)
	w.fake.InjectFault(fake.ToolFlakyWrite, fake.Fault{Mode: fake.FaultHang, Applied: true, Remaining: 1})
	args := w.args("marker", "m-crash", "payload", "payload of the hung write")
	done := make(chan error, 1)
	go func() {
		_, err := hung.CallTool(t.Context(), &sdk.CallToolParams{Name: "fake.flaky_write", Arguments: args})
		done <- err
	}()
	w.eventually("in_progress row", 5*time.Second, func() bool { return w.opFor(w.alice, "fake.flaky_write", store.LedgerInProgress) != nil })
	op := w.opFor(w.alice, "fake.flaky_write", store.LedgerInProgress)
	time.Sleep(50 * time.Millisecond) // let the call reach the connector
	// A duplicate while it hangs is "pending verification".
	other := w.client(w.alice)
	_, err := w.call(other, "fake.flaky_write", args)
	_ = rpcError(t, err, mcp.CodePendingVerification)
	// The replica died: the row is older than the staleness window.
	w.exec(`UPDATE ledger_operations SET created_at = now() - interval '10 minutes', updated_at = now() - interval '10 minutes' WHERE id = $1`, op.ID)
	w.runJobs(jobs.NewStaleSweepJob(w.ledger, 100*time.Millisecond))
	w.eventually("stale sweep", 10*time.Second, func() bool { return w.op(op.ID).State == store.LedgerUnknown })
	if row := w.op(op.ID); row.ErrorCode == nil || *row.ErrorCode != ledger.ClassStale {
		t.Errorf("swept row = %+v", row)
	}
	// Cut the hung client: the handler returns; the row stays unknown.
	w.srv.CloseClientConnections()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the hung call did not return after its connection was cut")
	}
	if row := w.op(op.ID); row.State != store.LedgerUnknown {
		t.Errorf("row after the cut = %+v", row)
	}
	// Reconciled (the marker was applied) and replayed on retry.
	w.advance(time.Minute)
	w.runJobs(jobs.NewReconcilerJob(w.ledger, 100*time.Millisecond))
	w.eventually("reconciled", 10*time.Second, func() bool { return w.op(op.ID).State == store.LedgerSucceeded })
	retry := w.client(w.alice)
	res, err := w.call(retry, "fake.flaky_write", args)
	if err != nil || res.IsError || !strings.Contains(text(t, res), "replayed") {
		t.Errorf("retry after reconcile: err=%v res=%+v", err, res)
	}
	if writes := w.fake.State().Writes(w.aliceAcc); len(writes) != 1 {
		t.Errorf("writes = %+v, want exactly one", writes)
	}
}

// TestE2ECrossUserAndScope: nothing of bob's is reachable with alice's
// token or session, and the refusals do not reveal existence; personal
// accounts are refused for the restricted role; a read-only token cannot
// write; /activity is the user's own, /admin/audit everyone's.
func TestE2ECrossUserAndScope(t *testing.T) {
	w := newWorld(t, options{})
	aliceToken := w.token(w.alice, tokens.CreateRequest{})
	alice, bob := w.clientWith(aliceToken), w.client(w.bob)
	w.fake.SeedItems(w.aliceAcc, fake.Item{ID: "it-alice-7", Name: "alice's"})
	w.fake.SeedItems(w.bobAcc, fake.Item{ID: "bob-prefix-q1", Name: "bob's"})

	// Bob's approval and operation to point at.
	_, err := w.call(bob, "fake.create_item", w.args("id", "b-1", "name", "bob item", "account", w.bobAcc))
	bobApproval := approvalRequired(t, err)
	if res, err := w.call(bob, "fake.post_note", w.args("text", "bob's note", "account", w.bobAcc)); err != nil || res.IsError {
		t.Fatalf("bob post_note: err=%v res=%+v", err, res)
	}
	bobOp := w.opFor(w.bob, "fake.post_note", store.LedgerSucceeded)
	if bobOp == nil {
		t.Fatal("no bob op")
	}

	// Alice naming bob's account: the same answer as a nonexistent one.
	random := "9b2d1c1e-0d5b-4f8a-9a1c-5b9f3d2e1a00"
	gotB := w.rawCall(aliceToken, "fake.list_items", map[string]any{"account": w.bobAcc})
	gotR := w.rawCall(aliceToken, "fake.list_items", map[string]any{"account": random})
	if a, b := strings.ReplaceAll(stripID(gotB), w.bobAcc, "X"), strings.ReplaceAll(stripID(gotR), random, "X"); a != b || !strings.Contains(a, "unknown account") {
		t.Errorf("bob's account vs random:\n%s\n%s", gotB, gotR)
	}
	// Alice retrying with bob's approval id: the same answer as an unknown id.
	gotB = w.rawCall(aliceToken, "fake.create_item", map[string]any{"id": "x", "name": "x", "approval_id": bobApproval})
	gotR = w.rawCall(aliceToken, "fake.create_item", map[string]any{"id": "x", "name": "x", "approval_id": random})
	if a, b := stripID(gotB), stripID(gotR); a != b || !strings.Contains(a, "does not match") {
		t.Errorf("bob's approval vs random:\n%s\n%s", gotB, gotR)
	}
	if a, _ := w.approval.Get(t.Context(), w.bob.id, bobApproval); a.Status != approvals.StatusPending {
		t.Errorf("bob's approval touched: %s", a.Status)
	}
	// Alice's session: bob's approval and operation do not exist.
	codeB, bodyB := w.post(w.alice, "/approvals/"+bobApproval+"/approve", true)
	codeR, bodyR := w.post(w.alice, "/approvals/"+random+"/approve", true)
	if codeB != 404 || codeR != 404 || bodyB != bodyR {
		t.Errorf("alice approving bob's: %d %q vs random %d %q", codeB, bodyB, codeR, bodyR)
	}
	for _, path := range []string{"/approvals", "/approvals/history", "/operations"} {
		if code, body := w.get(w.alice, path); code != 200 || strings.Contains(body, bobApproval) || strings.Contains(body, bobOp.ID[:8]) {
			t.Errorf("alice GET %s = %d, shows bob's rows", path, code)
		}
	}
	if code, body := w.get(w.bob, "/operations"); code != 200 || !strings.Contains(body, bobOp.ID[:8]) {
		t.Errorf("bob GET /operations = %d, missing his own", code)
	}

	// Personal account on the deny-personal role: refused; company runs.
	_, err = w.call(bob, "fake.post_note", w.args("text", "from home", "account", w.bobPersonal))
	_ = rpcError(t, err, mcp.CodeDenied)
	if notes := w.fake.State().Notes(w.bobPersonal); len(notes) != 0 {
		t.Errorf("personal notes = %+v", notes)
	}
	// Alice (member, personal allowed) could use a personal account; she
	// has none, and naming bob's personal one is unknown to her.
	_, err = w.call(alice, "fake.post_note", map[string]any{"text": "x", "account": w.bobPersonal})
	_ = rpcError(t, err, mcp.CodeInvalidParams)

	// A read-only token: writes are not available and nothing is written.
	ro := w.clientWith(w.token(w.alice, tokens.CreateRequest{Name: "ro", ReadOnly: true}))
	roTools := toolNames(t, ro)
	for _, name := range []string{"fake.create_item", "fake.post_note", "fake.flaky_write"} {
		if contains(roTools, name) {
			t.Errorf("read-only token lists %s", name)
		}
	}
	if !contains(roTools, "fake.list_items") {
		t.Errorf("read-only token lost its reads: %v", roTools)
	}
	_, err = w.call(ro, "fake.post_note", w.args("text", "read only write"))
	if err == nil {
		t.Fatal("read-only token wrote")
	}
	if notes := w.fake.State().Notes(w.aliceAcc); len(notes) != 0 {
		t.Errorf("alice notes = %+v", notes)
	}
	if res, err := w.call(ro, "fake.get_item", w.args("id", "it-alice-7")); err != nil || res.IsError {
		t.Errorf("read-only read: err=%v res=%+v", err, res)
	}

	// Reads by both, then the pages: /activity shows only the caller's
	// rows, /admin/audit everyone's, and only to an admin.
	if res, err := w.call(bob, "fake.list_items", map[string]any{"prefix": "bob-prefix-q", "account": w.bobAcc}); err != nil || res.IsError {
		t.Fatalf("bob list_items: err=%v res=%+v", err, res)
	}
	if code, body := w.get(w.alice, "/activity"); code != 200 || !strings.Contains(body, "it-alice-7") || strings.Contains(body, "bob-prefix-q") || !strings.Contains(body, "fake.create_item") {
		t.Errorf("alice /activity = %d: alice row %v, bob row %v", code, strings.Contains(body, "it-alice-7"), strings.Contains(body, "bob-prefix-q"))
	}
	if code, body := w.get(w.bob, "/activity"); code != 200 || strings.Contains(body, "it-alice-7") || !strings.Contains(body, "bob-prefix-q") {
		t.Errorf("bob /activity = %d", code)
	}
	if code, body := w.get(w.alice, "/activity?user_id="+w.bob.id); code != 200 || strings.Contains(body, "bob-prefix-q") {
		t.Errorf("alice /activity?user_id=bob = %d, widened: %v", code, strings.Contains(body, "bob-prefix-q"))
	}
	if code, _ := w.get(w.alice, "/admin/audit"); code != 404 {
		t.Errorf("alice /admin/audit = %d, want 404", code)
	}
	if code, body := w.get(w.admin, "/admin/audit"); code != 200 || !strings.Contains(body, "it-alice-7") || !strings.Contains(body, "bob-prefix-q") {
		t.Errorf("admin /admin/audit = %d: alice %v bob %v", code, strings.Contains(body, "it-alice-7"), strings.Contains(body, "bob-prefix-q"))
	}
	if code, body := w.get(w.admin, "/admin/audit?user_id="+w.bob.id); code != 200 || strings.Contains(body, "it-alice-7") || !strings.Contains(body, "bob-prefix-q") {
		t.Errorf("admin /admin/audit?user_id=bob = %d", code)
	}
	// Every audited call of alice's names the resolved account and the
	// resource identity the connector extracted, never argument content.
	var withResource int
	for _, ev := range w.events(w.alice) {
		if ev.EventType == audit.EventTypeToolCall && ev.Tool == "fake.get_item" && ev.ResourceIdentity["id"] == "it-alice-7" && ev.AccountID == w.aliceAcc {
			withResource++
		}
	}
	if withResource != 1 {
		t.Errorf("get_item audit rows with resource identity = %d", withResource)
	}
}

// TestE2ERevokedTokenAndAnonymous: a revoked token and no token are 401
// at the transport, before any tool runs.
func TestE2ERevokedTokenAndAnonymous(t *testing.T) {
	w := newWorld(t, options{})
	raw := w.token(w.alice, tokens.CreateRequest{Name: "short"})
	cs := w.clientWith(raw)
	if res, err := w.call(cs, "fake.list_accounts", nil); err != nil || res.IsError {
		t.Fatalf("before revoke: %v", err)
	}
	list, err := w.tokens.List(t.Context(), w.alice.id)
	if err != nil || len(list) == 0 {
		t.Fatal(err)
	}
	for _, tok := range list {
		if err := w.tokens.Revoke(t.Context(), w.alice.id, tok.ID); err != nil {
			t.Fatal(err)
		}
	}
	if code := w.rawStatus(raw); code != 401 {
		t.Errorf("revoked token = %d, want 401", code)
	}
	if code := w.rawStatus(""); code != 401 {
		t.Errorf("no token = %d, want 401", code)
	}
	if _, err := w.call(cs, "fake.list_accounts", nil); err == nil {
		t.Error("revoked token still works")
	}
}
