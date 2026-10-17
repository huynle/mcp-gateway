//go:build integration || e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors/github"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

// TestE2EGitHubCreateIssueConfirmAndDeny: a real vendor connector behind
// the safety core. create_issue in org acme needs an approval; after the
// approval the retry creates the issue with the operation's hidden marker
// in its body and the ledger stores the result ids; the same write in
// another org is denied by policy; the connector never sees the call.
func TestE2EGitHubCreateIssueConfirmAndDeny(t *testing.T) {
	gw := newGitHubWorld(t)
	alice := gw.client(gw.alice)

	tools := toolNames(t, alice)
	if !contains(tools, "github.create_issue") || !contains(tools, "github.get_me") || !contains(tools, "github.list_accounts") {
		t.Fatalf("tools/list = %v", tools)
	}
	if contains(tools, "github.create_branch") {
		t.Errorf("tools/list shows an ungranted tool: %v", tools)
	}

	// Org acme: approval required, then the approved retry runs.
	args := gw.issueArgs("acme", "widgets", "Uploader gives up on the first timeout", "Steps: upload a 2 GB file on a slow link.")
	_, err := gw.call(alice, "github.create_issue", args)
	id := approvalRequired(t, err)
	if n := len(gw.stub.list("acme/widgets")); n != 0 {
		t.Fatalf("stub has %d issues before the approval", n)
	}
	if code, _ := gw.post(gw.alice, "/approvals/"+id+"/approve", true); code != 303 {
		t.Fatalf("approve = %d, want 303", code)
	}
	retry := map[string]any{"owner": "acme", "repo": "widgets", "title": "drifted", "body": "drifted", "approval_id": id}
	res, err := gw.call(alice, "github.create_issue", retry)
	if err != nil || res.IsError {
		t.Fatalf("approved retry: err=%v res=%+v", err, res)
	}
	var created struct {
		Number int    `json:"number"`
		ID     int64  `json:"id"`
		URL    string `json:"url"`
		Repo   string `json:"repo"`
	}
	if err := json.Unmarshal([]byte(text(t, res)), &created); err != nil {
		t.Fatalf("result %q: %v", text(t, res), err)
	}
	if created.Number != 1 || created.ID == 0 || created.Repo != "acme/widgets" || !strings.HasSuffix(created.URL, "/acme/widgets/issues/1") {
		t.Errorf("result = %+v", created)
	}
	op := gw.opFor(gw.alice, "github.create_issue", store.LedgerSucceeded)
	if op == nil || op.ApprovalID == nil || *op.ApprovalID != id {
		t.Fatalf("ledger op = %s", describe(op))
	}
	if ids := resultIDs(t, op); ids["number"] != "1" || ids["url"] != created.URL || ids["id"] == "" {
		t.Errorf("stored result ids = %v", ids)
	}
	if rid := resource(t, op); rid["repo"] != "acme/widgets" || rid["org"] != "acme" {
		t.Errorf("resource identity = %v", rid)
	}
	issues := gw.stub.list("acme/widgets")
	if len(issues) != 1 {
		t.Fatalf("stub issues = %+v, want one", issues)
	}
	// The stored (approved) arguments ran, not the drifted retry, and the
	// body ends with the hidden marker of the ledger operation.
	if issues[0].Title != args["title"] || !strings.HasPrefix(issues[0].Body, args["body"].(string)) {
		t.Errorf("issue = %+v, want the approved title and body", issues[0])
	}
	if !strings.HasSuffix(issues[0].Body, github.Marker(op.ID)) {
		t.Errorf("issue body %q does not end with the marker of operation %s", issues[0].Body, op.ID)
	}
	if strings.Contains(text(t, res), "mcp-gateway op:") {
		t.Errorf("the marker leaked into the tool result: %s", text(t, res))
	}

	// Another org: denied by policy, the connector never called.
	_, err = gw.call(alice, "github.create_issue", gw.issueArgs("other-org", "widgets", "Not our organization", "This body must never be created."))
	if je := rpcError(t, err, mcp.CodeDenied); !strings.Contains(je.Message, "denied") {
		t.Errorf("deny = %q", je.Message)
	}
	if n := len(gw.stub.list("other-org/widgets")); n != 0 {
		t.Errorf("stub created %d issues for a denied write", n)
	}
	for _, row := range gw.ops(gw.alice) {
		if resource(t, &row)["org"] == "other-org" {
			t.Errorf("a denied write reached the ledger: %s", describe(&row))
		}
	}
	var denied int
	for _, ev := range gw.events(gw.alice) {
		if ev.Tool == "github.create_issue" && ev.Decision == "deny" && ev.ResourceIdentity["org"] == "other-org" {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("audit deny events for other-org = %d, want 1", denied)
	}
	// Bob's role grants no GitHub tool: hidden, exactly like an unknown tool.
	_, err = gw.call(gw.client(gw.bob), "github.create_issue", gw.issueArgs("acme-labs", "widgets", "Bob's issue title", "Bob's issue body text"))
	if je := rpcError(t, err, -32602); !strings.Contains(je.Message, "unknown tool") {
		t.Errorf("bob's call = %q", je.Message)
	}
}

// TestE2EGitHubUnknownOutcomeReconciled: GitHub applies the write but
// the answer never arrives (timeout). The ledger marks the operation
// unknown, the reconciler job finds the issue by its marker through the
// stub's search API, the operation succeeds with the issue number, and a
// duplicate call replays the stored ids without creating a second issue.
func TestE2EGitHubUnknownOutcomeReconciled(t *testing.T) {
	gw := newGitHubWorld(t)
	alice := gw.client(gw.alice)
	args := gw.issueArgs("acme-labs", "tools", "Lost answer", "The reply to this create was lost.")

	gw.stub.setFault(stubCreateThenHang)
	res, err := gw.call(alice, "github.create_issue", args)
	if err != nil || !res.IsError || !strings.Contains(text(t, res), "outcome unknown") {
		t.Fatalf("unknown write: err=%v res=%+v", err, res)
	}
	op := gw.opFor(gw.alice, "github.create_issue", store.LedgerUnknown)
	if op == nil {
		t.Fatalf("no unknown op: %+v", gw.ops(gw.alice))
	}
	if is := gw.issueWithMarker("acme-labs/tools", op.ID); is == nil {
		t.Fatalf("the stub holds no issue with the marker of %s: %+v", op.ID, gw.stub.list("acme-labs/tools"))
	}
	// Meanwhile the same write is blocked.
	_, err = gw.call(alice, "github.create_issue", args)
	_ = rpcError(t, err, mcp.CodePendingVerification)

	gw.runJobs(jobs.NewReconcilerJob(gw.ledger, 100*time.Millisecond))
	gw.advance(time.Minute)
	gw.eventually("create_issue reconciled", 10*time.Second, func() bool { return gw.op(op.ID).State == store.LedgerSucceeded })
	row := gw.op(op.ID)
	if errorCode(row) != ledger.ClassReconciled || resultIDs(t, row)["id"] != "1" || row.FinishedAt == nil {
		t.Errorf("reconciled row = %s", describe(row))
	}
	// A duplicate inside the window replays the stored ids; the stub
	// still has exactly one issue.
	res, err = gw.call(alice, "github.create_issue", args)
	if err != nil || res.IsError {
		t.Fatalf("replay: err=%v res=%+v", err, res)
	}
	var replay struct {
		Ledger string            `json:"_ledger"`
		OpID   string            `json:"operation_id"`
		Result map[string]string `json:"result"`
	}
	if err := json.Unmarshal([]byte(text(t, res)), &replay); err != nil || replay.Ledger != "replayed" || replay.OpID != op.ID || replay.Result["id"] != "1" {
		t.Errorf("replay = %s (%v)", text(t, res), err)
	}
	if n := len(gw.stub.list("acme-labs/tools")); n != 1 {
		t.Errorf("stub issues = %d, want 1 (no duplicate)", n)
	}
	var reconciled int
	for _, ev := range gw.events(gw.alice) {
		if ev.OperationID == op.ID && ev.Outcome == "succeeded" && ev.ErrorClass == ledger.ClassReconciled {
			reconciled++
		}
	}
	if reconciled != 1 {
		t.Errorf("audit reconciled events = %d", reconciled)
	}
	if code, body := gw.get(gw.alice, "/operations"); code != 200 || !strings.Contains(body, "github.create_issue") || !strings.Contains(body, "succeeded") {
		t.Errorf("GET /operations = %d", code)
	}
}

// TestE2EGitHubUnknownOutcomeNotFound: the answer never arrives and
// GitHub did not apply the write. The reconciler searches by marker,
// falls back to the user's recent issues, finds nothing, closes the
// operation as failed (not_found) and lifts the block: a deliberate
// retry creates the issue.
func TestE2EGitHubUnknownOutcomeNotFound(t *testing.T) {
	gw := newGitHubWorld(t)
	alice := gw.client(gw.alice)
	args := gw.issueArgs("acme-labs", "tools", "Never created", "GitHub dropped this one.")

	gw.stub.setFault(stubHangWithoutCreate)
	res, err := gw.call(alice, "github.create_issue", args)
	if err != nil || !res.IsError {
		t.Fatalf("unknown write: err=%v res=%+v", err, res)
	}
	op := gw.opFor(gw.alice, "github.create_issue", store.LedgerUnknown)
	if op == nil {
		t.Fatalf("no unknown op: %+v", gw.ops(gw.alice))
	}
	if n := len(gw.stub.list("acme-labs/tools")); n != 0 {
		t.Fatalf("stub issues = %d, want none", n)
	}
	gw.runJobs(jobs.NewReconcilerJob(gw.ledger, 100*time.Millisecond))
	gw.advance(2 * time.Minute)
	gw.eventually("create_issue not found", 10*time.Second, func() bool { return gw.op(op.ID).State == store.LedgerFailed })
	row := gw.op(op.ID)
	if errorCode(row) != ledger.ClassNotFound || len(resultIDs(t, row)) != 0 {
		t.Errorf("failed row = %s", describe(row))
	}
	// The ledger row turns failed before the reconciler records its audit
	// event, so wait for the event rather than reading it once.
	countNotFound := func() int {
		n := 0
		for _, ev := range gw.events(gw.alice) {
			if ev.OperationID == op.ID && ev.Outcome == "failed" && ev.ErrorClass == ledger.ClassNotFound {
				n++
			}
		}
		return n
	}
	gw.eventually("audit not_found event", 10*time.Second, func() bool { return countNotFound() >= 1 })
	if n := countNotFound(); n != 1 {
		t.Errorf("audit not_found events = %d", n)
	}
	if n := len(gw.notifier.list()); n != 0 {
		t.Errorf("a definite not_found notified the user %d times (only unresolved does)", n)
	}
	// The block is lifted: the retry is a new operation that succeeds.
	res, err = gw.call(alice, "github.create_issue", args)
	if err != nil || res.IsError {
		t.Fatalf("retry after not_found: err=%v res=%+v", err, res)
	}
	second := gw.opFor(gw.alice, "github.create_issue", store.LedgerSucceeded)
	if second == nil || second.ID == op.ID {
		t.Fatalf("retry op = %s", describe(second))
	}
	if is := gw.issueWithMarker("acme-labs/tools", second.ID); is == nil || len(gw.stub.list("acme-labs/tools")) != 1 {
		t.Errorf("stub issues = %+v, want one carrying the retry's marker", gw.stub.list("acme-labs/tools"))
	}
	if code, body := gw.get(gw.alice, "/operations"); code != 200 || !strings.Contains(body, "failed") || !strings.Contains(body, "succeeded") {
		t.Errorf("GET /operations = %d", code)
	}
}
