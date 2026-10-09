package mcp_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/ledger/ledgertest"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const (
	ledgerPolicyV = "11111111-1111-1111-1111-111111111111"
	ledgerAcct    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

// ledgerConsumer is a stand-in approvals service for the stage tests.
type ledgerConsumer struct {
	args map[string]map[string]any
	err  error
}

func (c *ledgerConsumer) Consume(_ context.Context, _ ledger.Tx, b ledger.ApprovalBinding) (*ledger.ConsumedApproval, error) {
	if c.err != nil {
		return nil, c.err
	}
	args, ok := c.args[b.ApprovalID]
	if !ok {
		return nil, errors.New("approvals: approval already used")
	}
	delete(c.args, b.ApprovalID)
	return &ledger.ConsumedApproval{ID: b.ApprovalID, Args: args, ResourceIdentity: map[string]string{"repo": "from-approval"}}, nil
}

// ledgerFixture is the default pipeline (account + policy) with the ledger
// stage inserted before ratelimit, over the in-memory ledger store. The
// write tool's handler is replaceable per test and records every call.
type ledgerFixture struct {
	st       *ledgertest.MemStore
	svc      *ledger.Service
	consumer *ledgerConsumer
	audit    *captureRecorder
	pipeline *mcp.Pipeline
	limiter  *stubLimiter

	mu      sync.Mutex
	calls   []connectors.Call
	handler func(ctx context.Context, call connectors.Call) (connectors.Result, error)
	now     time.Time
}

type stubLimiter struct{ deny bool }

func (l *stubLimiter) Allow(context.Context, string, string) (bool, time.Duration) {
	if l.deny {
		return false, 7 * time.Second
	}
	return true, 0
}

func newLedgerFixture(t *testing.T, confirm mcp.ConfirmHandler) *ledgerFixture {
	t.Helper()
	f := &ledgerFixture{st: ledgertest.NewMemStore(), consumer: &ledgerConsumer{args: map[string]map[string]any{}}, audit: &captureRecorder{}, limiter: &stubLimiter{}}
	f.now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	f.handler = func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: map[string]any{"number": 42, "url": "https://example.com/i/42", "body": "SECRET"}}, nil
	}
	svc, err := ledger.New(ledger.DefaultConfig(), f.st, ledger.Options{Approvals: f.consumer, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time { return f.now })
	f.svc = svc

	reg := connectors.NewRegistry()
	write := stubTool("github", "create_issue", connectors.KindWrite)
	write.ResourceIdentity = func(args map[string]any) map[string]string {
		if r, _ := args["repo"].(string); r != "" {
			return map[string]string{"repo": r}
		}
		return nil
	}
	write.ResultIDs = func(res connectors.Result) map[string]string {
		m, _ := res.Content.(map[string]any)
		if m == nil {
			return nil
		}
		return map[string]string{"number": fmt.Sprint(m["number"]), "url": fmt.Sprint(m["url"])}
	}
	write.Handler = func(ctx context.Context, call connectors.Call) (connectors.Result, error) {
		f.mu.Lock()
		f.calls = append(f.calls, call)
		h := f.handler
		f.mu.Unlock()
		return h(ctx, call)
	}
	read := stubTool("github", "list_issues", connectors.KindRead)
	read.Handler = write.Handler
	for _, tool := range []connectors.Tool{write, read} {
		if err := reg.Register(tool); err != nil {
			t.Fatal(err)
		}
	}
	accounts := connectors.NewStaticAccountSource()
	accounts.Add("user-1", connectors.Account{ID: ledgerAcct, App: "github", Label: connectors.LabelCompany, DisplayName: "Work"})
	d := &stubDecider{outcomes: map[string]policy.Outcome{"github.create_issue": policy.OutcomeAllow, "github.list_issues": policy.OutcomeAllow}}
	if confirm != nil {
		d.outcomes["github.create_issue"], d.outcomes["github.list_issues"] = policy.OutcomeConfirm, policy.OutcomeConfirm
	}
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: reg, Accounts: accounts, Policy: d, Confirm: confirm, RateLimiter: f.limiter, Audit: f.audit,
		Visibility: mcp.PolicyVisibility{Decider: d}, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Insert(mcp.Before, mcp.StageRateLimit, mcp.LedgerStage(svc, slog.New(slog.DiscardHandler))); err != nil {
		t.Fatal(err)
	}
	f.pipeline = p
	return f
}

func (f *ledgerFixture) run(t *testing.T, ctx context.Context, name string, args map[string]any) (*mcp.CallContext, connectors.Result, error) {
	t.Helper()
	cc := &mcp.CallContext{Principal: &tokens.Principal{UserID: "user-1", TokenID: "token-1", PublicID: "pub1"}, Name: name, RawArgs: args}
	res, err := f.pipeline.Run(ctx, cc)
	return cc, res, err
}

func (f *ledgerFixture) lastCall(t *testing.T) connectors.Call {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("no handler call")
	}
	return f.calls[len(f.calls)-1]
}

func (f *ledgerFixture) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestLedgerStageSitsBeforeRateLimitAndSkipsReads(t *testing.T) {
	f := newLedgerFixture(t, nil)
	if names := strings.Join(f.pipeline.Names(), ","); names != "authenticate,audit,resolve,strip,account,policy,ledger,ratelimit,dispatch" {
		t.Errorf("stages = %s", names)
	}
	cc, _, err := f.run(t, t.Context(), "github.list_issues", map[string]any{"repo": "acme/web"})
	if err != nil || cc.OperationID != "" || f.st.Count() != 0 || f.lastCall(t).OperationID != "" {
		t.Errorf("read: err=%v op=%q rows=%d", err, cc.OperationID, f.st.Count())
	}
}

func TestLedgerStageRecordsBeforeTheCallAndStoresResultIDsOnly(t *testing.T) {
	f := newLedgerFixture(t, nil)
	var seen *store.LedgerOperation
	f.handler = func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		seen = f.st.Operation(call.OperationID) // the row exists while the call runs
		return connectors.Result{Content: map[string]any{"number": 42, "url": "https://example.com/i/42", "body": "SECRET"}}, nil
	}
	cc, res, err := f.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web", "title": "SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	if cc.OperationID == "" || f.lastCall(t).OperationID != cc.OperationID {
		t.Fatalf("operation id not propagated: cc=%q call=%q", cc.OperationID, f.lastCall(t).OperationID)
	}
	if seen == nil || seen.State != store.LedgerInProgress || seen.ConnectionID != ledgerAcct || seen.PolicyVersionID != ledgerPolicyV || seen.TokenID == nil || *seen.TokenID != "token-1" {
		t.Errorf("row during the call = %+v", seen)
	}
	if m, _ := res.Content.(map[string]any); m["body"] != "SECRET" {
		t.Errorf("the harness must still get the full result: %v", res.Content)
	}
	row := f.st.Operation(cc.OperationID)
	if row.State != store.LedgerSucceeded || !strings.Contains(string(row.ResultIDs), `"number":"42"`) || !strings.Contains(string(row.ResultIDs), `"url"`) || strings.Contains(string(row.ResultIDs), "SECRET") {
		t.Errorf("row after = %s %s", row.State, row.ResultIDs)
	}
	if !strings.Contains(string(row.Resource), `"repo":"acme/web"`) || strings.Contains(string(row.Resource), "SECRET") {
		t.Errorf("resource = %s", row.Resource)
	}
	if atts := f.st.Attempts(cc.OperationID); len(atts) != 1 || atts[0].Outcome != "succeeded" {
		t.Errorf("attempts = %+v", atts)
	}
	ev := f.audit.events[len(f.audit.events)-1]
	if ev.OperationID != cc.OperationID || ev.Outcome != "succeeded" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestLedgerStageReplaysADuplicateInsideTheWindow(t *testing.T) {
	f := newLedgerFixture(t, nil)
	args := map[string]any{"repo": "acme/web", "title": "same"}
	first, _, err := f.run(t, t.Context(), "github.create_issue", args)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	cc, res, err := f.run(t, t.Context(), "github.create_issue", map[string]any{"title": "same", "repo": "acme/web"})
	if err != nil {
		t.Fatal(err)
	}
	if f.callCount() != 1 {
		t.Fatalf("duplicate ran the handler: %d calls", f.callCount())
	}
	m, _ := res.Content.(map[string]any)
	if m["_ledger"] != "replayed" || m["operation_id"] != first.OperationID {
		t.Errorf("replay content = %v", res.Content)
	}
	ids, _ := m["result"].(map[string]string)
	if ids["number"] != "42" || ids["url"] == "" {
		t.Errorf("replayed ids = %v", m["result"])
	}
	if cc.OperationID != first.OperationID {
		t.Errorf("audit op = %q, want the replayed %q", cc.OperationID, first.OperationID)
	}
	ev := f.audit.events[len(f.audit.events)-1]
	if ev.Outcome != "succeeded" || ev.ErrorClass != "replayed" {
		t.Errorf("audit = %+v", ev)
	}
	// Different arguments: a new call.
	if _, _, err := f.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web", "title": "other"}); err != nil || f.callCount() != 2 {
		t.Errorf("new args: err=%v calls=%d", err, f.callCount())
	}
	// Past the window: a new call.
	f.now = f.now.Add(24 * time.Hour)
	if _, _, err := f.run(t, t.Context(), "github.create_issue", args); err != nil || f.callCount() != 3 {
		t.Errorf("after window: err=%v calls=%d", err, f.callCount())
	}
}

func TestLedgerStageAnswersPendingVerificationWhileAPriorIsOpen(t *testing.T) {
	f := newLedgerFixture(t, nil)
	args := map[string]any{"repo": "acme/web", "title": "slow"}
	started := make(chan string)
	release := make(chan struct{})
	f.handler = func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		started <- call.OperationID
		<-release
		return connectors.Result{Content: map[string]any{"number": 1}}, nil
	}
	go func() { _, _, _ = f.run(t, context.Background(), "github.create_issue", args) }()
	opID := <-started

	f.handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		t.Error("duplicate ran")
		return connectors.Result{}, nil
	}
	cc, _, err := f.run(t, t.Context(), "github.create_issue", args)
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodePendingVerification || te.Class() != "pending_verification" || te.Data["operation_id"] != opID || !strings.Contains(te.Message, opID) {
		t.Fatalf("err = %v", err)
	}
	if !te.Denial() || cc.OperationID != opID {
		t.Errorf("denial=%v op=%q", te.Denial(), cc.OperationID)
	}
	close(release)
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func TestLedgerStageClassifiesOutcomes(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		state string
		class string
	}{
		{"outcome unknown", fmt.Errorf("github: %w", connectors.ErrOutcomeUnknown), store.LedgerUnknown, "outcome_unknown"},
		{"deadline", fmt.Errorf("github: %w", context.DeadlineExceeded), store.LedgerUnknown, "timeout"},
		{"canceled", context.Canceled, store.LedgerUnknown, "canceled"},
		{"connection reset", fmt.Errorf("write: %w", syscall.ECONNRESET), store.LedgerUnknown, "connection_reset"},
		{"net timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, store.LedgerUnknown, "timeout"},
		{"vendor error", errors.New("422 validation failed"), store.LedgerFailed, "tool_error"},
		{"vendor rate limit", &connectors.RateLimited{App: "github", RetryAfter: 3 * time.Second}, store.LedgerFailed, "vendor_rate_limited"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t, nil)
			f.handler = func(context.Context, connectors.Call) (connectors.Result, error) { return connectors.Result{}, tc.err }
			cc, _, err := f.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web", "n": i})
			if err == nil {
				t.Fatal("expected the error to propagate")
			}
			row := f.st.Operation(cc.OperationID)
			if row == nil || row.State != tc.state || row.ErrorCode == nil || *row.ErrorCode != tc.class {
				t.Errorf("row = %+v", row)
			}
		})
	}
	// Refused by the limiter before dispatch: the row closes as failed so
	// the key is free for the retry.
	f := newLedgerFixture(t, nil)
	f.limiter.deny = true
	cc, _, err := f.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeRateLimited {
		t.Fatalf("err = %v", err)
	}
	if row := f.st.Operation(cc.OperationID); row.State != store.LedgerFailed || *row.ErrorCode != "rate_limited" {
		t.Errorf("row = %+v", row)
	}
	f.limiter.deny = false
	if _, _, err := f.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web"}); err != nil || f.callCount() != 1 {
		t.Errorf("retry after rate limit: err=%v calls=%d", err, f.callCount())
	}
}

func TestLedgerStageFinishesEvenWhenTheRequestContextIsCut(t *testing.T) {
	f := newLedgerFixture(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	f.handler = func(ctx context.Context, _ connectors.Call) (connectors.Result, error) {
		cancel() // the drain period elapsed mid-call
		<-ctx.Done()
		return connectors.Result{}, fmt.Errorf("%w: %w", connectors.ErrOutcomeUnknown, ctx.Err())
	}
	cc, _, err := f.run(t, ctx, "github.create_issue", map[string]any{"repo": "acme/web"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if row := f.st.Operation(cc.OperationID); row == nil || row.State != store.LedgerUnknown {
		t.Errorf("row = %+v", row)
	}
	if f.svc.InFlight() != 0 {
		t.Errorf("in flight = %d", f.svc.InFlight())
	}
}

func TestLedgerStageRefusesWritesWithoutAccountOrPolicy(t *testing.T) {
	f := newLedgerFixture(t, nil)
	// A tool nobody has an account for: the account stage refuses first,
	// so drive the stage directly with an unbound context.
	stage := mcp.LedgerStage(f.svc, nil)
	cc := &mcp.CallContext{Principal: &tokens.Principal{UserID: "user-1"}, Name: "github.create_issue"}
	tool := stubTool("github", "create_issue", connectors.KindWrite)
	cc.Tool = &tool
	cc.Call.Tool = tool.FullName()
	_, err := stage.Run(t.Context(), cc, func(context.Context) (connectors.Result, error) {
		t.Fatal("ran unbound")
		return connectors.Result{}, nil
	})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te.Code != mcp.CodeInternal || te.Class() != "ledger_unbound" {
		t.Errorf("err = %v", err)
	}
	if f.st.Count() != 0 {
		t.Errorf("rows = %d", f.st.Count())
	}
}

// deferredConfirm imitates the approvals handler in deferred mode: it
// resolves the approval id, passes it forward and leaves consumption to
// the ledger stage, which runs the stored arguments.
func deferredConfirm(id string) mcp.ConfirmHandler {
	return mcp.ConfirmHandlerFunc(func(ctx context.Context, cc *mcp.CallContext, next mcp.Next) (connectors.Result, error) {
		cc.ApprovalID, cc.Call.ApprovalID = id, id
		cc.Call.Args = map[string]any{}
		return next(ctx)
	})
}

func TestLedgerStageConsumesTheApprovalAndRunsTheStoredArguments(t *testing.T) {
	f := newLedgerFixture(t, deferredConfirm("ap-1"))
	f.consumer.args["ap-1"] = map[string]any{"repo": "acme/web", "title": "as approved"}
	cc, _, err := f.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web", "title": "as retried"})
	if err != nil {
		t.Fatal(err)
	}
	call := f.lastCall(t)
	if call.Args["title"] != "as approved" || call.ApprovalID != "ap-1" || call.OperationID != cc.OperationID {
		t.Errorf("call = %+v", call)
	}
	row := f.st.Operation(cc.OperationID)
	if row.IdempotencyKey != ledger.ApprovalKey("ap-1") || row.ApprovalID == nil || *row.ApprovalID != "ap-1" || !strings.Contains(string(row.Resource), "from-approval") {
		t.Errorf("row = %+v", row)
	}
	if cc.ApprovalID != "ap-1" {
		t.Errorf("cc.ApprovalID = %q", cc.ApprovalID)
	}
	// The same approval again: the consumer's error reaches the caller
	// unchanged (the confirm handler maps it), nothing runs.
	_, _, err = f.run(t, t.Context(), "github.create_issue", map[string]any{"repo": "acme/web", "title": "as retried"})
	if err == nil || !strings.Contains(err.Error(), "already used") || f.callCount() != 1 {
		t.Errorf("second: err=%v calls=%d", err, f.callCount())
	}
	// A confirmed read also goes through the ledger (the approval must be consumed).
	f2 := newLedgerFixture(t, deferredConfirm("ap-2"))
	f2.consumer.args["ap-2"] = map[string]any{"repo": "acme/web"}
	cc, _, err = f2.run(t, t.Context(), "github.list_issues", nil)
	if err != nil || cc.OperationID == "" || f2.st.Operation(cc.OperationID).State != store.LedgerSucceeded {
		t.Errorf("confirmed read: err=%v op=%q", err, cc.OperationID)
	}
}
