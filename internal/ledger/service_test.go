package ledger_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/ledger/ledgertest"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	alice    = "11111111-1111-4111-8111-111111111111"
	bob      = "22222222-2222-4222-8222-222222222222"
	acctA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	policyV1 = "99999999-9999-4999-8999-999999999999"
	tokenID  = "77777777-7777-4777-8777-777777777777"
)

var errConsumed = errors.New("approvals: approval already used")

// fakeConsumer stands in for the approvals service: it hands out stored
// arguments once per approval id and remembers which Tx it was called
// with, so the test can assert the consume ran inside Begin's transaction.
type fakeConsumer struct {
	args     map[string]map[string]any
	fail     error
	consumed []string
	lastTx   ledger.Tx
	bindings []ledger.ApprovalBinding
}

func (f *fakeConsumer) Consume(_ context.Context, tx ledger.Tx, b ledger.ApprovalBinding) (*ledger.ConsumedApproval, error) {
	f.lastTx = tx
	f.bindings = append(f.bindings, b)
	if f.fail != nil {
		return nil, f.fail
	}
	args, ok := f.args[b.ApprovalID]
	if !ok {
		return nil, errConsumed
	}
	delete(f.args, b.ApprovalID)
	f.consumed = append(f.consumed, b.ApprovalID)
	return &ledger.ConsumedApproval{ID: b.ApprovalID, Args: args}, nil
}

type fixture struct {
	st       *ledgertest.MemStore
	svc      *ledger.Service
	consumer *fakeConsumer
	metrics  *observability.Metrics
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{st: ledgertest.NewMemStore(), consumer: &fakeConsumer{args: map[string]map[string]any{}}, metrics: observability.NewMetrics()}
	f.now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := ledger.DefaultConfig()
	cfg.BaseURL = "https://gw.example.com"
	svc, err := ledger.New(cfg, f.st, ledger.Options{Approvals: f.consumer, Metrics: f.metrics, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time { return f.now })
	f.svc = svc
	return f
}

func (f *fixture) intent(args map[string]any) ledger.Intent {
	return ledger.Intent{
		UserID: alice, TokenID: tokenID, AccountID: acctA, Tool: "fake.create_item",
		Digest: ledger.Digest(args), PolicyVersionID: policyV1,
		ResourceIdentity: map[string]string{"id": "it-1"},
	}
}

func (f *fixture) begin(t *testing.T, in ledger.Intent) *ledger.Operation {
	t.Helper()
	op, prior, err := f.svc.Begin(t.Context(), in)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if prior.Kind != ledger.PriorNone || op == nil {
		t.Fatalf("Begin: prior = %+v, op = %+v; want a new operation", prior, op)
	}
	return op
}

func TestBeginInsertsInProgressBeforeTheCall(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"id": "it-1", "name": "first"}
	op := f.begin(t, f.intent(args))
	if op.ID == "" || op.State != ledger.StateInProgress || op.UserID != alice || op.AccountID != acctA || op.Tool != "fake.create_item" || op.TokenID != tokenID || op.PolicyVersionID != policyV1 {
		t.Errorf("op = %+v", op)
	}
	if op.Key != ledger.DigestKey(alice, acctA, "fake.create_item", ledger.Digest(args)) {
		t.Errorf("key = %q", op.Key)
	}
	if op.ApprovalID != "" || op.ApprovalArgs != nil {
		t.Errorf("unconfirmed write carries approval data: %+v", op)
	}
	if op.ResourceIdentity["id"] != "it-1" || !op.CreatedAt.Equal(f.now) {
		t.Errorf("resource/created = %v %v", op.ResourceIdentity, op.CreatedAt)
	}
	row := f.st.Operation(op.ID)
	if row == nil || row.State != store.LedgerInProgress || row.IdempotencyKey != op.Key || !row.WindowEnd.Equal(f.now.Add(24*time.Hour)) {
		t.Errorf("stored row = %+v", row)
	}
	if n := f.st.Attempts(op.ID); len(n) != 0 {
		t.Errorf("attempts before finish = %d", len(n))
	}
	if got := ledgerCounter(t, f.metrics, "in_progress"); got != 1 {
		t.Errorf("ledger_operations_total{in_progress} = %v", got)
	}
}

func TestBeginValidatesTheIntent(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(*ledger.Intent){
		"user":    func(in *ledger.Intent) { in.UserID = "" },
		"account": func(in *ledger.Intent) { in.AccountID = "" },
		"tool":    func(in *ledger.Intent) { in.Tool = "" },
		"policy":  func(in *ledger.Intent) { in.PolicyVersionID = "" },
		"digest":  func(in *ledger.Intent) { in.Digest = nil },
	} {
		in := f.intent(map[string]any{"x": 1})
		mutate(&in)
		if _, _, err := f.svc.Begin(t.Context(), in); !errors.Is(err, ledger.ErrInvalid) {
			t.Errorf("%s missing: err = %v, want ErrInvalid", name, err)
		}
	}
	if f.st.Count() != 0 {
		t.Errorf("invalid intents inserted %d rows", f.st.Count())
	}
}

func TestFinishRecordsOutcomeAndAttempt(t *testing.T) {
	f := newFixture(t)
	op := f.begin(t, f.intent(map[string]any{"id": "it-1", "name": "n"}))
	f.now = f.now.Add(3 * time.Second)
	done, err := f.svc.Finish(t.Context(), alice, op.ID, ledger.Succeeded(map[string]string{"id": "it-1", "": "dropped", "body": strings.Repeat("x", 600)}))
	if err != nil {
		t.Fatal(err)
	}
	if done.State != ledger.StateSucceeded || len(done.ResultIDs) != 1 || done.ResultIDs["id"] != "it-1" || done.FinishedAt == nil || !done.FinishedAt.Equal(f.now) {
		t.Errorf("finished = %+v", done)
	}
	atts := f.st.Attempts(op.ID)
	if len(atts) != 1 || atts[0].Kind != store.AttemptCall || atts[0].AttemptNo != 1 || atts[0].Outcome != store.LedgerSucceeded || !atts[0].StartedAt.Equal(op.CreatedAt) || atts[0].FinishedAt == nil {
		t.Errorf("attempts = %+v", atts)
	}
	if got := ledgerCounter(t, f.metrics, "succeeded"); got != 1 {
		t.Errorf("succeeded counter = %v", got)
	}
	// A finished operation cannot be finished again.
	if _, err := f.svc.Finish(t.Context(), alice, op.ID, ledger.Failed("tool_error")); !errors.Is(err, ledger.ErrNotOpen) {
		t.Errorf("second finish: err = %v, want ErrNotOpen", err)
	}
	// Someone else's operation is not found.
	if _, err := f.svc.Finish(t.Context(), bob, op.ID, ledger.Failed("tool_error")); !errors.Is(err, ledger.ErrNotFound) {
		t.Errorf("bob finishes alice's op: err = %v, want ErrNotFound", err)
	}

	failed := f.begin(t, f.intent(map[string]any{"id": "it-2", "name": "n"}))
	done, err = f.svc.Finish(t.Context(), alice, failed.ID, ledger.Failed("tool_error"))
	if err != nil || done.State != ledger.StateFailed || done.ErrorClass != "tool_error" || done.FinishedAt == nil {
		t.Errorf("failed = %+v, %v", done, err)
	}
	unknown := f.begin(t, f.intent(map[string]any{"id": "it-3", "name": "n"}))
	done, err = f.svc.Finish(t.Context(), alice, unknown.ID, ledger.Unknown("outcome_unknown"))
	if err != nil || done.State != ledger.StateUnknown || done.ErrorClass != "outcome_unknown" || done.FinishedAt != nil {
		t.Errorf("unknown = %+v, %v (finished_at must stay empty: the reconciler owns it)", done, err)
	}
	if atts := f.st.Attempts(unknown.ID); len(atts) != 1 || atts[0].Outcome != store.LedgerUnknown || atts[0].ErrorCode == nil || *atts[0].ErrorCode != "outcome_unknown" {
		t.Errorf("unknown attempts = %+v", atts)
	}
	if _, err := f.svc.Finish(t.Context(), alice, op.ID, ledger.Outcome{State: "bogus"}); !errors.Is(err, ledger.ErrInvalid) {
		t.Errorf("bogus outcome: err = %v", err)
	}
}

func TestBeginReplaysASucceededWriteInsideTheWindowOnly(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"id": "it-1", "name": "first"}
	first := f.begin(t, f.intent(args))
	if _, err := f.svc.Finish(t.Context(), alice, first.ID, ledger.Succeeded(map[string]string{"id": "it-1"})); err != nil {
		t.Fatal(err)
	}
	// Same arguments, same user/account/tool, 23 hours later: replay.
	f.now = f.now.Add(23 * time.Hour)
	op, prior, err := f.svc.Begin(t.Context(), f.intent(args))
	if err != nil || op != nil || prior.Kind != ledger.PriorReplay || prior.Operation == nil || prior.Operation.ID != first.ID || prior.Operation.ResultIDs["id"] != "it-1" {
		t.Errorf("inside window: op=%+v prior=%+v err=%v", op, prior, err)
	}
	if f.st.Count() != 1 {
		t.Errorf("replay inserted a row: %d", f.st.Count())
	}
	// Different arguments: a new operation.
	f.begin(t, f.intent(map[string]any{"id": "it-1", "name": "second"}))
	// Another account or user with the same arguments: a new operation.
	other := f.intent(args)
	other.AccountID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	f.begin(t, other)
	// Past the window: a new operation.
	f.now = f.now.Add(2 * time.Hour)
	again := f.begin(t, f.intent(args))
	if again.ID == first.ID {
		t.Error("outside the window the same arguments must be a new operation")
	}
}

func TestBeginReportsPendingVerificationWhilePriorIsOpen(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"id": "it-1", "name": "first"}
	first := f.begin(t, f.intent(args))
	op, prior, err := f.svc.Begin(t.Context(), f.intent(args))
	if err != nil || op != nil || prior.Kind != ledger.PriorPending || prior.Operation == nil || prior.Operation.ID != first.ID {
		t.Errorf("while in_progress: op=%+v prior=%+v err=%v", op, prior, err)
	}
	if _, err := f.svc.Finish(t.Context(), alice, first.ID, ledger.Unknown("outcome_unknown")); err != nil {
		t.Fatal(err)
	}
	_, prior, err = f.svc.Begin(t.Context(), f.intent(args))
	if err != nil || prior.Kind != ledger.PriorPending || prior.Operation.State != ledger.StateUnknown {
		t.Errorf("while unknown: prior=%+v err=%v", prior, err)
	}
	if f.st.Count() != 1 {
		t.Errorf("pending verification inserted rows: %d", f.st.Count())
	}
}

func TestBeginAfterFailedOrUnresolvedStartsANewOperation(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"id": "it-1", "name": "first"}
	first := f.begin(t, f.intent(args))
	if _, err := f.svc.Finish(t.Context(), alice, first.ID, ledger.Failed("tool_error")); err != nil {
		t.Fatal(err)
	}
	second := f.begin(t, f.intent(args))
	if second.ID == first.ID {
		t.Fatal("failed prior must not block")
	}
	// unresolved (what the reconciler sets): the block is lifted.
	f.st.SetState(second.ID, store.LedgerUnresolved)
	third := f.begin(t, f.intent(args))
	if third.ID == second.ID || third.State != ledger.StateInProgress {
		t.Errorf("unresolved prior must not block: %+v", third)
	}
}

func TestBeginWithApprovalConsumesItInTheSameTransaction(t *testing.T) {
	f := newFixture(t)
	stored := map[string]any{"id": "it-1", "name": "as approved"}
	f.consumer.args["ap-1"] = stored
	in := f.intent(map[string]any{"id": "it-1", "name": "as retried"})
	in.ApprovalID = "ap-1"
	op := f.begin(t, in)
	if op.Key != ledger.ApprovalKey("ap-1") || op.ApprovalID != "ap-1" || op.ApprovalArgs["name"] != "as approved" {
		t.Errorf("op = %+v", op)
	}
	if f.consumer.lastTx == nil || len(f.consumer.bindings) != 1 {
		t.Fatalf("consumer not called inside a transaction: %+v", f.consumer)
	}
	b := f.consumer.bindings[0]
	if b.UserID != alice || b.AccountID != acctA || b.Tool != "fake.create_item" || b.PolicyVersionID != policyV1 || b.ApprovalID != "ap-1" {
		t.Errorf("binding = %+v", b)
	}
	if row := f.st.Operation(op.ID); row == nil || row.ApprovalID == nil || *row.ApprovalID != "ap-1" {
		t.Errorf("stored row = %+v", row)
	}
	// The same approval again, even with the same digest: the consume
	// refuses and nothing is inserted.
	_, _, err := f.svc.Begin(t.Context(), in)
	if !errors.Is(err, errConsumed) {
		t.Errorf("second begin: err = %v, want the consumer's error", err)
	}
	if f.st.Count() != 1 {
		t.Errorf("rows = %d", f.st.Count())
	}
	// Without an approvals service an approval cannot be consumed.
	svc, err := ledger.New(ledger.DefaultConfig(), f.st, ledger.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Begin(t.Context(), in); !errors.Is(err, ledger.ErrApprovalsUnavailable) {
		t.Errorf("no consumer: err = %v", err)
	}
}

func TestBeginRollsBackTheConsumeWhenTheInsertFails(t *testing.T) {
	f := newFixture(t)
	f.consumer.args["ap-2"] = map[string]any{"id": "it-2", "name": "n"}
	in := f.intent(map[string]any{"id": "it-2", "name": "n"})
	in.ApprovalID = "ap-2"
	f.st.FailNextCreate(errors.New("boom"))
	if _, _, err := f.svc.Begin(t.Context(), in); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	if f.st.Count() != 0 || f.st.Rollbacks() != 1 {
		t.Errorf("rows = %d rollbacks = %d", f.st.Count(), f.st.Rollbacks())
	}
}

func TestOperationsListsTheUsersRecentOnes(t *testing.T) {
	f := newFixture(t)
	a := f.begin(t, f.intent(map[string]any{"id": "a"}))
	f.now = f.now.Add(time.Second)
	b := f.begin(t, f.intent(map[string]any{"id": "b"}))
	other := f.intent(map[string]any{"id": "c"})
	other.UserID = bob
	f.begin(t, other)
	list, err := f.svc.Operations(t.Context(), alice, 10)
	if err != nil || len(list) != 2 || list[0].ID != b.ID || list[1].ID != a.ID {
		t.Errorf("operations = %+v, %v", list, err)
	}
	if list, err := f.svc.Operations(t.Context(), alice, 1); err != nil || len(list) != 1 {
		t.Errorf("limited = %+v, %v", list, err)
	}
}

// ledgerCounter reads ledger_operations_total{state} from the private registry.
func ledgerCounter(t *testing.T, m *observability.Metrics, state string) float64 {
	const name = "ledger_operations_total"
	label := state
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		for _, metric := range fam.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetValue() == label {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// A per-call intent (tools whose upstream owns idempotency, e.g. user-added
// MCP servers) is recorded under a key unique to the operation: identical
// arguments never replay or wait on an earlier operation (quirk 47ab9sk7).
func TestBeginPerCallNeverReplaysOrWaits(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"path": "m5bgl1ye"}
	in := f.intent(args)
	in.PerCall = true
	first := f.begin(t, in)
	if !strings.HasPrefix(first.Key, "call:") || first.Key == ledger.DigestKey(alice, acctA, in.Tool, in.Digest) {
		t.Errorf("per-call key = %q", first.Key)
	}
	// While the first is still in_progress: a new operation, not pending.
	second := f.begin(t, in)
	if second.ID == first.ID || second.Key == first.Key {
		t.Errorf("concurrent identical per-call intents share an operation: %+v %+v", first, second)
	}
	for _, op := range []*ledger.Operation{first, second} {
		if _, err := f.svc.Finish(t.Context(), alice, op.ID, ledger.Succeeded(nil)); err != nil {
			t.Fatal(err)
		}
	}
	// After a success inside the window: still a new operation.
	f.now = f.now.Add(time.Hour)
	third := f.begin(t, in)
	if third.ID == first.ID || third.ID == second.ID {
		t.Error("a per-call intent replayed a prior operation")
	}
	if f.st.Count() != 3 {
		t.Errorf("rows = %d, want 3", f.st.Count())
	}
}

// An approval still keys the operation by the approval id, per-call or not:
// an approval executes at most once.
func TestBeginPerCallWithApprovalUsesTheApprovalKey(t *testing.T) {
	f := newFixture(t)
	f.consumer.args["appr-1"] = map[string]any{"path": "x"}
	in := f.intent(map[string]any{"path": "x"})
	in.PerCall = true
	in.ApprovalID = "appr-1"
	op := f.begin(t, in)
	if op.Key != ledger.ApprovalKey("appr-1") {
		t.Errorf("key = %q, want the approval key", op.Key)
	}
}

// A replayed prior carries the end of its idempotency window, so the
// replay answer can say when the same arguments run again.
func TestBeginReplayCarriesTheWindowEnd(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"id": "it-1"}
	first := f.begin(t, f.intent(args))
	if !first.WindowEnd.Equal(f.now.Add(24 * time.Hour)) {
		t.Errorf("window end = %v", first.WindowEnd)
	}
	if _, err := f.svc.Finish(t.Context(), alice, first.ID, ledger.Succeeded(nil)); err != nil {
		t.Fatal(err)
	}
	_, prior, err := f.svc.Begin(t.Context(), f.intent(args))
	if err != nil || prior.Kind != ledger.PriorReplay || !prior.Operation.WindowEnd.Equal(first.WindowEnd) {
		t.Errorf("prior = %+v err = %v", prior, err)
	}
}
