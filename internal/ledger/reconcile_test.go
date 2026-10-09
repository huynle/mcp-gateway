package ledger_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/store"
)

type memRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *memRecorder) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *memRecorder) forOperation(id string) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, ev := range r.events {
		if ev.OperationID == id {
			out = append(out, ev)
		}
	}
	return out
}

type memNotifier struct {
	mu  sync.Mutex
	ops []ledger.Operation
	err error
}

func (n *memNotifier) NotifyUnresolved(_ context.Context, op ledger.Operation) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ops = append(n.ops, op)
	return n.err
}

func (n *memNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.ops)
}

// reconcileFixture is the service over the fake connector's registry, so
// the reconciler calls the real create_item / flaky_write / post_note
// reconciliation declarations.
type reconcileFixture struct {
	*fixture
	fake     *fake.Connector
	reg      *connectors.Registry
	audit    *memRecorder
	notifier *memNotifier
}

func newReconcileFixture(t *testing.T) *reconcileFixture {
	t.Helper()
	f := newFixture(t)
	fc := fake.New(fake.Options{})
	fc.SeedAccount(alice, connectors.Account{ID: acctA, Label: connectors.LabelCompany, DisplayName: "Work"})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, fc, fc.Accounts()); err != nil {
		t.Fatal(err)
	}
	rf := &reconcileFixture{fixture: f, fake: fc, reg: reg, audit: &memRecorder{}, notifier: &memNotifier{}}
	cfg := ledger.DefaultConfig()
	cfg.BaseURL = "https://gw.example.com"
	svc, err := ledger.New(cfg, f.st, ledger.Options{
		Approvals: f.consumer, Registry: reg, Notifier: rf.notifier, Audit: rf.audit, Metrics: f.metrics, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time { return f.now })
	rf.svc = svc
	return rf
}

// unknownWrite runs tool through the fake with the given fault (applied
// or not), then records the unknown outcome on a fresh operation.
func (rf *reconcileFixture) unknownWrite(t *testing.T, tool string, args map[string]any, applied bool) *ledger.Operation {
	t.Helper()
	in := rf.intent(args)
	in.Tool = "fake." + tool
	resource := map[string]string{}
	if reg, ok := rf.reg.Get(in.Tool); ok && reg.ResourceIdentity != nil {
		resource = reg.ResourceIdentity(args)
	}
	in.ResourceIdentity = resource
	op := rf.begin(t, in)
	rf.fake.InjectFault(tool, fake.Fault{Mode: fake.FaultUnknown, Applied: applied, Remaining: 1})
	_, err := rf.fake.Call(t.Context(), connectors.Call{
		Principal: connectors.Principal{UserID: alice}, Tool: in.Tool, Account: acctA, OperationID: op.ID, Args: args,
	})
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Fatalf("fake call: err = %v, want ErrOutcomeUnknown", err)
	}
	if _, err := rf.svc.Finish(t.Context(), alice, op.ID, ledger.Unknown("outcome_unknown")); err != nil {
		t.Fatal(err)
	}
	return op
}

func TestReconcileResolvesAReconcilableWriteThroughCheck(t *testing.T) {
	rf := newReconcileFixture(t)
	applied := rf.unknownWrite(t, "create_item", map[string]any{"id": "it-applied", "name": "n"}, true)
	lost := rf.unknownWrite(t, "create_item", map[string]any{"id": "it-lost", "name": "n"}, false)
	derived := rf.unknownWrite(t, "flaky_write", map[string]any{"payload": "p"}, true) // marker = operation id

	// Not due yet: the first check waits 2^0 minutes after the row turned unknown.
	stats, err := rf.svc.Reconcile(t.Context())
	if err != nil || stats.Checked != 0 || stats.Skipped != 3 {
		t.Fatalf("too early: stats=%+v err=%v", stats, err)
	}
	rf.now = rf.now.Add(time.Minute)
	stats, err = rf.svc.Reconcile(t.Context())
	if err != nil || stats.Checked != 3 || stats.Succeeded != 2 || stats.Failed != 1 || stats.Unresolved != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	got, _ := rf.svc.Get(t.Context(), alice, applied.ID)
	if got.State != ledger.StateSucceeded || got.ResultIDs["id"] != "it-applied" || got.ReconcileAttempts != 1 || got.FinishedAt == nil {
		t.Errorf("applied = %+v", got)
	}
	got, _ = rf.svc.Get(t.Context(), alice, lost.ID)
	if got.State != ledger.StateFailed || got.ErrorClass != "not_found" || got.FinishedAt == nil {
		t.Errorf("lost = %+v", got)
	}
	got, _ = rf.svc.Get(t.Context(), alice, derived.ID)
	if got.State != ledger.StateSucceeded || got.ResultIDs["id"] != derived.ID {
		t.Errorf("derived marker = %+v", got)
	}
	atts := rf.st.Attempts(applied.ID)
	if len(atts) != 2 || atts[1].Kind != store.AttemptReconcile || atts[1].AttemptNo != 1 || atts[1].Outcome != "found" {
		t.Errorf("attempts = %+v", atts)
	}
	if evs := rf.audit.forOperation(applied.ID); len(evs) != 1 || evs[0].Outcome != "succeeded" || evs[0].UserID != alice || evs[0].Tool != "fake.create_item" || evs[0].AccountID != acctA || evs[0].ErrorClass != "reconciled" {
		t.Errorf("audit for applied = %+v", evs)
	}
	if evs := rf.audit.forOperation(lost.ID); len(evs) != 1 || evs[0].Outcome != "failed" || evs[0].ErrorClass != "not_found" {
		t.Errorf("audit for lost = %+v", evs)
	}
	if rf.notifier.count() != 0 {
		t.Errorf("resolved operations must not notify: %d", rf.notifier.count())
	}
	if ledgerCounter(t, rf.metrics, "succeeded") != 2 || ledgerCounter(t, rf.metrics, "failed") != 1 {
		t.Error("metrics not counted")
	}
	// Resolved operations are not looked at again; the succeeded one now
	// replays for the same arguments.
	if stats, _ := rf.svc.Reconcile(t.Context()); stats.Checked != 0 {
		t.Errorf("second run checked %d", stats.Checked)
	}
	in := rf.intent(map[string]any{"id": "it-applied", "name": "n"})
	if _, prior, err := rf.svc.Begin(t.Context(), in); err != nil || prior.Kind != ledger.PriorReplay {
		t.Errorf("replay after reconcile: prior=%+v err=%v", prior, err)
	}
}

func TestReconcileMarksNonReconcilableUnresolvedAtOnceAndLiftsTheBlock(t *testing.T) {
	rf := newReconcileFixture(t)
	args := map[string]any{"text": "hello"}
	op := rf.unknownWrite(t, "post_note", args, true)
	in := rf.intent(args)
	in.Tool = "fake.post_note"
	if _, prior, err := rf.svc.Begin(t.Context(), in); err != nil || prior.Kind != ledger.PriorPending {
		t.Fatalf("before reconcile: prior=%+v err=%v", prior, err)
	}
	stats, err := rf.svc.Reconcile(t.Context())
	if err != nil || stats.Unresolved != 1 || stats.Checked != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	got, _ := rf.svc.Get(t.Context(), alice, op.ID)
	if got.State != ledger.StateUnresolved || got.ErrorClass != "not_reconcilable" || got.FinishedAt == nil {
		t.Errorf("op = %+v", got)
	}
	if rf.notifier.count() != 1 || rf.notifier.ops[0].ID != op.ID || rf.notifier.ops[0].Tool != "fake.post_note" {
		t.Errorf("notified = %+v", rf.notifier.ops)
	}
	if evs := rf.audit.forOperation(op.ID); len(evs) != 1 || evs[0].Outcome != "unresolved" || evs[0].ErrorClass != "not_reconcilable" {
		t.Errorf("audit = %+v", evs)
	}
	if ledgerCounter(t, rf.metrics, "unresolved") != 1 {
		t.Error("unresolved not counted")
	}
	// The block is lifted: the same arguments start a new operation.
	next := rf.begin(t, in)
	if next.ID == op.ID {
		t.Error("unresolved must not block")
	}
	// A notifier failure is logged, not fatal: the row is still unresolved.
	rf.notifier.err = errors.New("slack down")
	op2 := rf.unknownWrite(t, "post_note", map[string]any{"text": "again"}, true)
	if stats, err := rf.svc.Reconcile(t.Context()); err != nil || stats.Unresolved != 1 {
		t.Errorf("with failing notifier: stats=%+v err=%v", stats, err)
	}
	if got, _ := rf.svc.Get(t.Context(), alice, op2.ID); got.State != ledger.StateUnresolved {
		t.Errorf("op2 = %+v", got)
	}
}

func TestReconcileBacksOffRetriesErrorsAndGivesUp(t *testing.T) {
	rf := newReconcileFixture(t)
	// A tool nobody registered any more: unresolved at once.
	orphan := rf.begin(t, func() ledger.Intent { in := rf.intent(map[string]any{"a": 1}); in.Tool = "gone.write"; return in }())
	if _, err := rf.svc.Finish(t.Context(), alice, orphan.ID, ledger.Unknown("outcome_unknown")); err != nil {
		t.Fatal(err)
	}
	// The fake's Checks answer found / not_found; drive the retry path
	// with a tool whose Check errs ("cannot tell yet").
	errTool := connectors.Tool{
		App: "fake", Name: "erring_write", Description: "errs on check", Kind: connectors.KindWrite,
		InputSchema:      []byte(`{"type":"object"}`),
		ResourceIdentity: func(map[string]any) map[string]string { return nil },
		Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
			return connectors.ReconcileResult{}, errors.New("vendor unreachable")
		}},
		Handler: func(context.Context, connectors.Call) (connectors.Result, error) { return connectors.Result{}, nil },
	}
	if err := rf.reg.Register(errTool); err != nil {
		t.Fatal(err)
	}
	in := rf.intent(map[string]any{"b": 2})
	in.Tool = "fake.erring_write"
	flaky := rf.begin(t, in)
	if _, err := rf.svc.Finish(t.Context(), alice, flaky.ID, ledger.Unknown("outcome_unknown")); err != nil {
		t.Fatal(err)
	}
	stats, err := rf.svc.Reconcile(t.Context())
	if err != nil || stats.Unresolved != 1 || stats.Skipped != 1 {
		t.Fatalf("first run: stats=%+v err=%v", stats, err)
	}
	if got, _ := rf.svc.Get(t.Context(), alice, orphan.ID); got.State != ledger.StateUnresolved || got.ErrorClass != "not_reconcilable" {
		t.Errorf("orphan = %+v", got)
	}
	// Attempt n is due 2^(n-1) minutes after the previous one: 1, 2, 4, 8, 16, 32.
	wait := time.Minute
	for attempt := 1; attempt <= rf.svc.Config().MaxReconcileAttempts; attempt++ {
		rf.now = rf.now.Add(wait - time.Second)
		if stats, _ := rf.svc.Reconcile(t.Context()); stats.Checked != 0 {
			t.Fatalf("attempt %d ran early (after %v)", attempt, wait-time.Second)
		}
		rf.now = rf.now.Add(time.Second)
		stats, err := rf.svc.Reconcile(t.Context())
		if err != nil || stats.Checked != 1 {
			t.Fatalf("attempt %d: stats=%+v err=%v", attempt, stats, err)
		}
		got, _ := rf.svc.Get(t.Context(), alice, flaky.ID)
		if got.ReconcileAttempts != attempt {
			t.Fatalf("attempt %d: attempts = %d", attempt, got.ReconcileAttempts)
		}
		if attempt < rf.svc.Config().MaxReconcileAttempts {
			if got.State != ledger.StateUnknown || stats.Retried != 1 {
				t.Fatalf("attempt %d: state %s stats %+v", attempt, got.State, stats)
			}
		} else if got.State != ledger.StateUnresolved || got.ErrorClass != "reconcile_exhausted" || stats.Unresolved != 1 {
			t.Fatalf("after %d attempts: state %s class %s stats %+v", attempt, got.State, got.ErrorClass, stats)
		}
		wait *= 2
	}
	atts := rf.st.Attempts(flaky.ID)
	if len(atts) != 1+rf.svc.Config().MaxReconcileAttempts || atts[1].Outcome != "error" || atts[1].ErrorCode == nil {
		t.Errorf("attempts = %d: %+v", len(atts), atts)
	}
	if rf.notifier.count() != 2 {
		t.Errorf("notified %d, want orphan + exhausted", rf.notifier.count())
	}

	// Max age: an unknown operation older than MaxReconcileAge is unresolved
	// even with attempts left.
	old := rf.unknownWrite(t, "create_item", map[string]any{"id": "it-old", "name": "n"}, false)
	rf.st.SetCreatedAt(old.ID, rf.now.Add(-rf.svc.Config().MaxReconcileAge-time.Minute))
	if stats, err := rf.svc.Reconcile(t.Context()); err != nil || stats.Unresolved != 1 {
		t.Fatalf("aged: stats=%+v err=%v", stats, err)
	}
	if got, _ := rf.svc.Get(t.Context(), alice, old.ID); got.State != ledger.StateUnresolved || got.ErrorClass != "reconcile_expired" {
		t.Errorf("aged = %+v", got)
	}
}

func TestSweepStaleTurnsAbandonedInProgressIntoUnknown(t *testing.T) {
	rf := newReconcileFixture(t)
	abandoned := rf.begin(t, rf.intent(map[string]any{"id": "a"}))
	live := rf.begin(t, rf.intent(map[string]any{"id": "b"}))
	rf.now = rf.now.Add(rf.svc.Config().StaleAfter + time.Second)
	rf.st.SetCreatedAt(live.ID, rf.now) // a call that just started
	n, err := rf.svc.SweepStale(t.Context())
	if err != nil || n != 1 {
		t.Fatalf("sweep = %d, %v", n, err)
	}
	if got, _ := rf.svc.Get(t.Context(), alice, abandoned.ID); got.State != ledger.StateUnknown || got.ErrorClass != "stale" {
		t.Errorf("abandoned = %+v", got)
	}
	if got, _ := rf.svc.Get(t.Context(), alice, live.ID); got.State != ledger.StateInProgress {
		t.Errorf("live = %+v", got)
	}
	if ledgerCounter(t, rf.metrics, "unknown") != 1 {
		t.Error("unknown not counted")
	}
	// The swept operation is then reconciled like any other unknown one
	// (create_item "a" never ran in the fake: not found -> failed).
	rf.now = rf.now.Add(time.Minute)
	if stats, err := rf.svc.Reconcile(t.Context()); err != nil || stats.Failed != 1 {
		t.Errorf("reconcile swept: stats=%+v err=%v", stats, err)
	}
	if _, err := rf.svc.Finish(t.Context(), alice, live.ID, ledger.Succeeded(map[string]string{"id": "b"})); err != nil {
		t.Fatal(err)
	}
	// A late Finish from the replica that was only slow, not dead, still
	// lands while the row is unknown.
	slow := rf.begin(t, rf.intent(map[string]any{"id": "c"}))
	rf.now = rf.now.Add(rf.svc.Config().StaleAfter + time.Second)
	if n, _ := rf.svc.SweepStale(t.Context()); n != 1 {
		t.Fatalf("sweep slow = %d", n)
	}
	if got, err := rf.svc.Finish(t.Context(), alice, slow.ID, ledger.Succeeded(map[string]string{"id": "c"})); err != nil || got.State != ledger.StateSucceeded {
		t.Errorf("late finish = %+v, %v", got, err)
	}
}

func TestShutdownMarksThisReplicasInFlightOperationsUnknown(t *testing.T) {
	rf := newReconcileFixture(t)
	cut := rf.begin(t, rf.intent(map[string]any{"id": "cut"}))
	done := rf.begin(t, rf.intent(map[string]any{"id": "done"}))
	if _, err := rf.svc.Finish(t.Context(), alice, done.ID, ledger.Succeeded(nil)); err != nil {
		t.Fatal(err)
	}
	// Another replica's operation (not tracked here) is left alone.
	other := rf.begin(t, rf.intent(map[string]any{"id": "other"}))
	rf.svc.Forget(other.ID)

	if n := rf.svc.InFlight(); n != 1 {
		t.Fatalf("in flight = %d, want 1", n)
	}
	n, err := rf.svc.Shutdown(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("shutdown = %d, %v", n, err)
	}
	if got, _ := rf.svc.Get(t.Context(), alice, cut.ID); got.State != ledger.StateUnknown || got.ErrorClass != "shutdown" {
		t.Errorf("cut = %+v", got)
	}
	if got, _ := rf.svc.Get(t.Context(), alice, done.ID); got.State != ledger.StateSucceeded {
		t.Errorf("done = %+v", got)
	}
	if got, _ := rf.svc.Get(t.Context(), alice, other.ID); got.State != ledger.StateInProgress {
		t.Errorf("other replica's = %+v", got)
	}
	if rf.svc.InFlight() != 0 {
		t.Errorf("in flight after shutdown = %d", rf.svc.InFlight())
	}
}
