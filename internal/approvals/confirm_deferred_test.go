package approvals_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/ledger/ledgertest"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

// memConsumer is the ledger.ApprovalConsumer for the in-memory stores:
// the real consume semantics (binding, single use, state errors) through
// the approvals service, just not in the ledger's transaction (the
// PostgreSQL adapter, Service.LedgerConsumer, is exercised by the
// integration suite).
type memConsumer struct{ svc *approvals.Service }

func (c memConsumer) Consume(ctx context.Context, _ ledger.Tx, b ledger.ApprovalBinding) (*ledger.ConsumedApproval, error) {
	consumed, err := c.svc.ConsumeNow(ctx, approvals.Binding{
		UserID: b.UserID, AccountID: b.AccountID, Tool: b.Tool, PolicyVersionID: b.PolicyVersionID, ApprovalID: b.ApprovalID,
	})
	if err != nil {
		return nil, err
	}
	return &ledger.ConsumedApproval{ID: consumed.ID, Args: consumed.Args}, nil
}

// newDeferredPipeline is newPipeline plus the ledger stage, with the
// confirm handler leaving consumption to the ledger.
func newDeferredPipeline(t *testing.T, wait time.Duration) (*pipelineFixture, *ledgertest.MemStore) {
	t.Helper()
	p := newPipeline(t, wait)
	lst := ledgertest.NewMemStore()
	lsvc, err := ledger.New(ledger.DefaultConfig(), lst, ledger.Options{Approvals: memConsumer{p.svc}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.pipeline.Insert(mcp.Before, mcp.StageRateLimit, mcp.LedgerStage(lsvc, slog.New(slog.DiscardHandler))); err != nil {
		t.Fatal(err)
	}
	p.confirm.DeferConsumption(true)
	return p, lst
}

func TestDeferredRetryWithApprovalIDConsumesThroughTheLedger(t *testing.T) {
	p, lst := newDeferredPipeline(t, 0)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "body": "the original body"})
	te := toolErr(t, err)
	if te.Code != mcp.CodeApprovalRequired {
		t.Fatalf("first call = %d %q", te.Code, te.Message)
	}
	id := te.Data["approval_id"].(string)
	if lst.Count() != 0 || len(p.fake.State().Items(acctA)) != 0 {
		t.Fatalf("approval required must not touch the ledger or the app: rows=%d items=%d", lst.Count(), len(p.fake.State().Items(acctA)))
	}
	if _, err := p.svc.Approve(t.Context(), alice, id); err != nil {
		t.Fatal(err)
	}
	cc, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first (reworded)", "body": "a different body", "approval_id": id})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	items := p.fake.State().Items(acctA)
	if len(items) != 1 || items[0].Name != "first" || items[0].Body != "the original body" || items[0].OperationID != cc.OperationID {
		t.Errorf("the connector did not receive the stored arguments under the operation: %+v (op %s)", items, cc.OperationID)
	}
	if cc.ApprovalID != id || cc.Call.Args["name"] != "first" || cc.OperationID == "" {
		t.Errorf("cc = approval %q args %v op %q", cc.ApprovalID, cc.Call.Args, cc.OperationID)
	}
	row := lst.Operation(cc.OperationID)
	if row == nil || row.IdempotencyKey != ledger.ApprovalKey(id) || row.ApprovalID == nil || *row.ApprovalID != id || row.State != store.LedgerSucceeded {
		t.Errorf("ledger row = %+v", row)
	}
	if rec := p.st.Record(id); rec.Status != approvals.StatusConsumed || rec.Payload != nil {
		t.Errorf("approval after the call: %+v", rec)
	}
	// Second use, identical digest: refused through the ledger's consume,
	// nothing runs, no new row.
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "body": "the original body", "approval_id": id})
	te = toolErr(t, err)
	if te.Code != mcp.CodeDenied || te.Class() != "approval_used" || !strings.Contains(te.Message, "already used") {
		t.Errorf("second use = %d %q class %s", te.Code, te.Message, te.Class())
	}
	if len(p.fake.State().Items(acctA)) != 1 || lst.Count() != 1 {
		t.Errorf("second use ran: items=%d rows=%d", len(p.fake.State().Items(acctA)), lst.Count())
	}
}

func TestDeferredMismatchedAndUnknownApprovalsAreDeniedBeforeTheLedger(t *testing.T) {
	p, lst := newDeferredPipeline(t, 0)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first"})
	id := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Approve(t.Context(), alice, id); err != nil {
		t.Fatal(err)
	}
	// Unknown id.
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": "00000000-0000-4000-8000-000000000000"})
	if te := toolErr(t, err); te.Code != mcp.CodeDenied || te.Class() != "approval_mismatch" {
		t.Errorf("unknown id = %d %s", te.Code, te.Class())
	}
	// Another tool with the same approval: the binding does not match.
	_, _, err = p.call(t, "fake.post_note", map[string]any{"text": "x", "approval_id": id})
	if te := toolErr(t, err); te.Code != mcp.CodeDenied || te.Class() != "approval_mismatch" {
		t.Errorf("other tool = %d %s", te.Code, te.Class())
	}
	// A policy change after the approval: mismatch too.
	p.decider.versionID = policyV2
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": id})
	if te := toolErr(t, err); te.Code != mcp.CodeDenied || te.Class() != "approval_mismatch" {
		t.Errorf("policy change = %d %s", te.Code, te.Class())
	}
	if lst.Count() != 0 || len(p.fake.State().Items(acctA)) != 0 {
		t.Errorf("refusals touched the ledger or the app: rows=%d items=%d", lst.Count(), len(p.fake.State().Items(acctA)))
	}
	if rec := p.st.Record(id); rec.Status != approvals.StatusApproved {
		t.Errorf("approval must stay approved after refusals: %s", rec.Status)
	}
}

func TestDeferredRetryWithoutIDMatchesAnApprovedDigest(t *testing.T) {
	p, lst := newDeferredPipeline(t, 0)
	args := map[string]any{"id": "it-1", "name": "first", "tags": []any{"x"}}
	_, _, err := p.call(t, "fake.create_item", args)
	id := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Approve(t.Context(), alice, id); err != nil {
		t.Fatal(err)
	}
	cc, _, err := p.call(t, "fake.create_item", map[string]any{"tags": []any{"x"}, "name": "first", "id": "it-1"})
	if err != nil {
		t.Fatalf("digest retry: %v", err)
	}
	if cc.ApprovalID != id || len(p.fake.State().Items(acctA)) != 1 || lst.Count() != 1 {
		t.Errorf("digest retry: approval %q items %d rows %d", cc.ApprovalID, len(p.fake.State().Items(acctA)), lst.Count())
	}
	if rec := p.st.Record(id); rec.Status != approvals.StatusConsumed {
		t.Errorf("approval = %s", rec.Status)
	}
	// Different arguments: a new approval, not a ledger row.
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-9", "name": "other"})
	if te := toolErr(t, err); te.Code != mcp.CodeApprovalRequired || te.Data["approval_id"] == id {
		t.Errorf("drifted retry = %d %v", te.Code, te.Data)
	}
	if lst.Count() != 1 {
		t.Errorf("rows = %d", lst.Count())
	}
}

func TestDeferredApprovedDuringTheWaitRunsOnce(t *testing.T) {
	p, lst := newDeferredPipeline(t, 5*time.Second)
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			pend, _ := p.svc.Pending(context.Background(), alice)
			if len(pend) == 1 {
				_, _ = p.svc.Approve(context.Background(), alice, pend[0].ID)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	cc, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "body": "SECRET"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if items := p.fake.State().Items(acctA); len(items) != 1 || items[0].Body != "SECRET" {
		t.Errorf("items = %+v", items)
	}
	if cc.ApprovalID == "" || cc.OperationID == "" || lst.Count() != 1 {
		t.Errorf("cc = approval %q op %q rows %d", cc.ApprovalID, cc.OperationID, lst.Count())
	}
	if rec := p.st.Record(cc.ApprovalID); rec.Status != approvals.StatusConsumed || rec.Payload != nil {
		t.Errorf("approval after the call: %+v", rec)
	}
}

func TestDeferredDeniedAndExpiredApprovalsAreRefused(t *testing.T) {
	p, lst := newDeferredPipeline(t, 0)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first"})
	denied := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Deny(t.Context(), alice, denied); err != nil {
		t.Fatal(err)
	}
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first", "approval_id": denied})
	if te := toolErr(t, err); te.Code != mcp.CodeDenied || te.Class() != "approval_denied" {
		t.Errorf("denied = %d %s", te.Code, te.Class())
	}
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-2", "name": "second"})
	expired := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Approve(t.Context(), alice, expired); err != nil {
		t.Fatal(err)
	}
	p.svc.SetClock(func() time.Time { return time.Now().Add(16 * time.Minute) }) // the pipeline fixture runs on a real clock
	_, _, err = p.call(t, "fake.create_item", map[string]any{"id": "it-2", "name": "second", "approval_id": expired})
	if te := toolErr(t, err); te.Code != mcp.CodeDenied || te.Class() != "approval_expired" {
		t.Errorf("expired = %d %s", te.Code, te.Class())
	}
	if lst.Count() != 0 || len(p.fake.State().Items(acctA)) != 0 {
		t.Errorf("refusals ran: rows=%d items=%d", lst.Count(), len(p.fake.State().Items(acctA)))
	}
}

func TestDeferredHandlerNeverForwardsTheHarnessArguments(t *testing.T) {
	// Without the ledger stage the deferred handler must still never run
	// whatever the retry carried: the arguments reaching dispatch are
	// empty, so the fake refuses ("name is required") instead of creating
	// a drifted item.
	p := newPipeline(t, 0)
	p.confirm.DeferConsumption(true)
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "first"})
	id := toolErr(t, err).Data["approval_id"].(string)
	if _, err := p.svc.Approve(t.Context(), alice, id); err != nil {
		t.Fatal(err)
	}
	cc, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "drifted", "approval_id": id})
	if err == nil || !strings.Contains(err.Error(), "name is required") || len(cc.Call.Args) != 0 {
		t.Errorf("err = %v args = %v", err, cc.Call.Args)
	}
	if len(p.fake.State().Items(acctA)) != 0 {
		t.Error("the harness's drifted arguments ran")
	}
}

func TestLedgerConsumerNeedsAStoreTransaction(t *testing.T) {
	f := newFixture(t)
	c := f.svc.LedgerConsumer()
	_, err := c.Consume(t.Context(), nopLedgerTx{}, ledger.ApprovalBinding{UserID: alice, AccountID: acctA, Tool: "fake.create_item", PolicyVersionID: policyV1, ApprovalID: "x"})
	if !errors.Is(err, approvals.ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

// nopLedgerTx is a ledger.Tx without a store transaction behind it.
type nopLedgerTx struct{ ledger.Tx }

func (nopLedgerTx) StoreTx() store.Tx { return nil }
