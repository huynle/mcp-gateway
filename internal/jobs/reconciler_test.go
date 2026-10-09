package jobs_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/ledger/ledgertest"
)

const (
	ledgerUser    = "11111111-1111-4111-8111-111111111111"
	ledgerAccount = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ledgerPolicy  = "99999999-9999-4999-8999-999999999999"
)

// newLedger builds a ledger service over the fake connector's registry
// and the in-memory store, with a controllable clock.
func newLedger(t *testing.T) (*ledger.Service, *time.Time) {
	t.Helper()
	fc := fake.New(fake.Options{})
	fc.SeedAccount(ledgerUser, connectors.Account{ID: ledgerAccount, Label: connectors.LabelCompany, DisplayName: "Work"})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, fc, fc.Accounts()); err != nil {
		t.Fatal(err)
	}
	st := ledgertest.NewMemStore()
	svc, err := ledger.New(ledger.DefaultConfig(), st, ledger.Options{Registry: reg, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return now })
	return svc, &now
}

func beginWrite(t *testing.T, svc *ledger.Service, tool string, args map[string]any) *ledger.Operation {
	t.Helper()
	op, prior, err := svc.Begin(t.Context(), ledger.Intent{
		UserID: ledgerUser, AccountID: ledgerAccount, Tool: tool, Digest: ledger.Digest(args), PolicyVersionID: ledgerPolicy,
	})
	if err != nil || prior.Kind != ledger.PriorNone {
		t.Fatalf("Begin: op=%v prior=%+v err=%v", op, prior, err)
	}
	return op
}

func TestReconcilerJobRunsTheReconciler(t *testing.T) {
	svc, now := newLedger(t)
	job := jobs.NewReconcilerJob(svc, 0)
	if job.Name() != "ledger.reconcile" || job.Interval() != jobs.DefaultReconcileInterval {
		t.Errorf("job = %s every %v", job.Name(), job.Interval())
	}
	if custom := jobs.NewReconcilerJob(svc, 5*time.Second); custom.Interval() != 5*time.Second {
		t.Errorf("custom interval = %v", custom.Interval())
	}
	// post_note cannot be reconciled: one run turns an unknown outcome unresolved.
	op := beginWrite(t, svc, "fake.post_note", map[string]any{"text": "x"})
	if _, err := svc.Finish(t.Context(), ledgerUser, op.ID, ledger.Unknown("outcome_unknown")); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if err := job.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.Get(t.Context(), ledgerUser, op.ID); got.State != ledger.StateUnresolved {
		t.Errorf("after run = %+v", got)
	}
	var _ jobs.Job = job
}

func TestStaleSweepJobRunsTheSweep(t *testing.T) {
	svc, now := newLedger(t)
	job := jobs.NewStaleSweepJob(svc, 0)
	if job.Name() != "ledger.sweep_stale" || job.Interval() != jobs.DefaultStaleSweepInterval {
		t.Errorf("job = %s every %v", job.Name(), job.Interval())
	}
	op := beginWrite(t, svc, "fake.create_item", map[string]any{"id": "it-1", "name": "n"})
	*now = now.Add(svc.Config().StaleAfter + time.Second)
	if err := job.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.Get(t.Context(), ledgerUser, op.ID); got.State != ledger.StateUnknown {
		t.Errorf("after sweep = %+v", got)
	}
	var _ jobs.Job = job
}
