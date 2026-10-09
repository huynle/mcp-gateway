package jobs

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/ledger"
)

// DefaultReconcileInterval is how often the reconciler looks at unknown
// operations (decision dovthftx; the per-operation backoff is the
// ledger's).
const DefaultReconcileInterval = time.Minute

// ReconcilerJob is the background worker (Job) that runs
// ledger.Service.Reconcile on one replica: reconcilable writes with an
// unknown outcome are checked with backoff and resolved to succeeded or
// failed; exhausted or non-reconcilable ones become unresolved, the user
// is notified and the idempotency block is lifted.
type ReconcilerJob struct {
	svc      *ledger.Service
	interval time.Duration
}

// NewReconcilerJob returns the job; interval 0 means
// DefaultReconcileInterval.
func NewReconcilerJob(svc *ledger.Service, interval time.Duration) *ReconcilerJob {
	if interval <= 0 {
		interval = DefaultReconcileInterval
	}
	return &ReconcilerJob{svc: svc, interval: interval}
}

// Name implements Job.
func (j *ReconcilerJob) Name() string { return "ledger.reconcile" }

// Interval implements Job.
func (j *ReconcilerJob) Interval() time.Duration { return j.interval }

// Run implements Job.
func (j *ReconcilerJob) Run(ctx context.Context) error {
	_, err := j.svc.Reconcile(ctx)
	return err
}
