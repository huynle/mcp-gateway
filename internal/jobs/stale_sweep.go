package jobs

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/ledger"
)

// DefaultStaleSweepInterval is how often the stale sweep runs; the age
// that makes an in_progress row stale is ledger.Config.StaleAfter.
const DefaultStaleSweepInterval = 30 * time.Second

// StaleSweepJob is the background worker (Job) that runs
// ledger.Service.SweepStale on one replica: in_progress operations older
// than the staleness window belong to a replica that was cut off or
// died, so they become unknown and the reconciler takes over.
type StaleSweepJob struct {
	svc      *ledger.Service
	interval time.Duration
}

// NewStaleSweepJob returns the job; interval 0 means
// DefaultStaleSweepInterval.
func NewStaleSweepJob(svc *ledger.Service, interval time.Duration) *StaleSweepJob {
	if interval <= 0 {
		interval = DefaultStaleSweepInterval
	}
	return &StaleSweepJob{svc: svc, interval: interval}
}

// Name implements Job.
func (j *StaleSweepJob) Name() string { return "ledger.sweep_stale" }

// Interval implements Job.
func (j *StaleSweepJob) Interval() time.Duration { return j.interval }

// Run implements Job.
func (j *StaleSweepJob) Run(ctx context.Context) error {
	_, err := j.svc.SweepStale(ctx)
	return err
}
