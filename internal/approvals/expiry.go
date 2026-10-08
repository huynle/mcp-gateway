package approvals

import (
	"context"
	"time"
)

// DefaultExpiryInterval is how often the expiry job sweeps.
const DefaultExpiryInterval = 30 * time.Second

// ExpiryJob is the background worker (jobs.Job) that marks approvals past
// their expiry as expired and drops their payloads. Consume and Wait
// already refuse expired rows on their own; the job is what guarantees
// the ciphertext does not outlive the approval when nobody comes back
// for it.
type ExpiryJob struct {
	svc      *Service
	interval time.Duration
}

// ExpiryJob returns the job; interval 0 means DefaultExpiryInterval.
func (s *Service) ExpiryJob(interval time.Duration) *ExpiryJob {
	if interval <= 0 {
		interval = DefaultExpiryInterval
	}
	return &ExpiryJob{svc: s, interval: interval}
}

// Name implements jobs.Job.
func (j *ExpiryJob) Name() string { return "approvals.expire" }

// Interval implements jobs.Job.
func (j *ExpiryJob) Interval() time.Duration { return j.interval }

// Run implements jobs.Job.
func (j *ExpiryJob) Run(ctx context.Context) error {
	_, err := j.svc.Expire(ctx)
	return err
}
