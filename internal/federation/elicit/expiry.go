package elicit

import (
	"context"
	"time"
)

// DefaultExpiryInterval is how often the expiry job sweeps. Expired rows
// are already refused by every read (they are not live); the job only
// deletes them Retention after expiry, so a slow sweep is harmless.
const DefaultExpiryInterval = 10 * time.Minute

// ExpiryJob is the background worker (jobs.Job) that deletes elicitations
// that expired more than Retention ago.
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
func (j *ExpiryJob) Name() string { return "elicit.expire" }

// Interval implements jobs.Job.
func (j *ExpiryJob) Interval() time.Duration { return j.interval }

// Run implements jobs.Job.
func (j *ExpiryJob) Run(ctx context.Context) error {
	_, err := j.svc.Expire(ctx)
	return err
}
