package secrets

import (
	"context"
	"time"
)

// DefaultExpiryInterval is how often the expiry job sweeps.
const DefaultExpiryInterval = 30 * time.Second

// ExpiryJob is the background worker (jobs.Job) that ends secrets whose
// link, TTL or uses ran out, wipes their ciphertext and deletes ended rows
// after Retention. Consume already refuses such rows on its own; the job
// is what guarantees the ciphertext does not outlive the secret. Calls
// never wipe inline (a use may still be refunded).
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
func (j *ExpiryJob) Name() string { return "secrets.expire" }

// Interval implements jobs.Job.
func (j *ExpiryJob) Interval() time.Duration { return j.interval }

// Run implements jobs.Job.
func (j *ExpiryJob) Run(ctx context.Context) error {
	_, err := j.svc.Expire(ctx)
	return err
}
