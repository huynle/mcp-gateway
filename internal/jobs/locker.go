package jobs

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Scopes is the part of *store.Store the Postgres locker uses.
type Scopes interface {
	WithJobs(ctx context.Context, fn func(store.Tx) error) error
}

// postgresLocker implements Locker over the job_locks table through the
// jobs scope (gateway_jobs owns the table; gateway_app can only read it).
type postgresLocker struct{ st Scopes }

// NewPostgresLocker returns the production Locker over st (normally
// *store.Store).
func NewPostgresLocker(st Scopes) Locker { return postgresLocker{st: st} }

func (l postgresLocker) Acquire(ctx context.Context, name, holder string, d time.Duration) (bool, error) {
	var ok bool
	err := l.st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		ok, err = store.AcquireJobLock(ctx, tx, name, holder, d)
		return err
	})
	return ok, err
}

func (l postgresLocker) Renew(ctx context.Context, name, holder string, d time.Duration) (bool, error) {
	var ok bool
	err := l.st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		ok, err = store.RenewJobLock(ctx, tx, name, holder, d)
		return err
	})
	return ok, err
}
