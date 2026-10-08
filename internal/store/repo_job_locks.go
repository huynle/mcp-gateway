package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Job-lock lease operations for the jobs runner (plan 36bakiw8 section 7).
// Both compare against the database clock so replicas with skewed clocks
// agree on expiry. They run under WithJobs: gateway_app can only read
// job_locks.

// AcquireJobLock takes the lease for name on behalf of holder for d when
// no row exists, the lease has expired, or holder already holds it. It
// reports whether the lease is now held by holder. The upsert is one
// statement, so two replicas racing for a free lease see exactly one
// winner (the loser's ON CONFLICT ... WHERE fails and returns no row).
func AcquireJobLock(ctx context.Context, q Querier, name, holder string, d time.Duration) (bool, error) {
	var got string
	err := q.QueryRow(ctx, `
		INSERT INTO job_locks (name, holder, acquired_at, expires_at)
		VALUES ($1, $2, now(), now() + $3::interval)
		ON CONFLICT (name) DO UPDATE
			SET holder = EXCLUDED.holder, acquired_at = now(), expires_at = EXCLUDED.expires_at
			WHERE job_locks.expires_at <= now() OR job_locks.holder = EXCLUDED.holder
		RETURNING holder`, name, holder, pgInterval(d)).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: acquire job lock: %w", err)
	}
	return got == holder, nil
}

// RenewJobLock extends a lease holder still holds (and that has not
// expired) by d from now, reporting false when it was lost.
func RenewJobLock(ctx context.Context, q Querier, name, holder string, d time.Duration) (bool, error) {
	tag, err := q.Exec(ctx, `
		UPDATE job_locks SET expires_at = now() + $3::interval
		WHERE name = $1 AND holder = $2 AND expires_at > now()`, name, holder, pgInterval(d))
	if err != nil {
		return false, fmt.Errorf("store: renew job lock: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// pgInterval renders d for a ::interval cast.
func pgInterval(d time.Duration) string {
	return fmt.Sprintf("%d microseconds", d.Microseconds())
}
