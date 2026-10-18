package store

import (
	"context"
	"fmt"
	"time"
)

// PurgeAuditBatch deletes at most limit audit events created before
// olderThan, oldest first, and returns how many it deleted. Like
// AuditRepository.Purge it declares the retention purge to the
// append-only trigger for the current transaction only (set_config(...,
// true)), so it works through WithJobs (gateway_jobs holds DELETE) and
// fails for gateway_app. The audit.purge job calls it in one short
// transaction per batch until a batch deletes fewer than limit rows.
func PurgeAuditBatch(ctx context.Context, q Querier, olderThan time.Time, limit int) (int64, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("store: audit purge: limit must be positive, got %d", limit)
	}
	if _, err := q.Exec(ctx, `SELECT set_config('app.audit_purge', 'on', true)`); err != nil {
		return 0, fmt.Errorf("store: audit purge: %w", err)
	}
	tag, err := q.Exec(ctx, `
		DELETE FROM audit_events WHERE id IN (
			SELECT id FROM audit_events WHERE created_at < $1 ORDER BY created_at LIMIT $2)`, olderThan, limit)
	if err != nil {
		return 0, fmt.Errorf("store: audit purge: %w", err)
	}
	return tag.RowsAffected(), nil
}
