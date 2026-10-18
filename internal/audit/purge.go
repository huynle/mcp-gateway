package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Retention purge defaults (Brain task mjdzepbx).
const (
	// PurgeJobName is the job's name in job_locks and the logs.
	PurgeJobName = "audit.purge"
	// DefaultPurgeInterval is how often the purge runs.
	DefaultPurgeInterval = 24 * time.Hour
	// DefaultPurgeBatch is how many rows one DELETE statement (and one
	// transaction) removes, so a first run over a large table never holds
	// one long transaction or lock.
	DefaultPurgeBatch = 10000
	// ActionPurged is the action of the system event a run records and the
	// event of its log line.
	ActionPurged = "audit.purged"
)

// PurgeMetrics receives the number of rows each run deleted
// (*observability.Metrics: audit_events_purged_total).
type PurgeMetrics interface {
	AuditPurged(n int)
}

// PurgeOptions configures NewPurgeJob. Retention is required.
type PurgeOptions struct {
	// Retention: events older than this are deleted (config
	// GATEWAY_AUDIT_RETENTION, validated there to be at least 30 days).
	Retention time.Duration
	// Interval between runs (DefaultPurgeInterval when 0).
	Interval time.Duration
	// BatchSize rows per statement (DefaultPurgeBatch when 0).
	BatchSize int
	// Recorder receives one system event per run that deleted rows
	// (optional).
	Recorder Recorder
	// Metrics counts deleted rows (optional).
	Metrics PurgeMetrics
	Log     *slog.Logger
	// Now is the clock (tests); time.Now when nil.
	Now func() time.Time
}

// PurgeJob is the background worker (jobs.Job) that enforces audit
// retention: on one replica (the runner's lease) it deletes events older
// than Retention in batches of BatchSize, each batch its own WithJobs
// transaction that sets app.audit_purge, the only way past the
// append-only trigger (migration 00006). Rows inside the retention window
// are never touched.
type PurgeJob struct {
	purge func(ctx context.Context, olderThan time.Time, limit int) (int64, error)
	o     PurgeOptions
}

// NewPurgeJob returns the job over st (normally *store.Store).
func NewPurgeJob(st Scopes, o PurgeOptions) (*PurgeJob, error) {
	if st == nil {
		return nil, errors.New("audit: purge job needs a store")
	}
	return newPurgeJob(func(ctx context.Context, olderThan time.Time, limit int) (int64, error) {
		var n int64
		err := st.WithJobs(ctx, func(tx store.Tx) error {
			var err error
			n, err = store.PurgeAuditBatch(ctx, tx, olderThan, limit)
			return err
		})
		return n, err
	}, o)
}

func newPurgeJob(purge func(context.Context, time.Time, int) (int64, error), o PurgeOptions) (*PurgeJob, error) {
	if o.Retention <= 0 {
		return nil, fmt.Errorf("audit: purge retention must be positive, got %v", o.Retention)
	}
	if o.Interval <= 0 {
		o.Interval = DefaultPurgeInterval
	}
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultPurgeBatch
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &PurgeJob{purge: purge, o: o}, nil
}

// Name implements jobs.Job.
func (j *PurgeJob) Name() string { return PurgeJobName }

// Interval implements jobs.Job.
func (j *PurgeJob) Interval() time.Duration { return j.o.Interval }

// Run implements jobs.Job: batches until one deletes fewer rows than the
// batch size, a batch fails, or ctx ends (a lost lease stops between
// batches; committed batches stay deleted). It logs audit.purged with the
// count and cutoff, counts the rows in the metrics and records a system
// event when rows went ("partial" when the run stopped early).
func (j *PurgeJob) Run(ctx context.Context) error {
	cutoff := j.o.Now().Add(-j.o.Retention).UTC()
	total, batches, runErr := j.purgeAll(ctx, cutoff)
	if j.o.Metrics != nil && total > 0 {
		j.o.Metrics.AuditPurged(int(total))
	}
	j.o.Log.Info("audit events purged", "event", ActionPurged, "deleted", total, "batches", batches,
		"cutoff", cutoff.Format(time.RFC3339), "retention", j.o.Retention.String(), "complete", runErr == nil)
	if total > 0 {
		j.record(ctx, total, cutoff, runErr)
	}
	if runErr != nil {
		return fmt.Errorf("audit: purge: %w", runErr)
	}
	return nil
}

func (j *PurgeJob) purgeAll(ctx context.Context, cutoff time.Time) (total int64, batches int, err error) {
	for {
		if err := ctx.Err(); err != nil {
			return total, batches, err
		}
		n, err := j.purge(ctx, cutoff, j.o.BatchSize)
		if err != nil {
			return total, batches, err
		}
		total += n
		batches++
		if n < int64(j.o.BatchSize) {
			return total, batches, nil
		}
	}
}

func (j *PurgeJob) record(ctx context.Context, total int64, cutoff time.Time, runErr error) {
	if j.o.Recorder == nil {
		return
	}
	ev := Event{
		Decision: "allow",
		Outcome:  "succeeded",
		ResourceIdentity: map[string]string{
			"action": ActionPurged, "deleted": strconv.FormatInt(total, 10), "cutoff": cutoff.Format(time.RFC3339),
		},
	}
	if runErr != nil {
		ev.Outcome = "partial"
	}
	// Detached from the run's context, which may be the cancelled one: the
	// deletions already committed must be on record.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := j.o.Recorder.Record(rctx, ev); err != nil {
		j.o.Log.Error("audit purge event not recorded", "event", "audit.purge_record_failed", "error", observability.RedactError(err))
	}
}
