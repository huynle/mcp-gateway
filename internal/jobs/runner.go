package jobs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// Errors from Register and Run.
var (
	ErrInvalidJob   = errors.New("jobs: invalid job")
	ErrDuplicateJob = errors.New("jobs: job already registered")
	ErrRunning      = errors.New("jobs: runner already started")
)

// DefaultLease is how long a replica may run a job before its lease must
// have been renewed by the heartbeat. It bounds how long a job can be
// orphaned when the replica dies mid-run.
const DefaultLease = time.Minute

// Job is a background worker: Run is called every Interval on exactly one
// replica. Run must honour ctx: it is cancelled when the runner stops and
// when the lease is lost.
type Job interface {
	Name() string
	Interval() time.Duration
	Run(ctx context.Context) error
}

// Locker is the lease store that makes a job run on one replica (the
// job_locks table in production: NewPostgresLocker). Acquire takes the
// lease for name on behalf of holder for d when it is free, expired or
// already held by holder; Renew extends a lease holder still holds and
// reports false when it was lost.
type Locker interface {
	Acquire(ctx context.Context, name, holder string, d time.Duration) (bool, error)
	Renew(ctx context.Context, name, holder string, d time.Duration) (bool, error)
}

// Options configures NewRunner. Everything is optional.
type Options struct {
	// Holder identifies this replica in job_locks; defaults to
	// hostname/random.
	Holder string
	// Lease is the heartbeat lease (DefaultLease); the heartbeat renews
	// it every Lease/3 while a job runs.
	Lease time.Duration
	Log   *slog.Logger
}

// Runner runs registered jobs on their intervals, each under a lease:
//
//   - every Interval the runner tries to acquire the job's lease for Lease;
//     a lease another replica holds and has not let expire means "not my
//     turn" and nothing runs here;
//   - while the job runs a heartbeat renews the lease every Lease/3; a
//     renewal that fails (the lease was lost or taken) cancels the job's
//     context;
//   - after the run the lease is kept, by this replica, until the next
//     interval, so no other replica runs the job before then and the job
//     stays on one replica while that replica is healthy; when it dies
//     the lease expires and any other replica picks the job up.
//
// Jobs are independent: one failing or panicking does not affect others,
// and failures are logged and retried next interval.
type Runner struct {
	locker Locker
	holder string
	lease  time.Duration
	log    *slog.Logger

	mu      sync.Mutex
	jobs    []Job
	started bool
}

// NewRunner builds a runner over l.
func NewRunner(l Locker, opts Options) *Runner {
	if opts.Holder == "" {
		opts.Holder = defaultHolder()
	}
	if opts.Lease <= 0 {
		opts.Lease = DefaultLease
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Runner{locker: l, holder: opts.Holder, lease: opts.Lease, log: opts.Log}
}

// Register adds a job. Names must be unique; intervals positive.
func (r *Runner) Register(j Job) error {
	if j == nil {
		return fmt.Errorf("%w: nil job", ErrInvalidJob)
	}
	if j.Name() == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidJob)
	}
	if j.Interval() <= 0 {
		return fmt.Errorf("%w: %s: interval must be positive", ErrInvalidJob, j.Name())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return ErrRunning
	}
	for _, existing := range r.jobs {
		if existing.Name() == j.Name() {
			return fmt.Errorf("%w: %s", ErrDuplicateJob, j.Name())
		}
	}
	r.jobs = append(r.jobs, j)
	return nil
}

// Names lists the registered jobs in registration order.
func (r *Runner) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.jobs))
	for i, j := range r.jobs {
		out[i] = j.Name()
	}
	return out
}

// Holder is this replica's lease holder id.
func (r *Runner) Holder() string { return r.holder }

// Run drives every registered job until ctx ends, then waits for running
// jobs to return. It always returns nil once stopped.
func (r *Runner) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return ErrRunning
	}
	r.started = true
	jobs := append([]Job(nil), r.jobs...)
	r.mu.Unlock()
	if ctx.Err() != nil {
		return nil
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.loop(ctx, j)
		}()
	}
	wg.Wait()
	return nil
}

func (r *Runner) loop(ctx context.Context, j Job) {
	ticker := time.NewTicker(j.Interval())
	defer ticker.Stop()
	for {
		r.try(ctx, j)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// try runs j once when this replica gets the lease.
func (r *Runner) try(ctx context.Context, j Job) {
	name := j.Name()
	ok, err := r.locker.Acquire(ctx, name, r.holder, r.lease)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("job lease unavailable", "event", "jobs.lease_failed", "job", name, "error", observability.RedactError(err))
		}
		return
	}
	if !ok {
		return
	}
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopHeartbeat := r.heartbeat(jobCtx, cancel, name)
	started := time.Now()
	err = r.runOne(jobCtx, j)
	stopHeartbeat()
	if err != nil {
		if jobCtx.Err() != nil && ctx.Err() == nil {
			r.log.Warn("job cancelled: lease lost", "event", "jobs.lease_lost", "job", name, "elapsed_ms", time.Since(started).Milliseconds())
		} else if ctx.Err() == nil {
			r.log.Error("job failed", "event", "jobs.failed", "job", name, "elapsed_ms", time.Since(started).Milliseconds(), "error", observability.RedactError(err))
		}
	} else {
		r.log.Debug("job ran", "event", "jobs.ran", "job", name, "elapsed_ms", time.Since(started).Milliseconds())
	}
	if ctx.Err() != nil {
		return
	}
	// Keep the lease until the next interval so no other replica runs the
	// job before then; our own ticker re-acquires it (holder match).
	if _, err := r.locker.Renew(ctx, name, r.holder, j.Interval()); err != nil {
		r.log.Warn("job lease not extended", "event", "jobs.lease_failed", "job", name, "error", observability.RedactError(err))
	}
}

// runOne calls Run, turning a panic into an error.
func (r *Runner) runOne(ctx context.Context, j Job) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("jobs: %s panicked: %v", j.Name(), p)
			r.log.Error("job panicked", "event", "jobs.panic", "job", j.Name(), "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	return j.Run(ctx)
}

// heartbeat renews the lease every lease/3 until stopped; a lost lease
// cancels the job.
func (r *Runner) heartbeat(ctx context.Context, cancel context.CancelFunc, name string) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(r.lease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				ok, err := r.locker.Renew(ctx, name, r.holder, r.lease)
				if err != nil {
					if ctx.Err() == nil {
						r.log.Warn("job lease renewal failed", "event", "jobs.lease_failed", "job", name, "error", observability.RedactError(err))
					}
					continue
				}
				if !ok {
					cancel()
					return
				}
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

func defaultHolder() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "replica"
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s/%x", host, b)
}
