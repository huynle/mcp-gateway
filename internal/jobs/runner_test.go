package jobs_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/jobs"
)

// memLocker is an in-memory jobs.Locker with a controllable clock and a
// way to steal a lease from under a holder.
type memLocker struct {
	mu     sync.Mutex
	leases map[string]lease
	now    func() time.Time
	renews map[string]int
}

type lease struct {
	holder string
	until  time.Time
}

func newMemLocker() *memLocker {
	return &memLocker{leases: map[string]lease{}, now: time.Now, renews: map[string]int{}}
}

func (m *memLocker) Acquire(_ context.Context, name, holder string, d time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	l, ok := m.leases[name]
	if ok && l.holder != holder && l.until.After(now) {
		return false, nil
	}
	m.leases[name] = lease{holder: holder, until: now.Add(d)}
	return true, nil
}

func (m *memLocker) Renew(_ context.Context, name, holder string, d time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	l, ok := m.leases[name]
	if !ok || l.holder != holder || !l.until.After(now) {
		return false, nil
	}
	m.leases[name] = lease{holder: holder, until: now.Add(d)}
	m.renews[name]++
	return true, nil
}

func (m *memLocker) steal(name, thief string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leases[name] = lease{holder: thief, until: m.now().Add(time.Hour)}
}

func (m *memLocker) holder(name string) (string, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.leases[name]
	return l.holder, l.until
}

func (m *memLocker) renewed(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.renews[name]
}

// countingJob counts runs and the number of concurrent runs.
type countingJob struct {
	name     string
	interval time.Duration
	work     time.Duration
	runs     atomic.Int32
	active   atomic.Int32
	maxAct   atomic.Int32
	err      error
	onRun    func(ctx context.Context)
}

func (j *countingJob) Name() string            { return j.name }
func (j *countingJob) Interval() time.Duration { return j.interval }
func (j *countingJob) Run(ctx context.Context) error {
	n := j.active.Add(1)
	defer j.active.Add(-1)
	for {
		m := j.maxAct.Load()
		if n <= m || j.maxAct.CompareAndSwap(m, n) {
			break
		}
	}
	j.runs.Add(1)
	if j.onRun != nil {
		j.onRun(ctx)
	}
	select {
	case <-time.After(j.work):
	case <-ctx.Done():
		return ctx.Err()
	}
	return j.err
}

func runFor(t *testing.T, d time.Duration, runners ...*jobs.Runner) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	defer cancel()
	var wg sync.WaitGroup
	for _, r := range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Run(ctx); err != nil {
				t.Errorf("Run: %v", err)
			}
		}()
	}
	wg.Wait()
}

// runUntil runs the runners until cond holds (polled every millisecond)
// or the deadline passes, then stops them. Condition-based waiting keeps
// the test independent of the scheduler's load: a fixed budget made
// TestJobErrorsAndPanicsDoNotStopTheRunner flake under a full -race
// suite.
func runUntil(t *testing.T, deadline time.Duration, cond func() bool, runners ...*jobs.Runner) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	defer cancel()
	var wg sync.WaitGroup
	for _, r := range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Run(ctx); err != nil {
				t.Errorf("Run: %v", err)
			}
		}()
	}
	for !cond() && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Errorf("condition not met within %s", deadline)
	}
	cancel()
	wg.Wait()
}

func TestRegisterValidatesJobs(t *testing.T) {
	r := jobs.NewRunner(newMemLocker(), jobs.Options{Log: slog.New(slog.DiscardHandler)})
	if err := r.Register(&countingJob{name: "a", interval: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(&countingJob{name: "a", interval: time.Second}); !errors.Is(err, jobs.ErrDuplicateJob) {
		t.Errorf("duplicate: %v", err)
	}
	if err := r.Register(&countingJob{name: "", interval: time.Second}); !errors.Is(err, jobs.ErrInvalidJob) {
		t.Errorf("empty name: %v", err)
	}
	if err := r.Register(&countingJob{name: "b", interval: 0}); !errors.Is(err, jobs.ErrInvalidJob) {
		t.Errorf("zero interval: %v", err)
	}
	if err := r.Register(nil); !errors.Is(err, jobs.ErrInvalidJob) {
		t.Errorf("nil: %v", err)
	}
	if names := r.Names(); len(names) != 1 || names[0] != "a" {
		t.Errorf("Names = %v", names)
	}
}

func TestTwoRunnersOneHolderNoOverlap(t *testing.T) {
	l := newMemLocker()
	j1 := &countingJob{name: "sweep", interval: 20 * time.Millisecond, work: 30 * time.Millisecond}
	j2 := &countingJob{name: "sweep", interval: 20 * time.Millisecond, work: 30 * time.Millisecond}
	var both atomic.Int32
	var maxBoth atomic.Int32
	track := func(context.Context) {
		n := both.Add(1)
		for {
			m := maxBoth.Load()
			if n <= m || maxBoth.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		both.Add(-1)
	}
	j1.onRun, j2.onRun = track, track
	r1 := jobs.NewRunner(l, jobs.Options{Holder: "replica-1", Lease: 200 * time.Millisecond, Log: slog.New(slog.DiscardHandler)})
	r2 := jobs.NewRunner(l, jobs.Options{Holder: "replica-2", Lease: 200 * time.Millisecond, Log: slog.New(slog.DiscardHandler)})
	if err := r1.Register(j1); err != nil {
		t.Fatal(err)
	}
	if err := r2.Register(j2); err != nil {
		t.Fatal(err)
	}
	runFor(t, 400*time.Millisecond, r1, r2)
	total := j1.runs.Load() + j2.runs.Load()
	if total < 3 {
		t.Errorf("runs = %d (+%d), want several", j1.runs.Load(), j2.runs.Load())
	}
	if maxBoth.Load() > 1 {
		t.Errorf("the job ran on both replicas at once (max concurrent %d)", maxBoth.Load())
	}
	// Stickiness: once a replica holds the lease it keeps running the job.
	if j1.runs.Load() > 0 && j2.runs.Load() > 0 {
		t.Logf("lease moved between replicas: %d / %d (acceptable only across an expiry)", j1.runs.Load(), j2.runs.Load())
	}
}

func TestHeartbeatKeepsALongRunAlive(t *testing.T) {
	l := newMemLocker()
	j := &countingJob{name: "long", interval: time.Second, work: 150 * time.Millisecond}
	r := jobs.NewRunner(l, jobs.Options{Holder: "r", Lease: 60 * time.Millisecond, Log: slog.New(slog.DiscardHandler)})
	if err := r.Register(j); err != nil {
		t.Fatal(err)
	}
	runFor(t, 250*time.Millisecond, r)
	if j.runs.Load() != 1 {
		t.Errorf("runs = %d, want 1", j.runs.Load())
	}
	if l.renewed("long") < 2 {
		t.Errorf("lease renewed %d times during a 150ms run with a 60ms lease", l.renewed("long"))
	}
	// After the run the lease is held until the next interval, by us.
	holder, until := l.holder("long")
	if holder != "r" || until.Before(time.Now().Add(500*time.Millisecond)) {
		t.Errorf("after run: holder %q until %v", holder, until)
	}
}

func TestLostLeaseCancelsTheRun(t *testing.T) {
	l := newMemLocker()
	cancelled := make(chan struct{}, 1)
	j := &countingJob{name: "steal", interval: time.Second, work: time.Second}
	j.onRun = func(ctx context.Context) {
		go func() {
			<-ctx.Done()
			cancelled <- struct{}{}
		}()
		l.steal("steal", "intruder")
	}
	r := jobs.NewRunner(l, jobs.Options{Holder: "r", Lease: 40 * time.Millisecond, Log: slog.New(slog.DiscardHandler)})
	if err := r.Register(j); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { _ = r.Run(ctx); close(done) }()
	select {
	case <-cancelled:
	case <-time.After(500 * time.Millisecond):
		t.Error("the run was not cancelled after the lease was lost")
	}
	cancel()
	<-done
}

func TestJobErrorsAndPanicsDoNotStopTheRunner(t *testing.T) {
	l := newMemLocker()
	failing := &countingJob{name: "fail", interval: 10 * time.Millisecond, err: errors.New("boom")}
	panicking := &panicJob{}
	r := jobs.NewRunner(l, jobs.Options{Holder: "r", Log: slog.New(slog.DiscardHandler)})
	if err := r.Register(failing); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(panicking); err != nil {
		t.Fatal(err)
	}
	runUntil(t, 10*time.Second, func() bool { return failing.runs.Load() >= 3 && panicking.runs.Load() >= 3 }, r)
	if failing.runs.Load() < 3 || panicking.runs.Load() < 3 {
		t.Errorf("runs after errors: fail=%d panic=%d", failing.runs.Load(), panicking.runs.Load())
	}
}

type panicJob struct{ runs atomic.Int32 }

func (p *panicJob) Name() string            { return "panic" }
func (p *panicJob) Interval() time.Duration { return 10 * time.Millisecond }
func (p *panicJob) Run(context.Context) error {
	p.runs.Add(1)
	panic("job exploded")
}

func TestRunReturnsWhenTheContextEnds(t *testing.T) {
	r := jobs.NewRunner(newMemLocker(), jobs.Options{Log: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Errorf("Run with cancelled ctx: %v", err)
	}
	if err := r.Register(&countingJob{name: "late", interval: time.Second}); !errors.Is(err, jobs.ErrRunning) {
		t.Errorf("register after Run: %v", err)
	}
}
