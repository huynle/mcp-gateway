//go:build integration

package jobs_test

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The jobs integration test runs against its own database
// (gateway_jobs_test; quirk 01mepmn6) and retries the ALTER ROLE race
// (quirk aihn7hjb).

const (
	testDB      = "gateway_jobs_test"
	appPassword = "gateway-app-test"
	jobsPass    = "gateway-jobs-test"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, testDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+testDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + testDB
	superURL := u.String()
	// Migration 00001 ALTERs the cluster-global roles, so a fresh database
	// can lose the race against another package's bootstrap (quirk
	// aihn7hjb); goose rolls the migration back and a retry reruns it.
	if err := retryConcurrentUpdate(func() error { return migrations.Up(ctx, superURL) }); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, superURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPass + "'",
		"TRUNCATE job_locks",
	} {
		err := retryConcurrentUpdate(func() error {
			_, err := super.Exec(ctx, stmt)
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

// retryConcurrentUpdate runs fn, retrying up to 20 times at 100 ms when
// PostgreSQL reports "tuple concurrently updated" (SQLSTATE XX000).
func retryConcurrentUpdate(fn func() error) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if err = fn(); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

type sharedJob struct {
	runs   *atomic.Int32 // shared across both replicas' jobs
	mine   atomic.Int32
	active *atomic.Int32
	maxAct *atomic.Int32
	enough chan struct{}
	once   *sync.Once
}

func (j *sharedJob) Name() string            { return "integration.sweep" }
func (j *sharedJob) Interval() time.Duration { return 50 * time.Millisecond }
func (j *sharedJob) Run(ctx context.Context) error {
	n := j.active.Add(1)
	defer j.active.Add(-1)
	for {
		m := j.maxAct.Load()
		if n <= m || j.maxAct.CompareAndSwap(m, n) {
			break
		}
	}
	j.mine.Add(1)
	if j.runs.Add(1) >= 4 {
		j.once.Do(func() { close(j.enough) })
	}
	select {
	case <-time.After(60 * time.Millisecond):
	case <-ctx.Done():
	}
	return nil
}

// runnerLease is the lease the two runners use. The holder keeps the lease
// for Interval + Lease after each run and re-acquires it on its next
// attempt one Interval later, so the lease can only move to the other
// replica when the holder stalls for longer than Lease. The shared test
// cluster stalls for seconds under the full suite with the race detector
// (quirk aihn7hjb), so the margin is far above any plausible round trip;
// the heartbeat (Lease/3) never fires during the 60 ms run, which is fine:
// the lease primitives are checked separately below with short leases.
const runnerLease = 30 * time.Second

// TestIntegrationTwoRunnersOneHolder: two runners over the real job_locks
// table never run the job at the same time, the job stays on the replica
// that holds the lease, the lease row names that holder and survives the
// run (held until the next interval). The runners run until the job has
// run four times (condition, not a time budget: the shared test cluster
// can be slow under the full suite).
func TestIntegrationTwoRunnersOneHolder(t *testing.T) {
	st := openTestStore(t)
	locker := jobs.NewPostgresLocker(st)
	var active, maxAct, runs atomic.Int32
	enough := make(chan struct{})
	var once sync.Once
	j1 := &sharedJob{runs: &runs, active: &active, maxAct: &maxAct, enough: enough, once: &once}
	j2 := &sharedJob{runs: &runs, active: &active, maxAct: &maxAct, enough: enough, once: &once}
	r1 := jobs.NewRunner(locker, jobs.Options{Holder: "replica-1", Lease: runnerLease, Log: slog.New(slog.DiscardHandler)})
	r2 := jobs.NewRunner(locker, jobs.Options{Holder: "replica-2", Lease: runnerLease, Log: slog.New(slog.DiscardHandler)})
	if err := r1.Register(j1); err != nil {
		t.Fatal(err)
	}
	if err := r2.Register(j2); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	for _, r := range []*jobs.Runner{r1, r2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.Run(ctx)
		}()
	}
	select {
	case <-enough:
	case <-time.After(30 * time.Second):
		t.Errorf("only %d runs in 30s", runs.Load())
	}
	cancel()
	wg.Wait()
	if maxAct.Load() > 1 {
		t.Errorf("job ran concurrently on both replicas (max %d)", maxAct.Load())
	}
	if j1.mine.Load() > 0 && j2.mine.Load() > 0 {
		t.Errorf("the lease moved between healthy replicas: %d / %d", j1.mine.Load(), j2.mine.Load())
	}
	var holder string
	var expires time.Time
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		l, err := tx.JobLocks().Get(t.Context(), "integration.sweep")
		if err != nil {
			return err
		}
		holder, expires = l.Holder, l.ExpiresAt
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if holder != "replica-1" && holder != "replica-2" {
		t.Errorf("lock holder = %q", holder)
	}
	if expires.Before(time.Now().Add(-time.Second)) {
		t.Errorf("lock expired long ago: %v", expires)
	}

	// The lease primitives themselves: a held lease is refused to another
	// holder, renewable by its holder, and taken over once expired.
	ok, err := locker.Acquire(t.Context(), "lease", "a", time.Second)
	if err != nil || !ok {
		t.Fatalf("a acquires: %v %v", ok, err)
	}
	if ok, _ := locker.Acquire(t.Context(), "lease", "b", time.Second); ok {
		t.Error("b acquired a's live lease")
	}
	if ok, _ := locker.Renew(t.Context(), "lease", "b", time.Second); ok {
		t.Error("b renewed a's lease")
	}
	if ok, _ := locker.Renew(t.Context(), "lease", "a", 50*time.Millisecond); !ok {
		t.Error("a could not renew its own lease")
	}
	time.Sleep(80 * time.Millisecond)
	if ok, _ := locker.Renew(t.Context(), "lease", "a", time.Second); ok {
		t.Error("a renewed an expired lease")
	}
	if ok, _ := locker.Acquire(t.Context(), "lease", "b", time.Second); !ok {
		t.Error("b could not take the expired lease")
	}
}
