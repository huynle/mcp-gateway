package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ExpectedSchemaVersion is the goose migration version this binary was built
// against. Startup and /readyz refuse a database at any other version; the
// unit test in store_test.go pins it to the highest embedded migration.
const ExpectedSchemaVersion int64 = 16

// Sentinel errors.
var (
	// ErrNotFound is returned by Get-style repository methods when no row is
	// visible, whether it does not exist or row-level security hides it.
	ErrNotFound = errors.New("store: not found")
	// ErrInvalidUserID is returned by WithUser for an empty or non-uuid user ID.
	ErrInvalidUserID = errors.New("store: user ID must be a uuid")
	// ErrJobsNotConfigured is returned by WithJobs when no jobs database URL
	// was given to New.
	ErrJobsNotConfigured = errors.New("store: jobs database URL not configured")
	// ErrSchemaVersionMismatch is returned by SchemaVersionMatches.
	ErrSchemaVersionMismatch = errors.New("store: schema version mismatch")
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Store owns the connection pools: one as gateway_app for the request path,
// subject to row-level security, and optionally one as gateway_jobs
// (BYPASSRLS) for background workers and admin metadata reads.
type Store struct {
	app  *pgxpool.Pool
	jobs *pgxpool.Pool
}

// Option configures New.
type Option func(*options)

type options struct {
	jobsURL string
}

// WithJobsURL enables WithJobs using a connection string for the gateway_jobs
// role.
func WithJobsURL(url string) Option {
	return func(o *options) { o.jobsURL = url }
}

// New opens the gateway_app pool on url (and the gateway_jobs pool when
// WithJobsURL is given) and verifies both can connect.
func New(ctx context.Context, url string, opts ...Option) (*Store, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	app, err := open(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("store: app pool: %w", err)
	}
	s := &Store{app: app}
	if o.jobsURL != "" {
		s.jobs, err = open(ctx, o.jobsURL)
		if err != nil {
			app.Close()
			return nil, fmt.Errorf("store: jobs pool: %w", err)
		}
	}
	return s, nil
}

func open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// Close releases both pools.
func (s *Store) Close() {
	if s.app != nil {
		s.app.Close()
	}
	if s.jobs != nil {
		s.jobs.Close()
	}
}

// Ping is the "database" readiness check: both pools can reach PostgreSQL.
func (s *Store) Ping(ctx context.Context) error {
	if s.app == nil {
		return errors.New("store: not opened")
	}
	if err := s.app.Ping(ctx); err != nil {
		return fmt.Errorf("store: app pool: %w", err)
	}
	if s.jobs != nil {
		if err := s.jobs.Ping(ctx); err != nil {
			return fmt.Errorf("store: jobs pool: %w", err)
		}
	}
	return nil
}

// SchemaVersion returns the migration version recorded in the database.
func (s *Store) SchemaVersion(ctx context.Context) (int64, error) {
	if s.app == nil {
		return 0, errors.New("store: not opened")
	}
	var v int64
	err := s.app.QueryRow(ctx, `SELECT coalesce(max(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return v, nil
}

// SchemaVersionMatches is the startup gate: it fails unless the database
// is exactly at ExpectedSchemaVersion. A process must not start against a
// schema it was not built for; migrating is cmd/migrate's job.
func (s *Store) SchemaVersionMatches(ctx context.Context) error {
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if v != ExpectedSchemaVersion {
		return fmt.Errorf("%w: database is at %d, this binary expects %d (run `migrate up` before starting the gateway)",
			ErrSchemaVersionMismatch, v, ExpectedSchemaVersion)
	}
	return nil
}

// SchemaVersionReady is the "schema" readiness check: the database must
// be at ExpectedSchemaVersion or newer. A rolling upgrade runs the next
// release's migrations before the old pods are replaced (migrations are
// additive and backward compatible within one release, docs/deploy.md),
// so a database that is ahead keeps the running replicas ready; one that
// is behind does not (quirk 6xxvsoyp, idea vv0vurcl).
func (s *Store) SchemaVersionReady(ctx context.Context) error {
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if v < ExpectedSchemaVersion {
		return fmt.Errorf("%w: database is at %d, this binary expects at least %d (run `migrate up`)",
			ErrSchemaVersionMismatch, v, ExpectedSchemaVersion)
	}
	return nil
}

// WithUser runs fn in a transaction on the gateway_app pool scoped to userID:
// SET LOCAL app.user_id makes every row-level security policy restrict reads
// and writes to that user's rows. The setting dies with the transaction, so a
// pooled connection never leaks a scope. fn's error rolls the transaction
// back; otherwise it is committed.
func (s *Store) WithUser(ctx context.Context, userID string, fn func(Tx) error) error {
	if !uuidRE.MatchString(userID) {
		return fmt.Errorf("%w: %q", ErrInvalidUserID, userID)
	}
	if s.app == nil {
		return errors.New("store: not opened")
	}
	return inTx(ctx, s.app, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, userID); err != nil {
			return fmt.Errorf("store: set user scope: %w", err)
		}
		return fn(&scope{Tx: tx})
	})
}

// WithJobs runs fn in a transaction on the gateway_jobs pool, which bypasses
// row-level security. For background workers (reconciler, expiry, purge,
// sweeps), just-in-time user creation and admin metadata reads only; request
// handling must use WithUser.
func (s *Store) WithJobs(ctx context.Context, fn func(Tx) error) error {
	if s.jobs == nil {
		return ErrJobsNotConfigured
	}
	return inTx(ctx, s.jobs, func(tx pgx.Tx) error { return fn(&scope{Tx: tx}) })
}

func inTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) (err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
