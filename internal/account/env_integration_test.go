//go:build integration

package account_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The account integration tests need GATEWAY_TEST_DATABASE_URL (a
// superuser URL, see internal/store/integration_test.go) and use their own
// database, gateway_account, like the audit package.

const (
	testDBName       = "gateway_account"
	testAppPassword  = "gateway-app-test"
	testJobsPassword = "gateway-jobs-test"
)

type testEnv struct {
	super   *pgxpool.Pool
	appURL  string
	jobsURL string
}

var (
	envMu  sync.Mutex
	envVal *testEnv
)

// setup builds the package's test environment once. A failed bootstrap is
// not sticky: the next test tries again, so a lost cluster-global race
// (quirk aihn7hjb) costs one test, not the whole package.
func setup(t *testing.T) *testEnv {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	envMu.Lock()
	defer envMu.Unlock()
	if envVal == nil {
		env, err := newTestEnv(context.Background(), raw)
		if err != nil {
			t.Fatalf("test environment: %v", err)
		}
		envVal = env
	}
	return envVal
}

func newTestEnv(ctx context.Context, superURL string) (*testEnv, error) {
	admin, err := pgxpool.New(ctx, superURL)
	if err != nil {
		return nil, err
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+testDBName); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P04" { // duplicate_database
			return nil, err
		}
	}
	dbURL, err := withDatabase(superURL, testDBName)
	if err != nil {
		return nil, err
	}
	if err := migrateUpRetrying(ctx, dbURL); err != nil {
		return nil, err
	}
	super, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, err
	}
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + testAppPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + testJobsPassword + "'",
	} {
		if err := execRetryingConcurrentUpdate(ctx, super, stmt); err != nil {
			return nil, err
		}
	}
	env := &testEnv{super: super}
	if env.appURL, err = withUser(dbURL, "gateway_app", testAppPassword); err != nil {
		return nil, err
	}
	if env.jobsURL, err = withUser(dbURL, "gateway_jobs", testJobsPassword); err != nil {
		return nil, err
	}
	return env, nil
}

func withDatabase(raw, name string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}

func withUser(raw, user, password string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(user, password)
	return u.String(), nil
}

func (e *testEnv) open(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(t.Context(), e.appURL, store.WithJobsURL(e.jobsURL))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func (e *testEnv) reset(t *testing.T) {
	t.Helper()
	if _, err := e.super.Exec(t.Context(), `TRUNCATE users, roles, audit_events, vendor_apps, oauth_clients, policy_versions CASCADE`); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

func newUser(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	var id string
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		u := &store.User{DisplayName: name, Status: store.UserActive}
		if err := tx.Users().Create(t.Context(), u); err != nil {
			return err
		}
		id = u.ID
		return nil
	})
	if err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	return id
}

// execRetryingConcurrentUpdate runs stmt, retrying when PostgreSQL reports
// "tuple concurrently updated" (SQLSTATE XX000): every package's
// integration bootstrap ALTERs the same cluster-global roles and `go test`
// runs packages in parallel.
func execRetryingConcurrentUpdate(ctx context.Context, conn *pgxpool.Pool, stmt string) error {
	return retryConcurrentUpdate(func() error {
		_, err := conn.Exec(ctx, stmt)
		return err
	})
}

// migrateUpRetrying runs the migrations, retrying when migration 00001's
// ALTER ROLE on the cluster-global roles loses the race against another
// package's bootstrap (quirk aihn7hjb: goose rolls the migration back, so a
// retry simply runs it again).
func migrateUpRetrying(ctx context.Context, dbURL string) error {
	return retryConcurrentUpdate(func() error { return migrations.Up(ctx, dbURL) })
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
