//go:build integration

package audit_test

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

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The audit integration tests need GATEWAY_TEST_DATABASE_URL (a superuser
// URL, see internal/store/integration_test.go). They create and migrate
// their own database, gateway_audit, on the same server so the store
// package's TRUNCATE-based reset cannot race with them when packages run in
// parallel. The roles are cluster-global; the same test passwords as the
// store tests are set so both packages can log in concurrently.

const (
	testDBName       = "gateway_audit"
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
	if _, err := e.super.Exec(t.Context(), `TRUNCATE users, audit_events CASCADE`); err != nil {
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

func toolsOf(recs []audit.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Tool)
	}
	return out
}

func TestIntegrationUsersSeeOnlyTheirOwnActivity(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "alice")
	bob := newUser(t, st, "bob")
	rec := audit.NewStoreRecorder(st)

	events := []audit.Event{
		{UserID: alice, Tool: "github.create_issue", Decision: "allow", Outcome: "succeeded",
			ResourceIdentity: map[string]string{"repo": "acme/api"}, Latency: 120 * time.Millisecond, RequestID: "req-alice-0001"},
		{UserID: alice, Tool: "slack.post_message", Decision: "confirm", Outcome: "pending", AccountLabel: "personal"},
		{UserID: bob, Tool: "github.create_issue", Decision: "deny", Outcome: "denied", RequestID: "req-bob-00001"},
		{Decision: "auth_failed", ErrorClass: "token_expired", RequestID: "req-system-001"}, // system event
	}
	for i, ev := range events {
		if err := rec.Record(ctx, ev); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	aliceRows, err := rec.ListForUser(ctx, alice, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatalf("alice list: %v", err)
	}
	if len(aliceRows) != 2 {
		t.Fatalf("alice sees %d rows %v, want 2", len(aliceRows), toolsOf(aliceRows))
	}
	for _, r := range aliceRows {
		if r.UserID != alice {
			t.Errorf("alice sees a row of user %q", r.UserID)
		}
	}
	// Newest first: slack was recorded after github.
	if aliceRows[0].Tool != "slack.post_message" || aliceRows[1].Tool != "github.create_issue" {
		t.Errorf("order = %v, want newest first", toolsOf(aliceRows))
	}
	got := aliceRows[1]
	if got.ResourceIdentity["repo"] != "acme/api" || got.Latency != 120*time.Millisecond || got.RequestID != "req-alice-0001" ||
		got.Outcome != "succeeded" || got.EventType != audit.EventTypeToolCall || got.ID == "" || got.Time.IsZero() {
		t.Errorf("alice's github row lost metadata: %+v", got)
	}

	bobRows, err := rec.ListForUser(ctx, bob, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatalf("bob list: %v", err)
	}
	if len(bobRows) != 1 || bobRows[0].UserID != bob || bobRows[0].Decision != "deny" {
		t.Errorf("bob sees %v", bobRows)
	}

	// A filter cannot widen the scope: asking for bob's rows as alice yields nothing of bob's.
	widened, err := rec.ListForUser(ctx, alice, audit.Filter{UserID: bob}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range widened {
		if r.UserID != alice {
			t.Errorf("filter widened alice's view to %q", r.UserID)
		}
	}

	// A user who recorded nothing sees nothing, and the system event is invisible to everyone but admins.
	carol := newUser(t, st, "carol")
	carolRows, err := rec.ListForUser(ctx, carol, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(carolRows) != 0 {
		t.Errorf("carol sees %d rows", len(carolRows))
	}
}

func TestIntegrationAdminSearchSeesAllUsersMetadataOnly(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "alice")
	bob := newUser(t, st, "bob")
	rec := audit.NewStoreRecorder(st)
	for _, ev := range []audit.Event{
		{UserID: alice, Tool: "github.create_issue", Decision: "allow", Outcome: "succeeded"},
		{UserID: bob, Tool: "github.create_issue", Decision: "deny", Outcome: "denied"},
		{UserID: bob, Tool: "jira.create_issue", Decision: "allow", Outcome: "failed", ErrorClass: "vendor_5xx"},
		{Decision: "auth_failed", ErrorClass: "token_expired"},
	} {
		if err := rec.Record(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	all, err := rec.AdminSearch(ctx, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatalf("admin search: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("admin sees %d rows, want 4: %v", len(all), toolsOf(all))
	}
	users := map[string]bool{}
	for _, r := range all {
		users[r.UserID] = true
	}
	if !users[alice] || !users[bob] || !users[""] {
		t.Errorf("admin search missing users: %v", users)
	}

	byUser, err := rec.AdminSearch(ctx, audit.Filter{UserID: bob}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(byUser) != 2 {
		t.Errorf("filter by user: %d rows, want 2", len(byUser))
	}
	byTool, err := rec.AdminSearch(ctx, audit.Filter{Tool: "github.create_issue", Decision: "deny"}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(byTool) != 1 || byTool[0].UserID != bob {
		t.Errorf("filter by tool+decision: %v", byTool)
	}
	byOutcome, err := rec.AdminSearch(ctx, audit.Filter{Outcome: "failed"}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(byOutcome) != 1 || byOutcome[0].ErrorClass != "vendor_5xx" {
		t.Errorf("filter by outcome: %v", byOutcome)
	}
	future, err := rec.AdminSearch(ctx, audit.Filter{Since: time.Now().Add(time.Hour)}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(future) != 0 {
		t.Errorf("since-filter in the future returned %d rows", len(future))
	}

	// Pagination.
	p1, err := rec.AdminSearch(ctx, audit.Filter{}, audit.Page{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := rec.AdminSearch(ctx, audit.Filter{}, audit.Page{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) != 3 || len(p2) != 1 || p1[0].ID == p2[0].ID {
		t.Errorf("pagination: page1=%d page2=%d", len(p1), len(p2))
	}
}

// TestIntegrationRecordNeverWritesAnotherUsersRow: the recorder inserts a
// user's event under that user's scope, so row-level security, not just
// the Go code, is what stops an event being filed under someone else.
func TestIntegrationRecordNeverWritesAnotherUsersRow(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "alice")
	bob := newUser(t, st, "bob")

	// Simulate a buggy caller: scoped as alice, trying to insert bob's row.
	err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		return tx.Audit().Create(ctx, &store.AuditEvent{UserID: &bob, Decision: "allow"})
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" || !strings.Contains(pgErr.Message, "row-level security") {
		t.Fatalf("expected RLS violation, got %v", err)
	}
	// A system event cannot be inserted through the user scope either.
	err = st.WithUser(ctx, alice, func(tx store.Tx) error {
		return tx.Audit().Create(ctx, &store.AuditEvent{Decision: "auth_failed"})
	})
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("expected RLS violation for a NULL user row under a user scope, got %v", err)
	}
}

func TestIntegrationRecordRejectsBadIDs(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	rec := audit.NewStoreRecorder(st)
	if err := rec.Record(t.Context(), audit.Event{UserID: "not-a-uuid", Decision: "allow"}); !errors.Is(err, store.ErrInvalidUserID) {
		t.Errorf("expected ErrInvalidUserID, got %v", err)
	}
	alice := newUser(t, st, "alice")
	if err := rec.Record(t.Context(), audit.Event{UserID: alice, Tool: "t", Decision: "allow", AccountLabel: "shared"}); err == nil {
		t.Error("expected an error for an invalid account label")
	}
	if err := rec.Record(t.Context(), audit.Event{UserID: alice, Tool: "t", Decision: "allow", TokenID: "junk"}); err == nil {
		t.Error("expected an error for a non-uuid token ID")
	}
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
