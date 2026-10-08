//go:build integration

package store_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The integration tests need a PostgreSQL superuser URL in
// GATEWAY_TEST_DATABASE_URL (BYPASSRLS can only be granted by a superuser).
// They migrate the database up, give the two migration-created roles a LOGIN
// password for the duration of the run, and derive the gateway_app and
// gateway_jobs URLs from the test URL.

const (
	testAppPassword  = "gateway-app-test"
	testJobsPassword = "gateway-jobs-test"
)

type testEnv struct {
	superURL string
	appURL   string
	jobsURL  string
	super    *pgxpool.Pool
}

var (
	envOnce sync.Once
	envVal  *testEnv
	envErr  error
)

func setup(t *testing.T) *testEnv {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	envOnce.Do(func() {
		envVal, envErr = newTestEnv(context.Background(), raw)
	})
	if envErr != nil {
		t.Fatalf("test environment: %v", envErr)
	}
	return envVal
}

func newTestEnv(ctx context.Context, superURL string) (*testEnv, error) {
	if err := migrations.Up(ctx, superURL); err != nil {
		return nil, err
	}
	super, err := pgxpool.New(ctx, superURL)
	if err != nil {
		return nil, err
	}
	env := &testEnv{superURL: superURL, super: super}
	if err := env.grantLogin(ctx); err != nil {
		return nil, err
	}
	if env.appURL, err = withUser(superURL, "gateway_app", testAppPassword); err != nil {
		return nil, err
	}
	if env.jobsURL, err = withUser(superURL, "gateway_jobs", testJobsPassword); err != nil {
		return nil, err
	}
	return env, nil
}

// grantLogin gives the NOLOGIN roles from migration 00001 a test password.
func (e *testEnv) grantLogin(ctx context.Context) error {
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + testAppPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + testJobsPassword + "'",
	} {
		if err := execRetryingConcurrentUpdate(ctx, e.super, stmt); err != nil {
			return err
		}
	}
	return nil
}

func withUser(raw, user, password string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(user, password)
	return u.String(), nil
}

// open returns a Store on the gateway_app / gateway_jobs URLs.
func (e *testEnv) open(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(t.Context(), e.appURL, store.WithJobsURL(e.jobsURL))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

// reset empties every table so tests start from a known state.
func (e *testEnv) reset(t *testing.T) {
	t.Helper()
	// The audit trigger blocks DELETE (TRUNCATE is not DELETE, so it passes).
	_, err := e.super.Exec(t.Context(), `TRUNCATE
		users, identities, sessions, roles, role_assignments, policy_versions,
		user_restrictions, tokens, oauth_clients, oauth_refresh_tokens,
		vendor_apps, connections, connection_secrets, approvals,
		ledger_operations, ledger_attempts, audit_events, signing_keys, job_locks
		CASCADE`)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
}

// newUser creates a user through the bypass role (just-in-time user creation
// happens before a user scope exists) and returns its ID.
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

func newVendorApp(t *testing.T, st *store.Store) string {
	t.Helper()
	var id string
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		app := &store.VendorApp{
			Vendor:       "github",
			Name:         "company",
			ClientID:     "iv1.client",
			ClientSecret: testSecret("vendor"),
			Config:       []byte(`{}`),
			Enabled:      true,
		}
		if err := tx.VendorApps().Create(t.Context(), app); err != nil {
			return err
		}
		id = app.ID
		return nil
	})
	if err != nil {
		t.Fatalf("create vendor app: %v", err)
	}
	return id
}

func testSecret(tag string) store.Encrypted {
	return store.Encrypted{
		KeyID:          "dev-key-1",
		WrappedDataKey: []byte("wrapped-" + tag),
		Nonce:          []byte("nonce-" + tag),
		Ciphertext:     []byte("ciphertext-" + tag),
	}
}

func newConnection(t *testing.T, st *store.Store, userID, appID, account string) string {
	t.Helper()
	var id string
	err := st.WithUser(t.Context(), userID, func(tx store.Tx) error {
		c := &store.Connection{
			UserID:            userID,
			VendorAppID:       appID,
			ExternalAccountID: account,
			Label:             store.AccountCompany,
			DisplayName:       "octocat",
			Scopes:            []string{"repo"},
			Status:            store.ConnectionActive,
		}
		if err := tx.Connections().Create(t.Context(), c); err != nil {
			return err
		}
		id = c.ID
		return tx.Connections().PutSecret(t.Context(), &store.ConnectionSecret{
			ConnectionID: c.ID, UserID: userID, Secret: testSecret(account),
		})
	})
	if err != nil {
		t.Fatalf("create connection for %s: %v", userID, err)
	}
	return id
}

// --- migrations -------------------------------------------------------------

func TestIntegrationMigrationsRoundTrip(t *testing.T) {
	env := setup(t)
	ctx := t.Context()

	if err := migrations.DownTo(ctx, env.superURL, 0); err != nil {
		t.Fatalf("down to 0: %v", err)
	}
	if n := countTables(t, env.super); n != 0 {
		t.Fatalf("after down: %d tables left in public besides goose_db_version", n)
	}
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	v, err := migrations.Version(ctx, env.superURL)
	if err != nil {
		t.Fatal(err)
	}
	if v != store.ExpectedSchemaVersion {
		t.Fatalf("version after up = %d, want %d", v, store.ExpectedSchemaVersion)
	}
	// Up is idempotent.
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("second up: %v", err)
	}
	env.reset(t)
	st := env.open(t)
	if err := st.SchemaVersionMatches(ctx); err != nil {
		t.Fatalf("SchemaVersionMatches after round trip: %v", err)
	}
}

func countTables(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_tables
		WHERE schemaname = 'public' AND tablename <> 'goose_db_version'`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntegrationSchemaVersionMismatchDetected(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	env.reset(t)
	st := env.open(t)

	if err := st.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := st.SchemaVersionMatches(ctx); err != nil {
		t.Fatalf("SchemaVersionMatches on a migrated database: %v", err)
	}
	if err := migrations.Down(ctx, env.superURL); err != nil {
		t.Fatalf("down one: %v", err)
	}
	t.Cleanup(func() {
		if err := migrations.Up(context.Background(), env.superURL); err != nil {
			t.Fatalf("restore: %v", err)
		}
	})
	err := st.SchemaVersionMatches(ctx)
	if !errors.Is(err, store.ErrSchemaVersionMismatch) {
		t.Fatalf("SchemaVersionMatches after down = %v, want ErrSchemaVersionMismatch", err)
	}
	if !strings.Contains(err.Error(), "migrate") {
		t.Errorf("error %q should tell the operator to run migrations", err)
	}
}

// --- row-level security -----------------------------------------------------

func TestIntegrationRLSIsolatesUsers(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)

	userA := newUser(t, st, "alice")
	userB := newUser(t, st, "bob")
	appID := newVendorApp(t, st)
	connA := newConnection(t, st, userA, appID, "acct-a")
	connB := newConnection(t, st, userB, appID, "acct-b")

	err := st.WithUser(ctx, userA, func(tx store.Tx) error {
		// Own rows are visible.
		if _, err := tx.Connections().Get(ctx, connA); err != nil {
			return err
		}
		if _, err := tx.Users().Get(ctx, userA); err != nil {
			return err
		}
		// B's rows are not.
		if _, err := tx.Connections().Get(ctx, connB); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("A reading B's connection = %v, want ErrNotFound", err)
		}
		if _, err := tx.Connections().GetSecret(ctx, connB); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("A reading B's secret = %v, want ErrNotFound", err)
		}
		if _, err := tx.Users().Get(ctx, userB); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("A reading user B = %v, want ErrNotFound", err)
		}
		// B's rows cannot be updated or deleted: the statement succeeds but
		// matches nothing.
		tag, err := tx.Exec(ctx, `UPDATE connections SET display_name = 'pwned' WHERE id = $1`, connB)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Errorf("A updated %d of B's connections", tag.RowsAffected())
		}
		tag, err = tx.Exec(ctx, `DELETE FROM connections WHERE id = $1`, connB)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Errorf("A deleted %d of B's connections", tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithUser(A): %v", err)
	}

	// A cannot insert rows for B (WITH CHECK). PostgreSQL aborts the
	// transaction on the violation, so this runs in its own WithUser.
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		c := &store.Connection{
			UserID: userB, VendorAppID: appID, ExternalAccountID: "forged",
			Label: store.AccountPersonal, Status: store.ConnectionActive, Scopes: []string{},
		}
		return tx.Connections().Create(ctx, c)
	})
	if !isRLSViolation(err) {
		t.Errorf("A inserting a connection for B = %v, want RLS violation", err)
	}

	err = st.WithUser(ctx, userB, func(tx store.Tx) error {
		c, err := tx.Connections().Get(ctx, connB)
		if err != nil {
			return err
		}
		if c.DisplayName != "octocat" {
			t.Errorf("B's connection display_name = %q, was modified by A", c.DisplayName)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithUser(B): %v", err)
	}
}

// isRLSViolation reports whether err is PostgreSQL's "new row violates
// row-level security policy" (SQLSTATE 42501, insufficient_privilege).
func isRLSViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501" && strings.Contains(pgErr.Message, "row-level security")
}

func TestIntegrationNoUserScopeDeniesAccess(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)

	userA := newUser(t, st, "alice")
	appID := newVendorApp(t, st)
	newConnection(t, st, userA, appID, "acct-a")

	// A bare gateway_app connection with no app.user_id set.
	pool, err := pgxpool.New(ctx, env.appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	for _, table := range []string{"users", "connections", "connection_secrets", "audit_events", "tokens", "approvals", "ledger_operations"} {
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s without scope: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s: %d rows visible without a user scope", table, n)
		}
	}
	_, err = pool.Exec(ctx, `INSERT INTO connections (user_id, vendor_app_id, external_account_id, label, display_name, scopes, status)
		VALUES ($1, $2, 'no-scope', 'company', 'x', '{}', 'active')`, userA, appID)
	if !isRLSViolation(err) {
		t.Errorf("insert without scope = %v, want RLS violation", err)
	}

	// WithUser refuses an empty or malformed user ID before touching the DB.
	if err := st.WithUser(ctx, "", func(store.Tx) error { return nil }); !errors.Is(err, store.ErrInvalidUserID) {
		t.Errorf("WithUser(\"\") = %v, want ErrInvalidUserID", err)
	}
	// An unknown but well-formed user ID sees nothing and the setting is
	// transaction-local: the next transaction on the same pool is unscoped.
	err = st.WithUser(ctx, "00000000-0000-0000-0000-000000000001", func(tx store.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM connections").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("unknown user sees %d connections", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationJobsRoleSeesAllRows(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)

	userA := newUser(t, st, "alice")
	userB := newUser(t, st, "bob")
	appID := newVendorApp(t, st)
	newConnection(t, st, userA, appID, "acct-a")
	connB := newConnection(t, st, userB, appID, "acct-b")

	err := st.WithJobs(ctx, func(tx store.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM connections").Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			t.Errorf("jobs role sees %d connections, want 2", n)
		}
		if _, err := tx.Connections().Get(ctx, connB); err != nil {
			t.Errorf("jobs role reading B's connection: %v", err)
		}
		// Admin views show metadata across users but no secret columns.
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM admin_connections").Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			t.Errorf("admin_connections has %d rows for jobs role, want 2", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithJobs: %v", err)
	}

	// Through gateway_app the same views are security_invoker: RLS applies.
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM admin_connections").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("admin_connections has %d rows for user A, want 1", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithUser: %v", err)
	}
}

func TestIntegrationAdminViewsExposeNoSecrets(t *testing.T) {
	env := setup(t)
	ctx := t.Context()

	rows, err := env.super.Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name LIKE 'admin\_%' ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	views := map[string]bool{}
	for rows.Next() {
		var view, col string
		if err := rows.Scan(&view, &col); err != nil {
			t.Fatal(err)
		}
		views[view] = true
		for _, bad := range []string{"secret", "ciphertext", "nonce", "wrapped", "hash", "payload", "private", "cedar"} {
			if strings.Contains(col, bad) {
				t.Errorf("%s.%s exposes a secret/content column", view, col)
			}
		}
	}
	for _, want := range []string{"admin_users", "admin_tokens", "admin_connections", "admin_vendor_apps", "admin_signing_keys", "admin_approvals", "admin_ledger_operations", "admin_audit_events"} {
		if !views[want] {
			t.Errorf("missing admin view %s", want)
		}
	}
}

// --- audit append-only ------------------------------------------------------

func TestIntegrationAuditIsAppendOnly(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	userA := newUser(t, st, "alice")

	var eventID string
	err := st.WithUser(ctx, userA, func(tx store.Tx) error {
		ev := &store.AuditEvent{UserID: &userA, Tool: ptr("github.create_issue"), Decision: "allow", Outcome: ptr("succeeded")}
		if err := tx.Audit().Create(ctx, ev); err != nil {
			return err
		}
		eventID = ev.ID
		got, err := tx.Audit().Get(ctx, ev.ID)
		if err != nil {
			return err
		}
		if got.Decision != "allow" {
			t.Errorf("Decision = %q", got.Decision)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("insert audit: %v", err)
	}

	// gateway_app: no UPDATE/DELETE privilege (and the trigger would block it).
	for _, stmt := range []string{
		"UPDATE audit_events SET decision = 'deny' WHERE id = $1",
		"DELETE FROM audit_events WHERE id = $1",
	} {
		err := st.WithUser(ctx, userA, func(tx store.Tx) error {
			_, err := tx.Exec(ctx, stmt, eventID)
			return err
		})
		if err == nil {
			t.Errorf("gateway_app %q succeeded, want error", stmt)
		}
	}
	// gateway_jobs: UPDATE is always blocked by the trigger; DELETE only
	// passes with the explicit purge flag set (retention purge job).
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE audit_events SET decision = 'deny' WHERE id = $1", eventID)
		return err
	})
	if err == nil {
		t.Error("gateway_jobs UPDATE audit_events succeeded, want trigger error")
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, "DELETE FROM audit_events WHERE id = $1", eventID)
		return err
	})
	if err == nil {
		t.Error("gateway_jobs DELETE audit_events without purge flag succeeded, want trigger error")
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.Audit().Purge(ctx, time.Now().Add(time.Hour))
	})
	if err != nil {
		t.Errorf("Audit().Purge via jobs role: %v", err)
	}
	// The superuser (migration owner) is subject to the trigger too.
	if _, err := env.super.Exec(ctx, "UPDATE audit_events SET decision = 'x'"); err == nil {
		t.Error("superuser UPDATE audit_events succeeded, want trigger error")
	}
}

func ptr[T any](v T) *T { return &v }

// --- every entity has insert + get through the user scope -------------------

func TestIntegrationEntitiesInsertAndGet(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	userA := newUser(t, st, "alice")
	appID := newVendorApp(t, st)
	connA := newConnection(t, st, userA, appID, "acct-a")
	now := time.Now()

	err := st.WithUser(ctx, userA, func(tx store.Tx) error {
		// identities
		ident := &store.Identity{UserID: userA, Issuer: "https://login.example.com", Subject: "sub-1"}
		if err := tx.Identities().Create(ctx, ident); err != nil {
			return err
		}
		if got, err := tx.Identities().Get(ctx, ident.ID); err != nil || got.Subject != "sub-1" {
			t.Errorf("identity get = %+v, %v", got, err)
		}
		// sessions
		sess := &store.Session{UserID: userA, TokenHash: []byte("sess-hash"), ExpiresAt: now.Add(time.Hour)}
		if err := tx.Sessions().Create(ctx, sess); err != nil {
			return err
		}
		if _, err := tx.Sessions().Get(ctx, sess.ID); err != nil {
			t.Errorf("session get: %v", err)
		}
		// roles (global) + assignment + restriction
		role := &store.Role{Name: "engineer", Definition: []byte(`{"apps":{}}`), IsDefault: true}
		if err := tx.Roles().Create(ctx, role); err != nil {
			return err
		}
		if _, err := tx.Roles().Get(ctx, role.ID); err != nil {
			t.Errorf("role get: %v", err)
		}
		if err := tx.Roles().Assign(ctx, &store.RoleAssignment{UserID: userA, RoleID: role.ID}); err != nil {
			return err
		}
		if as, err := tx.Roles().AssignmentsForUser(ctx, userA); err != nil || len(as) != 1 {
			t.Errorf("assignments = %v, %v", as, err)
		}
		restr := &store.UserRestriction{UserID: userA, Definition: []byte(`{"deny":["slack.post_message"]}`)}
		if err := tx.Roles().CreateRestriction(ctx, restr); err != nil {
			return err
		}
		if rs, err := tx.Roles().RestrictionsForUser(ctx, userA); err != nil || len(rs) != 1 {
			t.Errorf("restrictions = %v, %v", rs, err)
		}
		// policy versions (global)
		pv := &store.PolicyVersion{VersionHash: "sha256:abc", Cedar: "permit(principal, action, resource);", Source: []byte(`{}`)}
		if err := tx.PolicyVersions().Create(ctx, pv); err != nil {
			return err
		}
		if got, err := tx.PolicyVersions().Get(ctx, pv.ID); err != nil || got.VersionHash != "sha256:abc" {
			t.Errorf("policy version get = %+v, %v", got, err)
		}
		// tokens
		tok := &store.Token{UserID: userA, PublicID: "entity01", Name: "laptop", TokenHash: []byte("tok-hash"), ReadOnly: true, Scope: []byte(`{"apps":["github"]}`), ExpiresAt: now.Add(24 * time.Hour)}
		if err := tx.Tokens().Create(ctx, tok); err != nil {
			return err
		}
		if got, err := tx.Tokens().Get(ctx, tok.ID); err != nil || !got.ReadOnly {
			t.Errorf("token get = %+v, %v", got, err)
		}
		// oauth clients (global) + refresh tokens
		cl := &store.OAuthClient{ClientID: "client-1", ClientName: "OpenCode", RedirectURIs: []string{"http://127.0.0.1/cb"}}
		if err := tx.OAuth().CreateClient(ctx, cl); err != nil {
			return err
		}
		if _, err := tx.OAuth().GetClient(ctx, cl.ID); err != nil {
			t.Errorf("oauth client get: %v", err)
		}
		rt := &store.OAuthRefreshToken{UserID: userA, ClientID: cl.ID, TokenHash: []byte("rt-hash"), Scope: []byte(`{}`), ExpiresAt: now.Add(30 * 24 * time.Hour)}
		if err := tx.OAuth().CreateRefreshToken(ctx, rt); err != nil {
			return err
		}
		if _, err := tx.OAuth().GetRefreshToken(ctx, rt.ID); err != nil {
			t.Errorf("refresh token get: %v", err)
		}
		// vendor apps (global) are readable with their secret by the service
		if app, err := tx.VendorApps().Get(ctx, appID); err != nil || app.ClientSecret.KeyID != "dev-key-1" {
			t.Errorf("vendor app get = %+v, %v", app, err)
		}
		// connection secret round trip
		if sec, err := tx.Connections().GetSecret(ctx, connA); err != nil || string(sec.Secret.Ciphertext) != "ciphertext-acct-a" {
			t.Errorf("connection secret = %+v, %v", sec, err)
		}
		// approvals
		payload := testSecret("payload")
		ap := &store.Approval{UserID: userA, ConnectionID: connA, Tool: "github.create_issue", Digest: []byte("digest"), Payload: &payload, Status: store.ApprovalPending, PolicyVersionID: pv.ID, ExpiresAt: now.Add(15 * time.Minute)}
		if err := tx.Approvals().Create(ctx, ap); err != nil {
			return err
		}
		if got, err := tx.Approvals().Get(ctx, ap.ID); err != nil || got.Payload == nil || got.Status != store.ApprovalPending {
			t.Errorf("approval get = %+v, %v", got, err)
		}
		// ledger: all five states are accepted
		for _, state := range []string{store.LedgerInProgress, store.LedgerSucceeded, store.LedgerFailed, store.LedgerUnknown, store.LedgerUnresolved} {
			op := &store.LedgerOperation{UserID: userA, ConnectionID: connA, Tool: "github.create_issue", State: state, IdempotencyKey: "key-" + state, WindowStart: now, WindowEnd: now.Add(24 * time.Hour), Digest: []byte("digest"), PolicyVersionID: pv.ID, ResultIDs: []byte(`{}`)}
			if state == store.LedgerSucceeded {
				op.ApprovalID = &ap.ID
				op.ResultIDs = []byte(`{"issue":42}`)
			}
			if err := tx.Ledger().CreateOperation(ctx, op); err != nil {
				return err
			}
			got, err := tx.Ledger().GetOperation(ctx, op.ID)
			if err != nil || got.State != state {
				t.Errorf("ledger op %s get = %+v, %v", state, got, err)
				continue
			}
			att := &store.LedgerAttempt{OperationID: op.ID, UserID: userA, AttemptNo: 1, Kind: store.AttemptCall, Outcome: state}
			if err := tx.Ledger().CreateAttempt(ctx, att); err != nil {
				return err
			}
			if atts, err := tx.Ledger().AttemptsForOperation(ctx, op.ID); err != nil || len(atts) != 1 {
				t.Errorf("attempts = %v, %v", atts, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithUser: %v", err)
	}

	// The ledger_state enum rejects anything outside the five states.
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		var pvID string
		if err := tx.QueryRow(ctx, "SELECT id FROM policy_versions LIMIT 1").Scan(&pvID); err != nil {
			return err
		}
		op := &store.LedgerOperation{UserID: userA, ConnectionID: connA, Tool: "x", State: "bogus", IdempotencyKey: "k", WindowStart: now, WindowEnd: now, PolicyVersionID: pvID, ResultIDs: []byte(`{}`)}
		return tx.Ledger().CreateOperation(ctx, op)
	})
	if err == nil {
		t.Error("ledger accepted state \"bogus\"")
	}

	// Global secrets and locks through the service / jobs roles.
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		sk := &store.SigningKey{KID: "k1", Algorithm: "EdDSA", PublicKey: []byte("pub"), PrivateKey: testSecret("priv"), Status: store.SigningKeyActive}
		if err := tx.SigningKeys().Create(ctx, sk); err != nil {
			return err
		}
		got, err := tx.SigningKeys().Get(ctx, sk.ID)
		if err != nil || string(got.PrivateKey.Ciphertext) != "ciphertext-priv" {
			t.Errorf("signing key get = %+v, %v", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("signing keys: %v", err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		lock := &store.JobLock{Name: "reconciler", Holder: "pod-1", ExpiresAt: now.Add(time.Minute)}
		if err := tx.JobLocks().Upsert(ctx, lock); err != nil {
			return err
		}
		got, err := tx.JobLocks().Get(ctx, "reconciler")
		if err != nil || got.Holder != "pod-1" {
			t.Errorf("job lock get = %+v, %v", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("job locks: %v", err)
	}
}

// A bare pgx connection as gateway_app must not be able to escalate by
// touching the roles or bypassing the schema (sanity check on grants).
func TestIntegrationAppRoleHasNoDDL(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, env.appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "CREATE TABLE should_fail (id int)"); err == nil {
		t.Error("gateway_app could CREATE TABLE in public")
		_, _ = env.super.Exec(ctx, "DROP TABLE should_fail")
	}
	if _, err := conn.Exec(ctx, "ALTER TABLE connections DISABLE ROW LEVEL SECURITY"); err == nil {
		t.Error("gateway_app could disable RLS")
	}
}

// execRetryingConcurrentUpdate runs stmt, retrying when PostgreSQL reports
// "tuple concurrently updated" (SQLSTATE XX000): every package's
// integration bootstrap ALTERs the same cluster-global roles and `go test`
// runs packages in parallel.
func execRetryingConcurrentUpdate(ctx context.Context, conn *pgxpool.Pool, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}
