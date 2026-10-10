//go:build integration

package identity_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The identity integration test runs against its own database
// (gateway_identity_test, created from GATEWAY_TEST_DATABASE_URL) so it
// never races the store package's tests, which truncate their database.
// Like them it needs a superuser URL and gives the two application roles a
// temporary LOGIN password.

const (
	identityTestDB = "gateway_identity_test"
	appPassword    = "gateway-app-test"
	jobsPassword   = "gateway-jobs-test"
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, identityTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+identityTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + identityTestDB
	superURL := u.String()
	if err := migrations.Up(ctx, superURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, superURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPassword + "'",
		"TRUNCATE users, identities, sessions, roles, role_assignments CASCADE",
	} {
		if err := execRetryingConcurrentUpdate(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPassword)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func TestIntegrationSignInPersistsUsersAndSessions(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	cfg := testConfig(dexProvider())
	cfg.BootstrapAdmins = []string{dexIssuer + "|admin-subject"}
	svc, err := identity.New(cfg, identity.NewPostgresStore(st), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	svc.SetClock(func() time.Time { return at })

	first, err := svc.SignIn(ctx, "dex", devClaims())
	if err != nil {
		t.Fatalf("first SignIn: %v", err)
	}
	if !first.Created || !slices.Equal(first.Principal.Roles, []string{"member"}) {
		t.Errorf("first sign-in = created %v roles %v", first.Created, first.Principal.Roles)
	}
	second, err := svc.SignIn(ctx, "dex", devClaims())
	if err != nil {
		t.Fatalf("second SignIn: %v", err)
	}
	if second.Created || second.Principal.UserID != first.Principal.UserID {
		t.Errorf("second sign-in = created %v user %s (first %s)", second.Created, second.Principal.UserID, first.Principal.UserID)
	}

	// Rows are there, under the user's own scope.
	err = st.WithUser(ctx, first.Principal.UserID, func(tx store.Tx) error {
		u, err := tx.Users().Get(ctx, first.Principal.UserID)
		if err != nil {
			return err
		}
		if u.LastCompanySignInAt == nil || !u.LastCompanySignInAt.Equal(at) {
			t.Errorf("last_company_sign_in_at = %v, want %v", u.LastCompanySignInAt, at)
		}
		ident, err := store.FindIdentity(ctx, tx, dexIssuer, devClaims().Subject)
		if err != nil {
			return err
		}
		if ident.UserID != u.ID {
			t.Errorf("identity bound to %s, want %s", ident.UserID, u.ID)
		}
		roles, err := store.RolesForUser(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if len(roles) != 1 || roles[0].Name != "member" {
			t.Errorf("roles = %+v", roles)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	// The session cookie resolves through the middleware.
	whoami := func(cookie *http.Cookie) *identity.Principal {
		var got *identity.Principal
		h := svc.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = identity.PrincipalFrom(r.Context())
		}))
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		req.AddCookie(cookie)
		h.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}
	p := whoami(second.Cookie)
	if p == nil || p.UserID != first.Principal.UserID || p.SessionID != second.Principal.SessionID || p.CSRFToken != second.Principal.CSRFToken {
		t.Fatalf("middleware principal = %+v, want the second session", p)
	}
	if whoami(first.Cookie) == nil {
		t.Error("the first browser's session should still be live")
	}

	// Bootstrap admin from a different subject gets its own user.
	adminClaims := devClaims()
	adminClaims.Subject = "admin-subject"
	adminClaims.Email = "admin@example.com"
	admin, err := svc.SignIn(ctx, "dex", adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if !admin.Principal.IsAdmin() || admin.Principal.UserID == first.Principal.UserID {
		t.Errorf("admin principal = %+v", admin.Principal)
	}
	users, err := svc.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Errorf("ListUsers = %d users, want 2", len(users))
	}

	// Disable: sessions revoked, hook sees a real transaction.
	var hookSawUser bool
	svc.OnDisable(func(ctx context.Context, tx store.Tx, userID string) error {
		if tx == nil {
			return errors.New("hook got a nil transaction")
		}
		u, err := tx.Users().Get(ctx, userID)
		if err != nil {
			return err
		}
		hookSawUser = u.Status == store.UserDisabled
		return nil
	})
	if err := svc.DisableUser(ctx, admin.Principal.UserID, first.Principal.UserID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if !hookSawUser {
		t.Error("hook should run after the status change, in the same transaction")
	}
	if whoami(second.Cookie) != nil || whoami(first.Cookie) != nil {
		t.Error("disabled user's sessions must be dead")
	}
	if _, err := svc.SignIn(ctx, "dex", devClaims()); !errors.Is(err, identity.ErrUserDisabled) {
		t.Errorf("disabled sign-in = %v, want ErrUserDisabled", err)
	}
	if err := svc.SetUserRole(ctx, admin.Principal.UserID, first.Principal.UserID, identity.AdminRole); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	users, _ = svc.ListUsers(ctx)
	for _, u := range users {
		if u.ID == first.Principal.UserID && (u.Status != store.UserDisabled || !slices.Equal(u.Roles, []string{"admin"})) {
			t.Errorf("user after disable + role change = %+v", u)
		}
	}
}

// execRetryingConcurrentUpdate runs stmt, retrying when PostgreSQL reports
// "tuple concurrently updated" (SQLSTATE XX000): every package's
// integration bootstrap ALTERs the same cluster-global roles and `go test`
// runs packages in parallel.
func execRetryingConcurrentUpdate(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}
