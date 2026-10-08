//go:build integration

package tokens_test

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// The tokens integration test runs against its own database
// (gateway_tokens_test, created from GATEWAY_TEST_DATABASE_URL) so it never
// races the store package's tests, which truncate their database (quirk
// 01mepmn6). Like them it needs a superuser URL and gives the two
// application roles a temporary LOGIN password.

const (
	tokensTestDB = "gateway_tokens_test"
	appPassword  = "gateway-app-test"
	jobsPassword = "gateway-jobs-test"
	dexIssuer    = "http://localhost:15556/dex"
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, tokensTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+tokensTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + tokensTestDB
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
		"TRUNCATE users, identities, sessions, roles, role_assignments, tokens CASCADE",
	} {
		if _, err := super.Exec(ctx, stmt); err != nil {
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

// signIn creates (or reuses) a user through the identity service so
// last_company_sign_in_at is set the way production sets it.
func signIn(t *testing.T, svc *identity.Service, subject, name string) *identity.Principal {
	t.Helper()
	res, err := svc.SignIn(t.Context(), "dex", identity.Claims{
		Issuer: dexIssuer, Subject: subject, Name: name, Email: subject + "@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("SignIn(%s): %v", subject, err)
	}
	return res.Principal
}

func TestIntegrationTokensPersistenceRLSAndDisableHook(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)

	idCfg := identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}
	idSvc, err := identity.New(idCfg, identity.NewPostgresStore(st), log)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	idSvc.SetClock(func() time.Time { return now })

	metrics := observability.NewMetrics()
	svc, err := tokens.New(tokens.Config{SignInMaxAge: 30 * 24 * time.Hour}, tokens.NewPostgresStore(st), metrics, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time { return now })
	idSvc.OnDisable(svc.DisableHook())

	alice := signIn(t, idSvc, "alice-subject", "Alice")
	bob := signIn(t, idSvc, "bob-subject", "Bob")

	// Persistence: create, list, authenticate round-trip through PostgreSQL.
	a1, err := svc.Create(ctx, alice.UserID, tokens.CreateRequest{Name: "laptop", ExpiryDays: 7, ReadOnly: true, AllowList: "github, slack.post_message"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	a2, err := svc.Create(ctx, alice.UserID, tokens.CreateRequest{Name: "desktop"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	b1, err := svc.Create(ctx, bob.UserID, tokens.CreateRequest{Name: "phone", ExpiryDays: 90})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	p, err := svc.Authenticate(ctx, a1.Raw)
	if err != nil {
		t.Fatalf("Authenticate(a1): %v", err)
	}
	if p.UserID != alice.UserID || p.TokenID != a1.Token.ID || !p.Scope.ReadOnly || !p.Scope.Allows("github.x") || p.Scope.Allows("jira.x") {
		t.Errorf("principal = %+v", p)
	}
	list, err := svc.List(ctx, alice.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != a2.Token.ID || list[1].ID != a1.Token.ID {
		t.Fatalf("alice's list = %+v", list)
	}
	if list[1].Scope.String() != "github, slack.post_message, read-only" || list[1].LastUsedAt == nil || !list[1].LastUsedAt.Equal(now) {
		t.Errorf("a1 as listed = %+v", list[1])
	}
	if want := now.Add(7 * 24 * time.Hour); !list[1].ExpiresAt.Equal(want) {
		t.Errorf("a1 expires %v, want %v", list[1].ExpiresAt, want)
	}

	// RLS: alice's list never contains bob's token; alice cannot revoke it.
	for _, tok := range list {
		if tok.ID == b1.Token.ID {
			t.Fatal("alice's list contains bob's token")
		}
	}
	if err := svc.Revoke(ctx, alice.UserID, b1.Token.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("alice revoking bob's token = %v, want ErrNotFound", err)
	}
	if _, err := svc.Authenticate(ctx, b1.Raw); err != nil {
		t.Errorf("bob's token broken by alice's revoke attempt: %v", err)
	}
	// And bob sees only his own.
	bobs, err := svc.List(ctx, bob.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(bobs) != 1 || bobs[0].ID != b1.Token.ID {
		t.Errorf("bob's list = %+v", bobs)
	}

	// Revocation is immediate.
	if err := svc.Revoke(ctx, alice.UserID, a2.Token.ID); err != nil {
		t.Fatal(err)
	}
	var authErr *tokens.Error
	if _, err := svc.Authenticate(ctx, a2.Raw); !errors.As(err, &authErr) || authErr.Reason != tokens.ReasonRevoked {
		t.Errorf("revoked token = %v, want revoked", err)
	}

	// Sign-in freshness against the real users row.
	now = now.Add(30*24*time.Hour + time.Second)
	if _, err := svc.Authenticate(ctx, b1.Raw); !errors.As(err, &authErr) || authErr.Reason != tokens.ReasonSignInStale {
		t.Errorf("stale sign-in = %v, want signin_stale", err)
	}
	signIn(t, idSvc, "bob-subject", "Bob") // a fresh company sign-in reactivates
	if _, err := svc.Authenticate(ctx, b1.Raw); err != nil {
		t.Errorf("after re-sign-in = %v, want ok", err)
	}
	// Expiry against the stored timestamp (a1 was given 7 days).
	if _, err := svc.Authenticate(ctx, a1.Raw); !errors.As(err, &authErr) || authErr.Reason != tokens.ReasonExpired {
		t.Errorf("expired token = %v, want expired", err)
	}

	// Disabling bob revokes his tokens inside the identity transaction.
	if err := idSvc.DisableUser(ctx, alice.UserID, bob.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, b1.Raw); !errors.As(err, &authErr) || authErr.Reason != tokens.ReasonRevoked {
		t.Errorf("after disable = %v, want revoked", err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		l, err := store.FindTokenByPublicID(ctx, tx, b1.Token.PublicID)
		if err != nil {
			return err
		}
		if l.Token.RevokedAt == nil || l.UserStatus != store.UserDisabled {
			t.Errorf("bob's token after disable = revoked %v, user %s", l.Token.RevokedAt, l.UserStatus)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationUnknownTokenIsNotFoundAndBadIDsAreHarmless(t *testing.T) {
	st := openTestStore(t)
	svc, err := tokens.New(tokens.Config{SignInMaxAge: tokens.DefaultSignInMaxAge}, tokens.NewPostgresStore(st), nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	g, err := tokens.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var authErr *tokens.Error
	if _, err := svc.Authenticate(context.Background(), g.Raw); !errors.As(err, &authErr) || authErr.Reason != tokens.ReasonUnknown {
		t.Errorf("never-stored token = %v, want unknown", err)
	}
	// A revoke with a non-uuid id is an error for the caller, not a crash.
	if err := svc.Revoke(context.Background(), "00000000-0000-4000-8000-000000000000", "not-a-uuid"); err == nil {
		t.Error("revoke of a non-uuid id succeeded")
	}
}
