//go:build integration

package auth

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The federation auth integration test runs the service over the real
// PostgreSQL store (row-level security, gateway_app / gateway_jobs) in its
// own database, like the connections package does, so it never races the
// store package's TRUNCATE.

const (
	fedAuthTestDB  = "gateway_fedauth_test"
	fedAppPassword = "gateway-app-test"
	fedJobsPass    = "gateway-jobs-test"
)

func execRetrying(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for range 20 {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func openPGStore(t *testing.T) *store.Store {
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, fedAuthTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+fedAuthTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + fedAuthTestDB
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + fedAppPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + fedJobsPass + "'",
		"TRUNCATE users, roles, mcp_servers CASCADE",
	} {
		if err := execRetrying(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", fedAppPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", fedJobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

// TestIntegrationFederationAuthPostgres runs the per-user OAuth flow and a
// shared API key over PostgreSQL: the owner publishes nothing herself (an
// admin does), a non-owner user of the published server is the first to
// connect (so DCR stores the client through the bypass scope), refresh
// takes the row lock, and the shared key reaches every user.
func TestIntegrationFederationAuthPostgres(t *testing.T) {
	st := openPGStore(t)
	ctx := t.Context()
	ids := map[string]string{}
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		for _, name := range []string{"owner", "alice", "bob"} {
			u := &store.User{DisplayName: name, Status: store.UserActive}
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
			ids[name] = u.ID
		}
		r := &store.Role{Name: "fedauth-users", Definition: []byte(`{}`)}
		if err := tx.Roles().Create(ctx, r); err != nil {
			return err
		}
		ids["role"] = r.ID
		for _, name := range []string{"alice", "bob"} {
			if err := tx.Roles().Assign(ctx, &store.RoleAssignment{UserID: ids[name], RoleID: r.ID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	n := newFakeNet(t)
	mcpURL, as := brainServer(t, n, "brain.example", nil)
	clock := &testClock{now: time.Now().UTC()}
	logs := &logBuffer{}
	svc, err := New(Options{HTTPClient: n.client(), Store: NewPostgresStore(st), Keys: testKeys(t), BaseURL: gatewayBase, Log: logs.logger(), Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}

	create := func(name, mode, kind, cfg string) *store.MCPServer {
		s := &store.MCPServer{Name: name, URL: mcpURL, OwnerUserID: ids["owner"], CredentialMode: mode, AuthKind: kind,
			AuthConfig: []byte(cfg), HeaderConfig: []byte(`{}`)}
		if err := st.WithUser(ctx, ids["owner"], func(tx store.Tx) error { return store.CreateMCPServer(ctx, tx, s) }); err != nil {
			t.Fatal(err)
		}
		if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.PublishMCPServer(ctx, tx, s.ID, []string{ids["role"]}) }); err != nil {
			t.Fatal(err)
		}
		return s
	}
	oauthSrv := create("brain-oauth", store.MCPCredentialPerUser, store.MCPAuthOAuth, `{}`)

	f := &fixture{t: t, n: n, svc: svc, clock: clock, logs: logs, as: as, server: oauthSrv, mcpURL: mcpURL}
	f.connect(ids["alice"])
	if as.registrations != 1 {
		t.Fatalf("registrations = %d", as.registrations)
	}
	// The client row is owner-only: alice cannot read it, the jobs role can.
	_ = st.WithUser(ctx, ids["alice"], func(tx store.Tx) error {
		if _, err := store.GetMCPOAuthClient(ctx, tx, oauthSrv.ID); err == nil {
			t.Error("alice reads the owner-only OAuth client row")
		}
		return nil
	})
	f.connect(ids["bob"])
	if as.registrations != 1 {
		t.Fatalf("registrations after bob = %d, want the client reused", as.registrations)
	}
	clock.Advance(2 * time.Hour)
	az, err := svc.ForUser(ctx, oauthSrv, ids["alice"])
	if err != nil {
		t.Fatal(err)
	}
	seen, err := f.whoami(ctx, az)
	if err != nil || !strings.HasPrefix(seen["Authorization"], "Bearer at-") || as.refreshCalls != 1 {
		t.Fatalf("whoami after expiry = %v %v (refreshes %d)", seen, err, as.refreshCalls)
	}
	// bob's connection is untouched by alice's refresh and invisible to her.
	_ = st.WithUser(ctx, ids["alice"], func(tx store.Tx) error {
		if _, err := store.GetMCPUserConnection(ctx, tx, oauthSrv.ID, ids["bob"]); err == nil {
			t.Error("alice reads bob's connection")
		}
		return nil
	})

	// Shared API key on a published server, set by the owner, used by both.
	mux := http.NewServeMux()
	mux.Handle("/mcp", gate(mcpHandler(), "", func(r *http.Request) bool { return r.Header.Get("X-Api-Key") == "pg-shared-key" }))
	keyBase := n.add("keyed.example", mux)
	keySrv := &store.MCPServer{Name: "keyed", URL: keyBase + "/mcp", OwnerUserID: ids["owner"], CredentialMode: store.MCPCredentialShared,
		AuthKind: store.MCPAuthAPIKey, AuthConfig: []byte(`{"api_key":{"header":"X-Api-Key"}}`), HeaderConfig: []byte(`{}`)}
	if err := st.WithUser(ctx, ids["owner"], func(tx store.Tx) error { return store.CreateMCPServer(ctx, tx, keySrv) }); err != nil {
		t.Fatal(err)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.PublishMCPServer(ctx, tx, keySrv.ID, []string{ids["role"]}) }); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSharedCredential(ctx, Actor{UserID: ids["alice"]}, keySrv.ID, Credential{APIKey: "x"}); err == nil {
		t.Fatal("alice set the owner's shared credential")
	}
	if err := svc.SetSharedCredential(ctx, Actor{UserID: ids["owner"]}, keySrv.ID, Credential{APIKey: "pg-shared-key"}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		az, err := svc.ForUser(ctx, keySrv, ids[u])
		if err != nil {
			t.Fatalf("ForUser(%s): %v", u, err)
		}
		seen, err := f.whoamiAt(ctx, keySrv, az)
		if err != nil || seen["X-Api-Key"] != "pg-shared-key" {
			t.Fatalf("%s: %v %v", u, seen, err)
		}
	}
	if strings.Contains(logs.String(), "pg-shared-key") {
		t.Fatal("shared key in logs")
	}
}
