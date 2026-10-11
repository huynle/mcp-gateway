//go:build integration

package tunnel_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The tunnel integration test runs against its own database
// (gateway_tunnel_test, created from GATEWAY_TEST_DATABASE_URL) so it never
// races the store package's tests, which truncate theirs (quirk 01mepmn6).

const (
	tunnelTestDB = "gateway_tunnel_test"
	appPassword  = "gateway-app-test"
	jobsPassword = "gateway-jobs-test"
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, tunnelTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+tunnelTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + tunnelTestDB
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPassword + "'",
		"TRUNCATE users, mcp_tunnels CASCADE",
	} {
		if err := execRetrying(ctx, super, stmt); err != nil {
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

// execRetrying retries role changes that race other packages' tests
// ("tuple concurrently updated").
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

func newUser(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	u := &store.User{DisplayName: name}
	if err := st.WithJobs(t.Context(), func(tx store.Tx) error { return tx.Users().Create(t.Context(), u) }); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestIntegrationTunnelStoreAndConnect(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	svc, err := tunnel.NewService(tunnel.Options{Store: tunnel.NewStore(st), Limits: tunnel.Limits{HeartbeatInterval: 50 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}

	tun, raw, err := svc.CreateTunnel(ctx, alice, "laptop")
	if err != nil {
		t.Fatalf("CreateTunnel: %v", err)
	}
	// Only the hash is stored.
	var stored []byte
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		got, err := store.GetMCPTunnel(ctx, tx, tun.ID)
		if got != nil {
			stored = got.TokenHash
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(tunnel.HashToken(raw)) || strings.Contains(string(stored), raw) {
		t.Fatal("stored token_hash is not SHA-256 of the token")
	}

	// Authenticate via WithJobs, Authorize owner-only.
	if got, err := svc.Authenticate(ctx, raw); err != nil || got.ID != tun.ID {
		t.Fatalf("Authenticate = %v, %v", got, err)
	}
	if err := svc.Authorize(ctx, alice, tun.ID); err != nil {
		t.Fatalf("Authorize(owner) = %v", err)
	}
	if err := svc.Authorize(ctx, bob, tun.ID); !errors.Is(err, tunnel.ErrForbidden) {
		t.Fatalf("Authorize(bob) = %v, want ErrForbidden", err)
	}
	if err := svc.Authorize(ctx, alice, "not-a-uuid"); !errors.Is(err, tunnel.ErrForbidden) {
		t.Fatalf("Authorize(bad id) = %v, want ErrForbidden", err)
	}

	// Live connection: last_seen_at is touched, requests flow.
	mux := http.NewServeMux()
	mux.Handle(tunnel.ConnectPath, svc.Handler())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	agent, err := tunnel.NewAgent(tunnel.AgentOptions{
		GatewayURL: srv.URL, Token: raw, HTTPClient: srv.Client(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "pong") }),
	})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- agent.Run(actx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for !svc.Online(tun.ID) {
		if time.Now().After(deadline) {
			t.Fatal("tunnel never came online")
		}
		time.Sleep(10 * time.Millisecond)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tunnel.URL(tun.ID, "/ping"), nil)
	resp, err := svc.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "pong" {
		t.Fatalf("body %q", body)
	}
	var seen *time.Time
	_ = st.WithUser(ctx, alice, func(tx store.Tx) error {
		got, err := store.GetMCPTunnel(ctx, tx, tun.ID)
		if got != nil {
			seen = got.LastSeenAt
		}
		return err
	})
	if seen == nil {
		t.Fatal("last_seen_at not set")
	}

	// Bob cannot revoke Alice's tunnel; Alice can, and the agent is cut off
	// and refused afterwards.
	if err := svc.Revoke(ctx, bob, tun.ID); !errors.Is(err, tunnel.ErrForbidden) {
		t.Fatalf("Revoke(bob) = %v, want ErrForbidden", err)
	}
	if err := svc.Revoke(ctx, alice, tun.ID); err != nil {
		t.Fatalf("Revoke(alice) = %v", err)
	}
	select {
	case err := <-done:
		done <- err
		if !errors.Is(err, tunnel.ErrRevoked) && !errors.Is(err, tunnel.ErrRejected) {
			t.Fatalf("agent after revoke: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent still connected after revoke")
	}
	if _, err := svc.Authenticate(ctx, raw); !errors.Is(err, tunnel.ErrUnauthorized) {
		t.Fatalf("Authenticate(revoked) = %v", err)
	}
}
