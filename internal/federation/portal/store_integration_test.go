//go:build integration

package portal_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// Store-backed test of the portal's Store adapter. It runs against its own
// database (gateway_portal_test, created from GATEWAY_TEST_DATABASE_URL) so
// it never races the store package's TRUNCATE (quirk 01mepmn6), and retries
// the concurrent ALTER ROLE (quirk aihn7hjb).

const (
	testDB      = "gateway_portal_test"
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
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPass + "'",
		"TRUNCATE users, roles, role_assignments, mcp_servers, mcp_tunnels CASCADE",
	} {
		if err := execRetrying(ctx, super, stmt); err != nil {
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

func execRetrying(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
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
		t.Fatalf("create user: %v", err)
	}
	return id
}

func publish(t *testing.T, st *store.Store, serverID string, users ...string) {
	t.Helper()
	ctx := t.Context()
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		r := &store.Role{Name: "readers-" + serverID[:8], Definition: []byte(`{}`)}
		if err := tx.Roles().Create(ctx, r); err != nil {
			return err
		}
		for _, u := range users {
			if err := tx.Roles().Assign(ctx, &store.RoleAssignment{UserID: u, RoleID: r.ID}); err != nil {
				return err
			}
		}
		return store.PublishMCPServer(ctx, tx, serverID, []string{r.ID})
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
}

func names(ss []store.MCPServer) string {
	var out []string
	for _, s := range ss {
		out = append(out, s.Name)
	}
	return strings.Join(out, ",")
}

func TestIntegrationPortalStoreVisibility(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	ps := portal.NewStore(st)
	owner, other, reader := newUser(t, st, "owner"), newUser(t, st, "other"), newUser(t, st, "reader")

	priv := &store.MCPServer{Name: "privnotes", URL: "https://p.example/mcp", AuthKind: store.MCPAuthAPIKey, CredentialMode: store.MCPCredentialShared}
	if err := ps.CreateServer(ctx, owner, priv); err != nil {
		t.Fatalf("create: %v", err)
	}
	if priv.ID == "" || priv.OwnerUserID != owner || priv.Audience != store.MCPAudiencePrivate {
		t.Fatalf("created %+v", priv)
	}
	pub := &store.MCPServer{Name: "pubwiki", URL: "https://w.example/mcp", AuthKind: store.MCPAuthNone}
	if err := ps.CreateServer(ctx, owner, pub); err != nil {
		t.Fatalf("create: %v", err)
	}
	publish(t, st, pub.ID, reader)

	if err := ps.CreateServer(ctx, other, &store.MCPServer{Name: "privnotes", URL: "https://x.example/mcp", AuthKind: store.MCPAuthNone}); !errors.Is(err, portal.ErrNameTaken) {
		t.Errorf("duplicate name: %v", err)
	}

	for user, want := range map[string]string{owner: "privnotes,pubwiki", reader: "pubwiki", other: ""} {
		got, err := ps.ListVisibleServers(ctx, user)
		if err != nil || names(got) != want {
			t.Errorf("visible to %s = %q (%v), want %q", user, names(got), err, want)
		}
	}
	if _, err := ps.GetServer(ctx, other, priv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("other user sees the private server: %v", err)
	}
	if _, err := ps.GetServer(ctx, reader, priv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reader sees the private server: %v", err)
	}
	if s, err := ps.GetServer(ctx, reader, pub.ID); err != nil || s.Name != "pubwiki" {
		t.Errorf("reader cannot see the published server: %v", err)
	}
	if _, err := ps.GetServer(ctx, owner, "not-a-uuid"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bad id: %v", err)
	}

	// Owner-only writes.
	edit := *pub
	edit.URL = "https://hijack.example/mcp"
	if err := ps.UpdateServer(ctx, reader, &edit); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reader updated: %v", err)
	}
	if err := ps.DeleteServer(ctx, reader, pub.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reader deleted: %v", err)
	}

	// Credential info: owner-only, no values.
	if err := st.WithUser(ctx, owner, func(tx store.Tx) error {
		return store.SetMCPServerSharedSecret(ctx, tx, &store.MCPServerSharedSecret{ServerID: priv.ID,
			Secret: store.Encrypted{KeyID: "k1", Nonce: make([]byte, 12), Ciphertext: []byte("x"), WrappedDataKey: []byte("w")}, SecretKeys: []string{"api_key"}})
	}); err != nil {
		t.Fatalf("set shared secret: %v", err)
	}
	if info, err := ps.CredentialInfo(ctx, owner, priv.ID); err != nil || !info.SharedSecret || strings.Join(info.SharedKeys, ",") != "api_key" {
		t.Errorf("owner info %+v %v", info, err)
	}
	if info, err := ps.CredentialInfo(ctx, reader, pub.ID); err != nil || info.SharedSecret || info.StaticClient {
		t.Errorf("reader info %+v %v", info, err)
	}

	// Tunnels are the owner's own.
	if err := st.WithUser(ctx, owner, func(tx store.Tx) error {
		return store.CreateMCPTunnel(ctx, tx, &store.MCPTunnel{OwnerUserID: owner, Name: "laptop", TokenHash: []byte("0123456789abcdef0123456789abcdef")})
	}); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	if ts, err := ps.ListTunnels(ctx, owner); err != nil || len(ts) != 1 {
		t.Errorf("owner tunnels %v %v", ts, err)
	}
	if ts, err := ps.ListTunnels(ctx, reader); err != nil || len(ts) != 0 {
		t.Errorf("reader tunnels %v %v", ts, err)
	}
	if cs, err := ps.ListConnections(ctx, reader); err != nil || len(cs) != 0 {
		t.Errorf("connections %v %v", cs, err)
	}

	if err := ps.DeleteServer(ctx, owner, priv.ID); err != nil {
		t.Errorf("owner delete: %v", err)
	}
}
