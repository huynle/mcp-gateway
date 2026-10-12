//go:build integration

package admin_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// Store-backed tests of the admin Store adapter. They run against their
// own database (gateway_fedadmin_test, created from
// GATEWAY_TEST_DATABASE_URL) so they never race the store package's
// TRUNCATE (quirk 01mepmn6), and retry the concurrent ALTER ROLE (quirk
// aihn7hjb).

const (
	testDB      = "gateway_fedadmin_test"
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
	super0, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = super0.Close(ctx) }()
	var exists bool
	if err := super0.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, testDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := super0.Exec(ctx, `CREATE DATABASE `+testDB); err != nil {
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
		"TRUNCATE users, roles, role_assignments, mcp_servers, mcp_tunnels, netguard_allow_hosts CASCADE",
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

func newRole(t *testing.T, st *store.Store, name string, users ...string) string {
	t.Helper()
	ctx := t.Context()
	var id string
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		r := &store.Role{Name: name, Definition: []byte(`{}`)}
		if err := tx.Roles().Create(ctx, r); err != nil {
			return err
		}
		for _, u := range users {
			if err := tx.Roles().Assign(ctx, &store.RoleAssignment{UserID: u, RoleID: r.ID}); err != nil {
				return err
			}
		}
		id = r.ID
		return nil
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	return id
}

func visibleTo(t *testing.T, st *store.Store, userID string) []string {
	t.Helper()
	var out []string
	err := st.WithUser(t.Context(), userID, func(tx store.Tx) error {
		ss, err := store.ListVisibleMCPServers(t.Context(), tx, userID)
		for _, s := range ss {
			out = append(out, s.Name)
		}
		return err
	})
	if err != nil {
		t.Fatalf("visible servers: %v", err)
	}
	return out
}

// TestIntegrationAdminPublishMakesServerVisibleToRole is the acceptance
// test: an admin publishes a member's server to a role and the role's
// users see it in store.ListVisibleMCPServers; unpublishing hides it.
func TestIntegrationAdminPublishMakesServerVisibleToRole(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	as := admin.NewStore(st)
	owner, reader, outsider := newUser(t, st, "Olivia Owner"), newUser(t, st, "Rita Reader"), newUser(t, st, "Otto Outsider")
	eng := newRole(t, st, "engineering", reader)
	newRole(t, st, "sales", outsider)

	srv := &store.MCPServer{Name: "wiki", URL: "https://wiki.example/mcp", OwnerUserID: owner, AuthKind: store.MCPAuthNone}
	if err := st.WithUser(ctx, owner, func(tx store.Tx) error { return store.CreateMCPServer(ctx, tx, srv) }); err != nil {
		t.Fatalf("create server: %v", err)
	}
	if got := visibleTo(t, st, reader); len(got) != 0 {
		t.Fatalf("reader sees %v before publishing", got)
	}

	roles, err := as.ListRoles(ctx)
	if err != nil || len(roles) != 2 || roles[0].Name != "engineering" || roles[0].ID != eng {
		t.Fatalf("roles = %+v, %v", roles, err)
	}

	if err := as.SetPublishedRoles(ctx, srv.ID, []string{eng}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := visibleTo(t, st, reader); !slices.Equal(got, []string{"wiki"}) {
		t.Errorf("reader sees %v after publishing, want [wiki]", got)
	}
	if got := visibleTo(t, st, outsider); len(got) != 0 {
		t.Errorf("outsider sees %v", got)
	}
	got, err := as.GetServer(ctx, srv.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Audience != store.MCPAudiencePublished || !slices.Equal(got.PublishedRoleIDs, []string{eng}) || got.OwnerName != "Olivia Owner" {
		t.Errorf("admin view = %+v", got)
	}

	if err := as.SetPublishedRoles(ctx, srv.ID, nil); err != nil {
		t.Fatalf("unpublish: %v", err)
	}
	if got := visibleTo(t, st, reader); len(got) != 0 {
		t.Errorf("reader sees %v after unpublishing", got)
	}
	if got, _ := as.GetServer(ctx, srv.ID); got.Audience != store.MCPAudiencePrivate || len(got.PublishedRoleIDs) != 0 {
		t.Errorf("after unpublish = %+v", got)
	}
	if got := visibleTo(t, st, owner); !slices.Equal(got, []string{"wiki"}) {
		t.Errorf("owner sees %v, want [wiki]", got)
	}

	// Replacing the role set drops roles that are no longer chosen.
	sales := roles[1].ID
	if err := as.SetPublishedRoles(ctx, srv.ID, []string{eng, sales}); err != nil {
		t.Fatal(err)
	}
	if err := as.SetPublishedRoles(ctx, srv.ID, []string{sales}); err != nil {
		t.Fatal(err)
	}
	if got := visibleTo(t, st, reader); len(got) != 0 {
		t.Errorf("reader still sees %v after their role was dropped", got)
	}
	if got := visibleTo(t, st, outsider); !slices.Equal(got, []string{"wiki"}) {
		t.Errorf("sales member sees %v", got)
	}
}

func TestIntegrationAdminStore(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	as := admin.NewStore(st)
	owner, user := newUser(t, st, "Olivia Owner"), newUser(t, st, "Uma User")

	srv := &store.MCPServer{Name: "notes", URL: "https://notes.example/mcp", OwnerUserID: owner,
		AuthKind: store.MCPAuthAPIKey, CredentialMode: store.MCPCredentialShared}
	err := st.WithUser(ctx, owner, func(tx store.Tx) error {
		if err := store.CreateMCPServer(ctx, tx, srv); err != nil {
			return err
		}
		return store.SetMCPServerSharedSecret(ctx, tx, &store.MCPServerSharedSecret{ServerID: srv.ID,
			Secret: store.Encrypted{KeyID: "k1", Nonce: make([]byte, 12), Ciphertext: []byte("x"), WrappedDataKey: []byte("w")}, SecretKeys: []string{"api_key"}})
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	other := &store.MCPServer{Name: "calc", URL: "https://calc.example/mcp", OwnerUserID: user, AuthKind: store.MCPAuthOAuth}
	if err := st.WithUser(ctx, user, func(tx store.Tx) error { return store.CreateMCPServer(ctx, tx, other) }); err != nil {
		t.Fatal(err)
	}

	list, err := as.ListServers(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "calc" || list[1].Name != "notes" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if !list[1].HasSharedCredential || list[0].HasSharedCredential || list[1].OwnerName != "Olivia Owner" {
		t.Errorf("credential / owner columns: %+v", list)
	}
	if list[1].LatestVersion != 0 || list[1].PendingReview() {
		t.Errorf("no snapshot yet but %+v", list[1])
	}

	// Snapshot versions: pending v1 -> approved v1 -> pending v2.
	snaps := snapshot.NewService(st)
	sv := func(v int) *store.MCPSnapshot {
		return &store.MCPSnapshot{ServerID: srv.ID, Version: v, Tools: []byte(`[]`), Resources: []byte(`[]`),
			ResourceTemplates: []byte(`[]`), Prompts: []byte(`[]`), Review: []byte(`{}`)}
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.CreateMCPSnapshot(ctx, tx, sv(1)) }); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if s, _ := as.GetServer(ctx, srv.ID); s.LatestVersion != 1 || s.ApprovedVersion != 0 || !s.PendingReview() {
		t.Errorf("after v1: %+v", s)
	}
	if _, err := snaps.Approve(ctx, snapshot.Actor{UserID: user, Admin: true}, srv.ID, 1, snapshot.ReviewDecisions{}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if s, _ := as.GetServer(ctx, srv.ID); s.LatestVersion != 1 || s.ApprovedVersion != 1 || s.PendingReview() {
		t.Errorf("after approve: %+v", s)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.CreateMCPSnapshot(ctx, tx, sv(2)) }); err != nil {
		t.Fatal(err)
	}
	if s, _ := as.GetServer(ctx, srv.ID); s.LatestVersion != 2 || s.ApprovedVersion != 1 || !s.PendingReview() {
		t.Errorf("after v2: %+v", s)
	}

	// User connections are counted, never read.
	err = st.WithUser(ctx, user, func(tx store.Tx) error {
		return store.UpsertMCPUserConnection(ctx, tx, &store.MCPUserConnection{ServerID: other.ID, UserID: user, Status: store.MCPConnectionActive,
			Secret: store.Encrypted{KeyID: "k1", Nonce: make([]byte, 12), Ciphertext: []byte("x"), WrappedDataKey: []byte("w")}})
	})
	if err != nil {
		t.Fatalf("connection: %v", err)
	}
	if s, _ := as.GetServer(ctx, other.ID); s.UserConnectionCount != 1 {
		t.Errorf("connection count = %d", s.UserConnectionCount)
	}

	// Static client ID (no secret).
	if id, err := as.StaticClientID(ctx, other.ID); err != nil || id != "" {
		t.Errorf("static client before = %q, %v", id, err)
	}
	err = st.WithUser(ctx, user, func(tx store.Tx) error {
		return store.UpsertMCPOAuthClient(ctx, tx, &store.MCPOAuthClient{ServerID: other.ID, Method: store.MCPOAuthClientStatic, ClientID: "gw-client", Issuer: "https://as.example"})
	})
	if err != nil {
		t.Fatalf("oauth client: %v", err)
	}
	if id, err := as.StaticClientID(ctx, other.ID); err != nil || id != "gw-client" {
		t.Errorf("static client = %q, %v", id, err)
	}

	// Status, delete, not found.
	if err := as.SetStatus(ctx, srv.ID, store.MCPServerDisabled); err != nil {
		t.Fatal(err)
	}
	if s, _ := as.GetServer(ctx, srv.ID); s.Status != store.MCPServerDisabled {
		t.Errorf("status = %q", s.Status)
	}
	if _, err := as.GetServer(ctx, "20000000-0000-4000-8000-0000000000ff"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown server: %v", err)
	}
	if err := as.DeleteServer(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := as.GetServer(ctx, srv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("deleted server: %v", err)
	}

	// Tunnels: every user's, without the token hash.
	err = st.WithUser(ctx, owner, func(tx store.Tx) error {
		return store.CreateMCPTunnel(ctx, tx, &store.MCPTunnel{OwnerUserID: owner, Name: "laptop", TokenHash: []byte("0123456789abcdef0123456789abcdef")})
	})
	if err != nil {
		t.Fatal(err)
	}
	ts, err := as.ListTunnels(ctx)
	if err != nil || len(ts) != 1 || ts[0].Name != "laptop" || ts[0].OwnerUserID != owner || ts[0].OwnerName != "Olivia Owner" {
		t.Fatalf("tunnels = %+v, %v", ts, err)
	}
	if tun, err := as.GetTunnel(ctx, ts[0].ID); err != nil || tun.Name != "laptop" {
		t.Errorf("get tunnel = %+v, %v", tun, err)
	}
	if _, err := as.GetTunnel(ctx, "30000000-0000-4000-8000-0000000000ff"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown tunnel: %v", err)
	}

	// Allow-list.
	h := &store.NetguardAllowHost{Pattern: "10.20.0.0/16", Note: "lab", CreatedBy: &owner}
	if err := as.AddAllowHost(ctx, h); err != nil || h.ID == "" {
		t.Fatalf("add host: %v", err)
	}
	if err := as.AddAllowHost(ctx, &store.NetguardAllowHost{Pattern: "10.20.0.0/16"}); !errors.Is(err, admin.ErrDuplicate) {
		t.Errorf("duplicate host: %v", err)
	}
	if hs, err := as.ListAllowHosts(ctx); err != nil || len(hs) != 1 || hs[0].Note != "lab" {
		t.Errorf("hosts = %+v, %v", hs, err)
	}
	if del, err := as.DeleteAllowHost(ctx, h.ID); err != nil || del.Pattern != "10.20.0.0/16" {
		t.Errorf("delete host = %+v, %v", del, err)
	}
	if _, err := as.DeleteAllowHost(ctx, h.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("delete again: %v", err)
	}
}

// TestIntegrationAdminAddressChangeWithdrawsApproval: an admin's new
// address for a published server supersedes the approved snapshot (schema
// 17 trigger), so the server needs a re-review; the owner cannot make the
// same change (Brain task mpszh6h0).
func TestIntegrationAdminAddressChangeWithdrawsApproval(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	as := admin.NewStore(st)
	owner, reader := newUser(t, st, "Olivia Owner"), newUser(t, st, "Rita Reader")
	eng := newRole(t, st, "engineering", reader)
	srv := &store.MCPServer{Name: "wiki", URL: "https://wiki.example/mcp", OwnerUserID: owner, AuthKind: store.MCPAuthNone}
	if err := st.WithUser(ctx, owner, func(tx store.Tx) error { return store.CreateMCPServer(ctx, tx, srv) }); err != nil {
		t.Fatal(err)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateMCPSnapshot(ctx, tx, &store.MCPSnapshot{ServerID: srv.ID, Tools: []byte(`[]`)})
	}); err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewService(st)
	if _, err := snaps.Approve(ctx, snapshot.Actor{UserID: owner}, srv.ID, 1, snapshot.ReviewDecisions{}); err != nil {
		t.Fatalf("owner approve while private: %v", err)
	}
	if err := as.SetPublishedRoles(ctx, srv.ID, []string{eng}); err != nil {
		t.Fatal(err)
	}

	// The owner may not move the published server.
	moved := *srv
	moved.URL = "https://attacker.example/mcp"
	if err := st.WithUser(ctx, owner, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, &moved) }); !errors.Is(err, store.ErrMCPServerLocked) {
		t.Fatalf("owner URL change of a published server = %v, want ErrMCPServerLocked", err)
	}
	if s, _ := as.GetServer(ctx, srv.ID); s.ApprovedVersion != 1 || s.URL != srv.URL {
		t.Fatalf("after the refused owner edit: %+v", s)
	}

	if err := as.UpdateAddress(ctx, srv.ID, "https://wiki-v2.example/mcp"); err != nil {
		t.Fatalf("admin UpdateAddress: %v", err)
	}
	s, err := as.GetServer(ctx, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.URL != "https://wiki-v2.example/mcp" || s.ApprovedVersion != 0 || s.LatestVersion != 1 || !s.PendingReview() {
		t.Errorf("after the admin's address change: url %q approved %d latest %d", s.URL, s.ApprovedVersion, s.LatestVersion)
	}
	if _, err := snaps.Current(ctx, snapshot.Actor{UserID: reader}, srv.ID); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Errorf("reader's current snapshot = %v, want ErrNoSnapshot", err)
	}
	// Re-approval as admin serves it again.
	if _, err := snaps.Approve(ctx, snapshot.Actor{UserID: owner, Admin: true}, srv.ID, 1, snapshot.ReviewDecisions{}); err != nil {
		t.Fatalf("re-approve: %v", err)
	}
	if s, _ := as.GetServer(ctx, srv.ID); s.ApprovedVersion != 1 {
		t.Errorf("after re-approval: approved %d", s.ApprovedVersion)
	}
}
