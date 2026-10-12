//go:build integration

package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The Postgres adapter against its own database (gateway_federation_test,
// quirk 01mepmn6), retrying the concurrent ALTER ROLE (quirk aihn7hjb).

const (
	testDB      = "gateway_federation_test"
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
		"TRUNCATE users, roles, role_assignments, mcp_servers, vendor_apps, connections, netguard_allow_hosts CASCADE",
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

func testKeys(t *testing.T) crypto.KeyProvider {
	t.Helper()
	k, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestIntegrationPostgresStore(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	ps := NewPostgresStore(st, testKeys(t))
	owner, other := newUser(t, st, "Owner"), newUser(t, st, "Other")

	// CreateServer runs as the owner; the server starts private.
	srv := &store.MCPServer{Name: "notes", URL: "https://notes.example.com/mcp", OwnerUserID: owner,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone}
	if err := ps.CreateServer(ctx, srv); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if srv.ID == "" || srv.Audience != store.MCPAudiencePrivate {
		t.Fatalf("created server = %+v", srv)
	}
	all, err := ps.ListServers(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("ListServers = %v, %v", all, err)
	}
	if got, err := ps.GetServer(ctx, srv.ID); err != nil || got.Name != "notes" {
		t.Fatalf("GetServer = %+v, %v", got, err)
	}
	if ids, _ := ps.VisibleServerIDs(ctx, owner); !slices.Equal(ids, []string{srv.ID}) {
		t.Errorf("owner visible = %v", ids)
	}
	if ids, _ := ps.VisibleServerIDs(ctx, other); len(ids) != 0 {
		t.Errorf("other user sees a private server: %v", ids)
	}
	// Only the owner may update.
	srv.Name = "notes2"
	if err := ps.UpdateServer(ctx, other, srv); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UpdateServer by another user = %v, want ErrNotFound", err)
	}
	if err := ps.UpdateServer(ctx, owner, srv); err != nil {
		t.Errorf("UpdateServer by the owner = %v", err)
	}
	if _, err := ps.UserConnection(ctx, owner, srv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UserConnection without a row = %v, want ErrNotFound", err)
	}

	// Anchor accounts: one connections row per (user, server), stable,
	// relabelled and revived, owned by the user (RLS), under the disabled
	// "mcp" vendor app.
	id1, err := ps.AnchorAccount(ctx, owner, srv, store.AccountCompany)
	if err != nil {
		t.Fatalf("AnchorAccount: %v", err)
	}
	id2, err := ps.AnchorAccount(ctx, owner, srv, store.AccountCompany)
	if err != nil || id2 != id1 {
		t.Fatalf("second AnchorAccount = %s, %v; want %s", id2, err, id1)
	}
	if _, err := ps.AnchorAccount(ctx, owner, srv, store.AccountPersonal); err != nil {
		t.Fatal(err)
	}
	var conn *store.Connection
	err = st.WithUser(ctx, owner, func(tx store.Tx) error {
		var err error
		conn, err = tx.Connections().Get(ctx, id1)
		return err
	})
	if err != nil || conn.Label != store.AccountPersonal || conn.DisplayName != "notes2" || conn.Status != store.ConnectionActive {
		t.Fatalf("anchor row = %+v, %v", conn, err)
	}
	err = st.WithUser(ctx, other, func(tx store.Tx) error {
		_, err := tx.Connections().Get(ctx, id1)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another user reads the anchor: %v", err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		app, err := store.FindVendorApp(ctx, tx, AnchorVendor, AnchorAppName)
		if err != nil {
			return err
		}
		if app.Enabled || app.ID != conn.VendorAppID {
			return fmt.Errorf("anchor vendor app = %+v", app)
		}
		return store.SetConnectionStatus(ctx, tx, id1, store.ConnectionRevoked)
	})
	if err != nil {
		t.Fatal(err)
	}
	if id3, err := ps.AnchorAccount(ctx, owner, srv, store.AccountPersonal); err != nil || id3 != id1 {
		t.Fatalf("revived anchor = %s, %v", id3, err)
	}

	// Concurrent first use by many requests yields one row.
	srvB := &store.MCPServer{Name: "other", URL: "https://other.example.com/mcp", OwnerUserID: other}
	if err := ps.CreateServer(ctx, srvB); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ids := make([]string, 8)
	errs := make([]error, 8)
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i], errs[i] = NewPostgresStore(st, testKeys(t)).AnchorAccount(ctx, other, srvB, store.AccountCompany)
		}()
	}
	wg.Wait()
	for i := range ids {
		if errs[i] != nil || ids[i] != ids[0] {
			t.Errorf("concurrent anchor %d = %s, %v (first %s)", i, ids[i], errs[i], ids[0])
		}
	}

	// The netguard allow list loader reads netguard_allow_hosts.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: "127.0.0.1", Note: "test"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if hosts, err := AllowHostsLoader(st)(ctx); err != nil || !slices.Equal(hosts, []string{"127.0.0.1"}) {
		t.Errorf("allow hosts = %v, %v", hosts, err)
	}
}

// TestIntegrationPostgresStoreNameTakenAndGatewayAccount (Brain task
// 99b5yzdb): a duplicate server name is ErrServerNameTaken, and the
// gateway.* management tools get one anchor connection per user (owned by
// the user, under the disabled "mcp" vendor app, external id
// "gateway-management", label company).
func TestIntegrationPostgresStoreNameTakenAndGatewayAccount(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	ps := NewPostgresStore(st, testKeys(t))
	owner, other := newUser(t, st, "Owner"), newUser(t, st, "Other")

	first := &store.MCPServer{Name: "dup", URL: "https://dup.example.com/mcp", OwnerUserID: owner,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone}
	if err := ps.CreateServer(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := &store.MCPServer{Name: "dup", URL: "https://dup2.example.com/mcp", OwnerUserID: other,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone}
	if err := ps.CreateServer(ctx, second); !errors.Is(err, ErrServerNameTaken) {
		t.Fatalf("duplicate name = %v, want ErrServerNameTaken", err)
	}

	ga, ok := ps.(GatewayAccounts)
	if !ok {
		t.Fatal("the Postgres store does not provide gateway accounts")
	}
	id1, err := ga.GatewayAccount(ctx, owner)
	if err != nil {
		t.Fatalf("GatewayAccount: %v", err)
	}
	if id2, err := ga.GatewayAccount(ctx, owner); err != nil || id2 != id1 {
		t.Fatalf("second GatewayAccount = %s, %v; want %s", id2, err, id1)
	}
	idOther, err := ga.GatewayAccount(ctx, other)
	if err != nil || idOther == id1 {
		t.Fatalf("other user's GatewayAccount = %s, %v", idOther, err)
	}
	var conn *store.Connection
	err = st.WithUser(ctx, owner, func(tx store.Tx) error {
		var err error
		conn, err = tx.Connections().Get(ctx, id1)
		return err
	})
	if err != nil || conn.ExternalAccountID != GatewayAccountExternalID || conn.Label != store.AccountCompany || conn.Status != store.ConnectionActive {
		t.Fatalf("gateway anchor row = %+v, %v", conn, err)
	}
	err = st.WithUser(ctx, other, func(tx store.Tx) error {
		_, err := tx.Connections().Get(ctx, id1)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another user reads the gateway anchor: %v", err)
	}
}
