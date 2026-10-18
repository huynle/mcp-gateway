//go:build integration

package caps_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

func openCapsDB(t *testing.T) *store.Store {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	const db = "gateway_caps_test"
	var exists bool
	if err := admin.QueryRow(ctx, `select exists(select 1 from pg_database where datname=$1)`, db).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `create database `+db); err != nil {
			t.Fatal(err)
		}
	}
	u, _ := url.Parse(raw)
	u.Path = "/" + db
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatal(err)
	}
	super, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, q := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD 'app-test'", "ALTER ROLE gateway_jobs LOGIN PASSWORD 'jobs-test'",
		"TRUNCATE users, vendor_apps, policy_versions CASCADE",
	} {
		if _, err := super.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	app, jobs := *u, *u
	app.User = url.UserPassword("gateway_app", "app-test")
	jobs.User = url.UserPassword("gateway_jobs", "jobs-test")
	st, err := store.New(ctx, app.String(), store.WithJobsURL(jobs.String()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

type fixed struct {
	v       caps.Values
	refused atomic.Int64
}

func (f *fixed) Limit(_ context.Context, _ string, r caps.Resource) int { return f.v[r] }
func (f *fixed) Refused(context.Context, string, caps.Resource, int)    { f.refused.Add(1) }

func mkUser(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	u := &store.User{DisplayName: name}
	if err := st.WithJobs(t.Context(), func(tx store.Tx) error { return tx.Users().Create(t.Context(), u) }); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func mkApp(t *testing.T, st *store.Store, vendor, name string) string {
	t.Helper()
	a := &store.VendorApp{Vendor: vendor, Name: name, ClientID: "c", ClientSecret: store.Encrypted{KeyID: "k", WrappedDataKey: []byte{1}, Nonce: []byte{1}, Ciphertext: []byte{1}}}
	if err := st.WithJobs(t.Context(), func(tx store.Tx) error { return tx.VendorApps().Create(t.Context(), a) }); err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// parallel runs n creates at once and returns how many succeeded; every
// failure must be the cap refusal with the expected limit.
func parallel(t *testing.T, n, limit int, create func(i int) error) int {
	t.Helper()
	var wg sync.WaitGroup
	var ok atomic.Int64
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := create(i)
			var ce *caps.ExceededError
			switch {
			case err == nil:
				ok.Add(1)
			case errors.As(err, &ce) && ce.Limit == limit:
			default:
				t.Errorf("create %d: %v", i, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	return int(ok.Load())
}

func TestIntegrationReserveServersConcurrent(t *testing.T) {
	st := openCapsDB(t)
	ctx := t.Context()
	alice, bob := mkUser(t, st, "alice"), mkUser(t, st, "bob")
	l := &fixed{v: caps.Values{caps.Servers: 3}}
	create := func(user, name string) error {
		return st.WithUser(ctx, user, func(tx store.Tx) error {
			if err := caps.Reserve(ctx, tx, l, user, caps.Servers); err != nil {
				return err
			}
			return store.CreateMCPServer(ctx, tx, &store.MCPServer{Name: name, URL: "https://example.com/mcp", OwnerUserID: user})
		})
	}
	if got := parallel(t, 12, 3, func(i int) error { return create(alice, fmt.Sprintf("a%d", i)) }); got != 3 {
		t.Fatalf("parallel creates succeeded = %d, want exactly 3", got)
	}
	if l.refused.Load() != 9 {
		t.Errorf("refusals reported = %d, want 9", l.refused.Load())
	}
	// Other users have their own budget.
	if err := create(bob, "b1"); err != nil {
		t.Fatalf("bob: %v", err)
	}
	// 0 = unlimited.
	l.v[caps.Servers] = 0
	if err := create(alice, "a-unlimited"); err != nil {
		t.Fatalf("unlimited: %v", err)
	}
	// Deleting frees a slot.
	l.v[caps.Servers] = 4
	if err := create(alice, "a-over"); !errors.Is(err, caps.ErrExceeded) {
		t.Fatalf("at limit = %v", err)
	}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		s, err := store.GetMCPServerByName(ctx, tx, "a-unlimited")
		if err != nil {
			return err
		}
		return store.DeleteMCPServer(ctx, tx, s.ID)
	}); err != nil {
		t.Fatal(err)
	}
	if err := create(alice, "a-again"); err != nil {
		t.Fatalf("after delete: %v", err)
	}
	// A nil limiter never refuses (not wired).
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return caps.Reserve(ctx, tx, nil, alice, caps.Servers) }); err != nil {
		t.Fatalf("nil limiter: %v", err)
	}
}

func TestIntegrationReserveTunnelsConcurrentIgnoresRevoked(t *testing.T) {
	st := openCapsDB(t)
	ctx := t.Context()
	alice := mkUser(t, st, "alice")
	l := &fixed{v: caps.Values{caps.Tunnels: 2}}
	n := 0
	create := func(i int) error {
		return st.WithUser(ctx, alice, func(tx store.Tx) error {
			if err := caps.Reserve(ctx, tx, l, alice, caps.Tunnels); err != nil {
				return err
			}
			return store.CreateMCPTunnel(ctx, tx, &store.MCPTunnel{OwnerUserID: alice, Name: fmt.Sprintf("t%d", i), TokenHash: []byte(fmt.Sprintf("hash-%d-%d", n, i))})
		})
	}
	if got := parallel(t, 8, 2, create); got != 2 {
		t.Fatalf("parallel tunnels = %d, want 2", got)
	}
	var first string
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		ts, err := store.ListMCPTunnels(ctx, tx, alice)
		if err != nil || len(ts) == 0 {
			return fmt.Errorf("list: %v (%d)", err, len(ts))
		}
		first = ts[0].ID
		return store.RevokeMCPTunnel(ctx, tx, first, time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	n = 1
	if err := create(100); err != nil {
		t.Fatalf("after revoke: %v", err)
	}
	if err := create(101); !errors.Is(err, caps.ErrExceeded) {
		t.Fatalf("over = %v", err)
	}
}

func TestIntegrationReserveConnectionsPerAppAndTotal(t *testing.T) {
	st := openCapsDB(t)
	ctx := t.Context()
	alice := mkUser(t, st, "alice")
	appA, appB, anchor := mkApp(t, st, "github", "a"), mkApp(t, st, "slack", "b"), mkApp(t, st, "mcp", "federation")
	l := &fixed{v: caps.Values{caps.ConnectionsPerApp: 2, caps.ConnectionsTotal: 3}}
	create := func(app, ext string, capped bool) error {
		return st.WithUser(ctx, alice, func(tx store.Tx) error {
			if capped {
				if err := caps.ReserveConnection(ctx, tx, l, alice, app); err != nil {
					return err
				}
			}
			return tx.Connections().Create(ctx, &store.Connection{UserID: alice, VendorAppID: app, ExternalAccountID: ext, Label: store.AccountCompany, Status: store.ConnectionActive})
		})
	}
	// Anchor rows (internal accounts of user-added servers) never count.
	for i := range 4 {
		if err := create(anchor, fmt.Sprintf("anchor-%d", i), false); err != nil {
			t.Fatal(err)
		}
	}
	if got := parallel(t, 6, 2, func(i int) error { return create(appA, fmt.Sprintf("a%d", i), true) }); got != 2 {
		t.Fatalf("per-app parallel = %d, want 2", got)
	}
	var ce *caps.ExceededError
	if err := create(appA, "a-over", true); !errors.As(err, &ce) || ce.Resource != caps.ConnectionsPerApp {
		t.Fatalf("per app over = %v", err)
	}
	if err := create(appB, "b1", true); err != nil {
		t.Fatalf("b1: %v", err)
	}
	if err := create(appB, "b2", true); !errors.As(err, &ce) || ce.Resource != caps.ConnectionsTotal || ce.Limit != 3 {
		t.Fatalf("total over = %v", err)
	}
	// A revoked connection frees its slot.
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE connections SET status='revoked' WHERE external_account_id='b1'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := create(appB, "b3", true); err != nil {
		t.Fatalf("after revoke: %v", err)
	}
}

func TestIntegrationReservePendingApprovalsConcurrent(t *testing.T) {
	st := openCapsDB(t)
	ctx := t.Context()
	alice := mkUser(t, st, "alice")
	app := mkApp(t, st, "github", "a")
	conn := &store.Connection{UserID: alice, VendorAppID: app, ExternalAccountID: "x", Label: store.AccountCompany, Status: store.ConnectionActive}
	pv := &store.PolicyVersion{VersionHash: "h", Cedar: ""}
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return tx.PolicyVersions().Create(ctx, pv) }); err != nil {
		t.Fatal(err)
	}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return tx.Connections().Create(ctx, conn) }); err != nil {
		t.Fatal(err)
	}
	l := &fixed{v: caps.Values{caps.PendingApprovals: 3}}
	var seq atomic.Int64
	create := func(expires time.Time) error {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", seq.Add(1))
		return st.WithUser(ctx, alice, func(tx store.Tx) error {
			if err := caps.Reserve(ctx, tx, l, alice, caps.PendingApprovals); err != nil {
				return err
			}
			return store.CreateApproval(ctx, tx, &store.ApprovalRecord{Approval: store.Approval{ID: id, UserID: alice, ConnectionID: conn.ID, Tool: "github.x", Digest: []byte{1},
				Payload: &store.Encrypted{KeyID: "k", WrappedDataKey: []byte{1}, Nonce: []byte{1}, Ciphertext: []byte{1}}, PolicyVersionID: pv.ID, ExpiresAt: expires}})
		})
	}
	// An expired pending approval no longer counts.
	if err := create(time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := parallel(t, 10, 3, func(int) error { return create(time.Now().Add(time.Hour)) }); got != 3 {
		t.Fatalf("parallel approvals = %d, want 3", got)
	}
}
