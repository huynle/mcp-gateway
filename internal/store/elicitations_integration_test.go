//go:build integration

package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// Integration tests for upstream URL elicitations and server elicitation
// origins (migration 00032,
// docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md).

func newElicitation(t *testing.T, st *store.Store, owner, serverID, name string, expires time.Time) *store.UpstreamElicitation {
	t.Helper()
	e := &store.UpstreamElicitation{
		LinkHash: secretHash("elicit-" + name), OwnerUserID: owner, ServerID: serverID, HarnessID: "tok-" + owner,
		URL: "https://connect.example.com/" + name, UpstreamElicitationID: "up-" + name, Message: "msg " + name,
		CreatedAt: expires.Add(-10 * time.Minute), ExpiresAt: expires,
	}
	err := st.WithUser(t.Context(), owner, func(tx store.Tx) error { return store.CreateUpstreamElicitation(t.Context(), tx, e) })
	if err != nil {
		t.Fatalf("create elicitation %s: %v", name, err)
	}
	if e.ID == "" || e.CreatedAt.IsZero() {
		t.Fatalf("created elicitation = %+v", e)
	}
	return e
}

func TestIntegrationUpstreamElicitationsLifecycleAndRowSecurity(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	srv := newMCPServer(t, st, alice, "alice-elicit")
	now := time.Now()
	e := newElicitation(t, st, alice, srv.ID, "one", now.Add(10*time.Minute))

	// Bob sees nothing and changes nothing.
	err := st.WithUser(ctx, bob, func(tx store.Tx) error {
		if _, err := store.GetUpstreamElicitationByLink(ctx, tx, alice, e.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob get alice's = %v, want ErrNotFound", err)
		}
		if _, err := store.GetUpstreamElicitationByLink(ctx, tx, bob, e.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob get as himself = %v, want ErrNotFound", err)
		}
		if _, err := store.MarkUpstreamElicitationOpened(ctx, tx, alice, e.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob open = %v, want ErrNotFound", err)
		}
		if _, err := store.MarkUpstreamElicitationCancelled(ctx, tx, alice, e.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob cancel = %v, want ErrNotFound", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE upstream_elicitations SET url = 'https://evil.example' WHERE id = $1`, e.ID)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("bob raw update = %d rows, %v", tag.RowsAffected(), err)
		}
		if n, err := store.CountLiveUpstreamElicitations(ctx, tx, alice, now); err != nil || n != 0 {
			t.Errorf("bob counts alice's = %d, %v", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Bob cannot insert a row owned by alice (WITH CHECK).
	forged := *e
	forged.ID, forged.LinkHash = "", secretHash("elicit-forged")
	if err := st.WithUser(ctx, bob, func(tx store.Tx) error { return store.CreateUpstreamElicitation(ctx, tx, &forged) }); err == nil {
		t.Error("bob created an elicitation owned by alice")
	}
	// gateway_app may not delete.
	err = st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM upstream_elicitations WHERE id = $1`, e.ID)
		return err
	})
	if !isPermissionDenied(err) {
		t.Errorf("app DELETE = %v, want permission denied", err)
	}

	// Link hashes are unique.
	dup := *e
	dup.ID = ""
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.CreateUpstreamElicitation(ctx, tx, &dup) }); pgCode(err) != "23505" {
		t.Errorf("duplicate link hash = %v, want 23505", err)
	}

	// Alice: read, open (repeatable, first time kept), count, cancel.
	err = st.WithUser(ctx, alice, func(tx store.Tx) error {
		got, err := store.GetUpstreamElicitationByLink(ctx, tx, alice, e.LinkHash, now)
		if err != nil {
			return err
		}
		if got.ID != e.ID || got.URL != e.URL || got.Message != e.Message || got.UpstreamElicitationID != e.UpstreamElicitationID ||
			got.HarnessID != e.HarnessID || got.ServerID != srv.ID || got.OpenedAt != nil || got.CancelledAt != nil {
			t.Errorf("got = %+v", got)
		}
		if n, err := store.CountLiveUpstreamElicitations(ctx, tx, alice, now); err != nil || n != 1 {
			t.Errorf("live = %d, %v; want 1", n, err)
		}
		if err := store.LockUpstreamElicitations(ctx, tx, alice); err != nil {
			t.Errorf("lock: %v", err)
		}
		first, err := store.MarkUpstreamElicitationOpened(ctx, tx, alice, e.LinkHash, now)
		if err != nil || first.OpenedAt == nil {
			t.Fatalf("open = %+v, %v", first, err)
		}
		again, err := store.MarkUpstreamElicitationOpened(ctx, tx, alice, e.LinkHash, now.Add(time.Minute))
		if err != nil || again.OpenedAt == nil || !again.OpenedAt.Equal(*first.OpenedAt) {
			t.Errorf("second open = %+v, %v; want live with the first opened_at", again, err)
		}
		c, err := store.MarkUpstreamElicitationCancelled(ctx, tx, alice, e.LinkHash, now)
		if err != nil || c.CancelledAt == nil {
			t.Errorf("cancel = %+v, %v", c, err)
		}
		if _, err := store.GetUpstreamElicitationByLink(ctx, tx, alice, e.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("get cancelled = %v, want ErrNotFound", err)
		}
		if _, err := store.MarkUpstreamElicitationOpened(ctx, tx, alice, e.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("open cancelled = %v, want ErrNotFound", err)
		}
		if _, err := store.MarkUpstreamElicitationCancelled(ctx, tx, alice, e.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cancel twice = %v, want ErrNotFound", err)
		}
		if n, _ := store.CountLiveUpstreamElicitations(ctx, tx, alice, now); n != 0 {
			t.Errorf("live after cancel = %d, want 0", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Expired rows are not live.
	old := newElicitation(t, st, alice, srv.ID, "old", now.Add(-time.Second))
	err = st.WithUser(ctx, alice, func(tx store.Tx) error {
		if _, err := store.GetUpstreamElicitationByLink(ctx, tx, alice, old.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("get expired = %v, want ErrNotFound", err)
		}
		if _, err := store.MarkUpstreamElicitationOpened(ctx, tx, alice, old.LinkHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("open expired = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Limits of the columns.
	long := &store.UpstreamElicitation{LinkHash: secretHash("elicit-long"), OwnerUserID: alice, ServerID: srv.ID,
		URL: "https://x.example/" + repeat("a", 2048), ExpiresAt: now.Add(time.Minute)}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.CreateUpstreamElicitation(ctx, tx, long) }); pgCode(err) != "23514" {
		t.Errorf("2048+ byte url = %v, want check violation", err)
	}
	long.URL, long.Message = "https://x.example/", repeat("é", 501)
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.CreateUpstreamElicitation(ctx, tx, long) }); pgCode(err) != "23514" {
		t.Errorf("501-char message = %v, want check violation", err)
	}
	long.Message = repeat("é", 500)
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.CreateUpstreamElicitation(ctx, tx, long) }); err != nil {
		t.Errorf("500-char message = %v", err)
	}

	// Deleting the server removes its elicitations.
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.DeleteMCPServer(ctx, tx, srv.ID) }); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM upstream_elicitations WHERE server_id = $1`, srv.ID).Scan(&n); err != nil || n != 0 {
		t.Errorf("rows after server delete = %d, %v", n, err)
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for range n {
		out = append(out, s...)
	}
	return string(out)
}

func TestIntegrationUpstreamElicitationsPurgeExpired(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	srv := newMCPServer(t, st, alice, "alice-purge")
	now := time.Now()
	live := newElicitation(t, st, alice, srv.ID, "live", now.Add(5*time.Minute))
	recent := newElicitation(t, st, alice, srv.ID, "recent", now.Add(-time.Hour))
	stale := newElicitation(t, st, alice, srv.ID, "stale", now.Add(-25*time.Hour))

	// The request path may not purge (no DELETE grant).
	err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := store.PurgeExpiredUpstreamElicitations(ctx, tx, now.Add(-24*time.Hour))
		return err
	})
	if !isPermissionDenied(err) {
		t.Errorf("app purge = %v, want permission denied", err)
	}
	var deleted int64
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		deleted, err = store.PurgeExpiredUpstreamElicitations(ctx, tx, now.Add(-24*time.Hour))
		return err
	})
	if err != nil || deleted != 1 {
		t.Fatalf("purge = %d, %v; want 1", deleted, err)
	}
	for _, c := range []struct {
		e    *store.UpstreamElicitation
		want int
	}{{live, 1}, {recent, 1}, {stale, 0}} {
		var n int
		if err := env.super.QueryRow(ctx, `SELECT count(*) FROM upstream_elicitations WHERE id = $1`, c.e.ID).Scan(&n); err != nil || n != c.want {
			t.Errorf("%s rows = %d, %v; want %d", c.e.Message, n, err, c.want)
		}
	}
}

func TestIntegrationUpstreamElicitationsDeletedWithUser(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob, carol := newUser(t, st, "Alice"), newUser(t, st, "Bob"), newUser(t, st, "Carol")
	// carol's published server: the server cascade is not what removes
	// alice's rows.
	pub := newMCPServer(t, st, carol, "carol-elicit")
	role := newRoleFor(t, st, "elicit-role", alice, bob)
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.PublishMCPServer(ctx, tx, pub.ID, []string{role}) }); err != nil {
		t.Fatal(err)
	}
	newElicitation(t, st, alice, pub.ID, "a1", time.Now().Add(time.Minute))
	b := newElicitation(t, st, bob, pub.ID, "b1", time.Now().Add(time.Minute))
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.DeleteUserData(ctx, tx, alice, time.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM upstream_elicitations WHERE owner_user_id = $1`, alice).Scan(&n); err != nil || n != 0 {
		t.Errorf("alice's rows after deletion = %d, %v", n, err)
	}
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM upstream_elicitations WHERE id = $1`, b.ID).Scan(&n); err != nil || n != 1 {
		t.Errorf("bob's row = %d, %v; want kept", n, err)
	}
}

func TestIntegrationMCPServerElicitationOrigins(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "alice"), newUser(t, st, "bob")
	srv := newMCPServer(t, st, alice, "origins")
	if srv.ElicitationOrigins == nil || len(srv.ElicitationOrigins) != 0 {
		t.Errorf("new server origins = %#v, want empty", srv.ElicitationOrigins)
	}
	want := []string{"https://auth.example.net", "https://tunnel.example.org:8443"}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		return store.SetMCPServerElicitationOrigins(ctx, tx, srv.ID, want)
	}); err != nil {
		t.Fatalf("set origins: %v", err)
	}
	read := func() *store.MCPServer {
		t.Helper()
		var got *store.MCPServer
		if err := st.WithJobs(ctx, func(tx store.Tx) error {
			var err error
			got, err = store.GetMCPServer(ctx, tx, srv.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := read(); !slices.Equal(got.ElicitationOrigins, want) {
		t.Errorf("origins = %v, want %v", got.ElicitationOrigins, want)
	}
	// UpdateMCPServer (whole-row settings writers) leaves the origins alone.
	next := *srv
	next.Name = srv.Name
	next.ElicitationOrigins = nil
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, &next) }); err != nil {
		t.Fatal(err)
	}
	if got := read(); !slices.Equal(got.ElicitationOrigins, want) {
		t.Errorf("origins after UpdateMCPServer = %v, want %v", got.ElicitationOrigins, want)
	}
	// The admin view lists them.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		a, err := store.GetAdminMCPServer(ctx, tx, srv.ID)
		if err != nil {
			return err
		}
		if !slices.Equal(a.ElicitationOrigins, want) {
			t.Errorf("admin view origins = %v", a.ElicitationOrigins)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Only the owner may change them (row security: ErrNotFound).
	if err := st.WithUser(ctx, bob, func(tx store.Tx) error {
		return store.SetMCPServerElicitationOrigins(ctx, tx, srv.ID, nil)
	}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob set = %v, want ErrNotFound", err)
	}
	// At most 20, no NULL entries.
	many := make([]string, 21)
	for i := range many {
		many[i] = "https://h" + string(rune('a'+i)) + ".example.com"
	}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		return store.SetMCPServerElicitationOrigins(ctx, tx, srv.ID, many)
	}); pgCode(err) != "23514" {
		t.Errorf("21 origins = %v, want check violation", err)
	}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_servers SET elicitation_origins = ARRAY[NULL]::text[] WHERE id = $1`, srv.ID)
		return err
	}); pgCode(err) != "23514" {
		t.Errorf("NULL origin = %v, want check violation", err)
	}
	// nil clears.
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		return store.SetMCPServerElicitationOrigins(ctx, tx, srv.ID, nil)
	}); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got.ElicitationOrigins) != 0 {
		t.Errorf("origins after clear = %v", got.ElicitationOrigins)
	}
}

// On a published server the origins are locked for the owner like the
// address (GW001); an admin may change them, and that keeps the approved
// snapshot (the origins do not change where calls go).
func TestIntegrationMCPPublishedServerElicitationOriginsLock(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	f := newPublishedLockFixture(t, st)
	origins := []string{"https://auth.example.net"}

	err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		return store.SetMCPServerElicitationOrigins(ctx, tx, f.server.ID, origins)
	})
	if !errors.Is(err, store.ErrMCPServerLocked) {
		t.Errorf("owner set origins of a published server = %v, want ErrMCPServerLocked", err)
	}
	err = st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_servers SET elicitation_origins = '{https://evil.example}' WHERE id = $1`, f.server.ID)
		return err
	})
	if pgCode(err) != store.MCPServerLockedCode {
		t.Errorf("owner raw update = %v, want %s", err, store.MCPServerLockedCode)
	}
	// Writing the same (empty) list is no change.
	if err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		return store.SetMCPServerElicitationOrigins(ctx, tx, f.server.ID, nil)
	}); err != nil {
		t.Errorf("owner rewrite of the same origins = %v", err)
	}
	// The admin path may; the approval stands.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.SetMCPServerElicitationOrigins(ctx, tx, f.server.ID, origins)
	}); err != nil {
		t.Fatalf("admin set origins: %v", err)
	}
	if v := approvedVersion(t, st, f.server.ID); v != f.approved.Version {
		t.Errorf("approved version after admin origins change = %d, want %d (not superseded)", v, f.approved.Version)
	}
	// An admin address change still supersedes.
	next := *f.server
	next.URL = "https://brain-v3.example.com/mcp"
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, &next) }); err != nil {
		t.Fatal(err)
	}
	if v := approvedVersion(t, st, f.server.ID); v != 0 {
		t.Errorf("approved version after admin URL change = %d, want none", v)
	}
}

func TestIntegrationUpstreamElicitationsMigrationDownUp(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	exists := func(sql string) bool {
		var ok bool
		if err := env.super.QueryRow(ctx, sql).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	table := `SELECT to_regclass('public.upstream_elicitations') IS NOT NULL`
	column := `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'mcp_servers' AND column_name = 'elicitation_origins')`
	viewColumn := `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'admin_mcp_servers' AND column_name = 'elicitation_origins')`
	if !exists(table) || !exists(column) || !exists(viewColumn) {
		t.Fatal("schema 32 objects missing")
	}
	var enabled, forced bool
	if err := env.super.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'upstream_elicitations'`).Scan(&enabled, &forced); err != nil || !enabled || !forced {
		t.Errorf("rls enabled=%v forced=%v, %v", enabled, forced, err)
	}
	if err := migrations.DownTo(ctx, env.superURL, 31); err != nil {
		t.Fatalf("down to 31: %v", err)
	}
	t.Cleanup(func() { _ = migrations.Up(context.WithoutCancel(ctx), env.superURL) })
	if exists(table) || exists(column) || exists(viewColumn) {
		t.Error("schema 32 objects left after down")
	}
	var invoker bool
	if err := env.super.QueryRow(ctx, `SELECT coalesce('security_invoker=true' = ANY(reloptions), false)
		FROM pg_class WHERE relname = 'admin_mcp_servers'`).Scan(&invoker); err != nil || !invoker {
		t.Errorf("admin_mcp_servers security_invoker after down = %v, %v", invoker, err)
	}
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("up: %v", err)
	}
	if !exists(table) || !exists(column) || !exists(viewColumn) {
		t.Error("schema 32 objects missing after up")
	}
}
