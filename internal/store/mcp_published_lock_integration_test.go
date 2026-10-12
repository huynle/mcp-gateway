//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// Schema 17 (Brain task mpszh6h0, decision q7vbxlyk point 3): a published
// server's address and sign-in settings (url, transport, auth kind, auth
// and header config) are admin-governed. The request path
// (gateway_app, row-level security) may not change them; an admin change
// through the bypass role supersedes the approved snapshot, so nothing is
// served from the new backend until an admin reviews it again.

// publishedLockFixture is alice's server with an approved snapshot,
// published to bob's role.
type publishedLockFixture struct {
	alice, bob string
	server     *store.MCPServer
	approved   *store.MCPSnapshot
}

func newPublishedLockFixture(t *testing.T, st *store.Store) *publishedLockFixture {
	t.Helper()
	ctx := t.Context()
	f := &publishedLockFixture{alice: newUser(t, st, "alice"), bob: newUser(t, st, "bob")}
	f.server = newMCPServer(t, st, f.alice, "brain")
	err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		f.approved = &store.MCPSnapshot{ServerID: f.server.ID, Tools: []byte(`[{"name":"search"}]`)}
		if err := store.CreateMCPSnapshot(ctx, tx, f.approved); err != nil {
			return err
		}
		return store.ApproveMCPSnapshot(ctx, tx, f.approved.ID, f.alice, []byte(`{"search":{"enabled":true}}`))
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	role := newRoleFor(t, st, "engineer", f.bob)
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.PublishMCPServer(ctx, tx, f.server.ID, []string{role})
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	return f
}

func approvedVersion(t *testing.T, st *store.Store, serverID string) int {
	t.Helper()
	v := 0
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		s, err := store.ApprovedMCPSnapshot(t.Context(), tx, serverID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		v = s.Version
		return nil
	})
	if err != nil {
		t.Fatalf("approved snapshot: %v", err)
	}
	return v
}

func TestIntegrationMCPPublishedServerLockedForOwner(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	f := newPublishedLockFixture(t, st)

	// Every locked column, by raw SQL through the user scope: refused.
	for col, set := range map[string]string{
		"url":           `url = 'https://attacker.example.net/mcp'`,
		"transport":     `transport = 'sse'`,
		"auth_kind":     `auth_kind = 'none'`,
		"auth_config":   `auth_config = '{"scopes":["admin"]}'`,
		"header_config": `header_config = '{"static":{"X-Route":"evil"}}'`,
	} {
		err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE mcp_servers SET `+set+` WHERE id = $1`, f.server.ID)
			return err
		})
		if pgCode(err) != store.MCPServerLockedCode {
			t.Errorf("owner UPDATE %s of a published server = %v, want SQLSTATE %s", col, err, store.MCPServerLockedCode)
		}
	}
	// Through the repository: ErrMCPServerLocked.
	next := *f.server
	next.URL = "https://attacker.example.net/mcp"
	err := st.WithUser(ctx, f.alice, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, &next) })
	if !errors.Is(err, store.ErrMCPServerLocked) {
		t.Errorf("UpdateMCPServer(new URL) by owner = %v, want ErrMCPServerLocked", err)
	}
	// Rewriting the same values and non-security columns still works.
	same := *f.server
	if err := st.WithUser(ctx, f.alice, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, &same) }); err != nil {
		t.Errorf("UpdateMCPServer(unchanged) by owner = %v", err)
	}
	if err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		return store.SetMCPServerStatus(ctx, tx, f.server.ID, store.MCPServerError, ptr("unreachable"))
	}); err != nil {
		t.Errorf("owner status update = %v", err)
	}
	// The credential mode is not locked: the backend stays the reviewed one.
	mode := *f.server
	mode.CredentialMode = store.MCPCredentialShared
	if err := st.WithUser(ctx, f.alice, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, &mode) }); err != nil {
		t.Errorf("owner credential mode change = %v", err)
	}
	// Nothing changed and the approval stands.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		got, err := store.GetMCPServer(ctx, tx, f.server.ID)
		if err != nil {
			return err
		}
		if got.URL != f.server.URL || got.AuthKind != f.server.AuthKind || got.Transport != f.server.Transport {
			t.Errorf("server changed: %+v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := approvedVersion(t, st, f.server.ID); v != f.approved.Version {
		t.Errorf("approved version = %d, want %d", v, f.approved.Version)
	}

	// A private server stays the owner's to edit (and its approval stays:
	// the owner reviews private servers).
	priv := newMCPServer(t, st, f.alice, "notes")
	privNext := *priv
	privNext.URL = "https://notes2.example.com/mcp"
	if err := st.WithUser(ctx, f.alice, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, &privNext) }); err != nil {
		t.Errorf("owner URL edit of a private server = %v", err)
	}
}

func TestIntegrationMCPPublishedServerAdminChangeNeedsReview(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	f := newPublishedLockFixture(t, st)

	// A non-security admin change keeps the approval.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.SetMCPServerStatus(ctx, tx, f.server.ID, store.MCPServerActive, nil)
	}); err != nil {
		t.Fatal(err)
	}
	if v := approvedVersion(t, st, f.server.ID); v != f.approved.Version {
		t.Fatalf("approved version after status change = %d, want %d", v, f.approved.Version)
	}

	// The admin path may change the address; the approved snapshot is
	// superseded in the same transaction.
	next := *f.server
	next.URL = "https://brain-v2.example.com/mcp"
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.UpdateMCPServer(ctx, tx, &next) }); err != nil {
		t.Fatalf("admin UpdateMCPServer: %v", err)
	}
	if v := approvedVersion(t, st, f.server.ID); v != 0 {
		t.Errorf("approved version after admin URL change = %d, want none", v)
	}
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		s, err := store.GetMCPSnapshot(ctx, tx, f.approved.ID)
		if err != nil {
			return err
		}
		if s.Status != store.MCPSnapshotSuperseded {
			t.Errorf("old approved snapshot status = %q, want superseded", s.Status)
		}
		got, err := store.GetMCPServer(ctx, tx, f.server.ID)
		if err != nil {
			return err
		}
		if got.URL != next.URL {
			t.Errorf("url = %q, want %q", got.URL, next.URL)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Bob (the published role) sees no approved snapshot.
	err = st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		if _, err := store.ApprovedMCPSnapshot(ctx, tx, f.server.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob ApprovedMCPSnapshot = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The admin re-approves the snapshot: served again.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.ApproveMCPSnapshot(ctx, tx, f.approved.ID, "", nil)
	}); err != nil {
		t.Fatalf("re-approve: %v", err)
	}
	if v := approvedVersion(t, st, f.server.ID); v != f.approved.Version {
		t.Errorf("approved version after re-approval = %d, want %d", v, f.approved.Version)
	}
}

func TestIntegrationMCPPublishedLockMigrationDownUp(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	triggers := func() int {
		var n int
		if err := env.super.QueryRow(ctx, `SELECT count(*) FROM pg_trigger
			WHERE tgrelid = 'mcp_servers'::regclass AND NOT tgisinternal`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := triggers(); n == 0 {
		t.Fatalf("no trigger on mcp_servers at schema %d", store.ExpectedSchemaVersion)
	}
	if err := migrations.DownTo(ctx, env.superURL, 16); err != nil {
		t.Fatalf("down to 16: %v", err)
	}
	t.Cleanup(func() { _ = migrations.Up(context.WithoutCancel(ctx), env.superURL) })
	if n := triggers(); n != 0 {
		t.Errorf("%d triggers on mcp_servers after down to 16", n)
	}
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("up: %v", err)
	}
	if n := triggers(); n == 0 {
		t.Error("trigger missing after up")
	}
}
