//go:build integration

package settings_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/settings"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestIntegrationPersistedResourceCapsAndRLS(t *testing.T) {
	st := openPG(t)
	ctx := t.Context()
	var admin, user, other string
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE gateway_resource_caps SET servers=NULL, tunnels=NULL, connections_per_app=NULL, connections_total=NULL, pending_approvals=NULL`); err != nil {
			return err
		}
		for _, p := range []struct {
			name string
			id   *string
		}{{"admin", &admin}, {"user", &user}, {"other", &other}} {
			u := &store.User{DisplayName: p.name, Status: store.UserActive}
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
			*p.id = u.ID
		}
		if err := store.UpsertRole(ctx, tx, "admin", "", nil, false); err != nil {
			return err
		}
		r, err := store.FindRoleByName(ctx, tx, "admin")
		if err != nil {
			return err
		}
		return tx.Roles().Assign(ctx, &store.RoleAssignment{UserID: admin, RoleID: r.ID})
	})
	if err != nil {
		t.Fatal(err)
	}
	s := settings.NewCaps(settings.NewPostgresCapsStore(st), settings.CapsOptions{Defaults: caps.Values{caps.Servers: 10}})
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.IsAdmin(ctx, admin) || s.IsAdmin(ctx, user) {
		t.Fatal("admin set wrong")
	}
	if got := s.Limit(ctx, user, caps.Servers); got != 10 {
		t.Fatalf("default servers = %d", got)
	}
	if err := s.SetOrg(ctx, admin, caps.Patch{caps.Servers: ptr(4), caps.Tunnels: ptr(2)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOrg(ctx, admin, caps.Patch{caps.Tunnels: nil}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUser(ctx, admin, user, caps.Patch{caps.Servers: ptr(0), caps.PendingApprovals: ptr(7)}); err != nil {
		t.Fatal(err)
	}
	// A second service (another replica) reads the persisted values.
	s2 := settings.NewCaps(settings.NewPostgresCapsStore(st), settings.CapsOptions{})
	if got := s2.Limit(ctx, other, caps.Servers); got != 4 {
		t.Errorf("org servers = %d, want 4", got)
	}
	if got := s2.Limit(ctx, other, caps.Tunnels); got != caps.Builtin[caps.Tunnels] {
		t.Errorf("cleared org tunnels = %d, want default", got)
	}
	if got := s2.Limit(ctx, user, caps.Servers); got != 0 {
		t.Errorf("user servers = %d, want 0 (unlimited)", got)
	}
	if got := s2.Limit(ctx, user, caps.PendingApprovals); got != 7 {
		t.Errorf("user approvals = %d, want 7", got)
	}
	// Clearing every override removes the row.
	if err := s.SetUser(ctx, admin, user, caps.Patch{caps.Servers: nil, caps.PendingApprovals: nil}); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM gateway_user_resource_caps WHERE user_id=$1`, user).Scan(&rows)
	}); err != nil || rows != 0 {
		t.Fatalf("rows after clear = %d (%v)", rows, err)
	}
	if err := s.SetUser(ctx, admin, user, caps.Patch{caps.Tunnels: ptr(1)}); err != nil {
		t.Fatal(err)
	}
	// Usage counts the user's own resources.
	if err := st.WithUser(ctx, user, func(tx store.Tx) error {
		return store.CreateMCPServer(ctx, tx, &store.MCPServer{Name: "u1", URL: "https://example.com", OwnerUserID: user})
	}); err != nil {
		t.Fatal(err)
	}
	use, err := s.Usage(ctx, user)
	if err != nil || use[caps.Servers] != 1 || use[caps.Tunnels] != 0 {
		t.Fatalf("usage = %v (%v)", use, err)
	}
	// gateway_app: a user reads only its own override row and writes none.
	err = st.WithUser(ctx, other, func(tx store.Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(*) FROM gateway_user_resource_caps`).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	_ = st.WithUser(ctx, other, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM gateway_user_resource_caps`).Scan(&seen)
	})
	if seen != 0 {
		t.Errorf("other user sees %d override rows", seen)
	}
	for _, q := range []string{
		`UPDATE gateway_user_resource_caps SET servers=0`,
		`INSERT INTO gateway_user_resource_caps(user_id, servers) VALUES ('` + user + `', 0)`,
		`UPDATE gateway_resource_caps SET servers=0`,
	} {
		if err := st.WithUser(ctx, user, func(tx store.Tx) error { _, err := tx.Exec(ctx, q); return err }); err == nil {
			t.Errorf("gateway_app may run %s", q)
		}
	}
}
