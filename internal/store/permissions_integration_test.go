//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// Schema 16 (Brain task ds5tjou2, decision bnneszc1): roles.may_add_servers
// (admin-only) and users.gateway_tools_enabled (each user, own row only).

const adminRoleName = "admin"

// newRole creates a role through the bypass scope (the admin path).
func newRole(t *testing.T, st *store.Store, name string, mayAddServers bool) string {
	t.Helper()
	var id string
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		if err := store.UpsertRole(t.Context(), tx, name, "", nil, mayAddServers); err != nil {
			return err
		}
		r, err := store.FindRoleByName(t.Context(), tx, name)
		if err != nil {
			return err
		}
		id = r.ID
		return nil
	})
	if err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
	return id
}

func assignRole(t *testing.T, st *store.Store, userID, roleID string) {
	t.Helper()
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		return tx.Roles().Assign(t.Context(), &store.RoleAssignment{UserID: userID, RoleID: roleID})
	})
	if err != nil {
		t.Fatalf("assign role: %v", err)
	}
}

func gatewayToolsAsJobs(t *testing.T, st *store.Store, userID string) bool {
	t.Helper()
	var on bool
	err := st.WithJobs(t.Context(), func(tx store.Tx) (err error) {
		on, err = store.GatewayToolsEnabled(t.Context(), tx, userID)
		return err
	})
	if err != nil {
		t.Fatalf("read gateway tools of %s: %v", userID, err)
	}
	return on
}

// A user flips only their own toggle; every other column of their row and
// every other user's row stay out of reach of gateway_app.
func TestIntegrationGatewayToolsToggleRLS(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	userA := newUser(t, st, "alice")
	userB := newUser(t, st, "bob")

	if gatewayToolsAsJobs(t, st, userA) {
		t.Fatal("gateway tools on by default")
	}

	// Own toggle: on, read back, off.
	if err := st.WithUser(ctx, userA, func(tx store.Tx) error {
		return store.SetGatewayToolsEnabled(ctx, tx, userA, true)
	}); err != nil {
		t.Fatalf("A enables own toggle: %v", err)
	}
	var on bool
	if err := st.WithUser(ctx, userA, func(tx store.Tx) (err error) {
		on, err = store.GatewayToolsEnabled(ctx, tx, userA)
		return err
	}); err != nil || !on {
		t.Fatalf("A reads own toggle = %v, %v; want true", on, err)
	}

	// Someone else's toggle: invisible (not found), unchanged.
	err := st.WithUser(ctx, userA, func(tx store.Tx) error {
		return store.SetGatewayToolsEnabled(ctx, tx, userB, true)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("A flips B's toggle: %v, want ErrNotFound", err)
	}
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET gateway_tools_enabled = true WHERE id = $1`, userB)
		return err
	})
	if err != nil {
		t.Errorf("raw update of B's row as A: %v (want 0 rows, no error)", err)
	}
	if gatewayToolsAsJobs(t, st, userB) {
		t.Error("A turned on B's gateway tools")
	}
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		_, err := store.GatewayToolsEnabled(ctx, tx, userB)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("A reads B's toggle: %v, want ErrNotFound", err)
	}

	// Other columns of the own row: privilege error.
	for _, stmt := range []string{
		`UPDATE users SET display_name = 'mallory' WHERE id = $1`,
		`UPDATE users SET status = 'disabled' WHERE id = $1`,
		`UPDATE users SET last_company_sign_in_at = now() WHERE id = $1`,
		`UPDATE users SET updated_at = now() WHERE id = $1`,
		`DELETE FROM users WHERE id = $1`,
	} {
		err := st.WithUser(ctx, userA, func(tx store.Tx) error {
			_, err := tx.Exec(ctx, stmt, userA)
			return err
		})
		if !isPermissionDenied(err) {
			t.Errorf("%s as the user: %v, want permission denied", stmt, err)
		}
	}
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (display_name) VALUES ('sneaky')`)
		return err
	})
	if !isPermissionDenied(err) {
		t.Errorf("insert user as the user: %v, want permission denied", err)
	}

	// Off again.
	if err := st.WithUser(ctx, userA, func(tx store.Tx) error {
		return store.SetGatewayToolsEnabled(ctx, tx, userA, false)
	}); err != nil {
		t.Fatalf("A disables own toggle: %v", err)
	}
	if gatewayToolsAsJobs(t, st, userA) {
		t.Error("toggle still on after disabling")
	}
}

// Roles and role assignments change only through the admin (bypass)
// path: gateway_app may read them, never write them.
func TestIntegrationRolesOnlyAdminPathWrites(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	userA := newUser(t, st, "alice")
	member := newRole(t, st, "member", false)
	admin := newRole(t, st, adminRoleName, false)
	assignRole(t, st, userA, member)

	for _, c := range []struct {
		stmt string
		args []any
	}{
		{`UPDATE roles SET may_add_servers = true WHERE id = $1`, []any{member}},
		{`UPDATE roles SET definition = '{}'::jsonb WHERE id = $1`, []any{member}},
		{`INSERT INTO roles (name, may_add_servers) VALUES ('mine', true)`, nil},
		{`DELETE FROM roles WHERE id = $1`, []any{member}},
		{`INSERT INTO role_assignments (user_id, role_id) VALUES ($1, $2)`, []any{userA, admin}},
		{`UPDATE role_assignments SET role_id = $2 WHERE user_id = $1`, []any{userA, admin}},
		{`DELETE FROM role_assignments WHERE user_id = $1`, []any{userA}},
	} {
		err := st.WithUser(ctx, userA, func(tx store.Tx) error {
			_, err := tx.Exec(ctx, c.stmt, c.args...)
			return err
		})
		if !isPermissionDenied(err) {
			t.Errorf("%s as a user: %v, want permission denied", c.stmt, err)
		}
	}

	// The admin path saves the flag and the role list carries it.
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.UpsertRole(ctx, tx, "member", "Members", nil, true); err != nil {
			return err
		}
		roles, err := store.ListRoles(ctx, tx)
		if err != nil {
			return err
		}
		for _, r := range roles {
			if want := r.Name == "member"; r.MayAddServers != want {
				t.Errorf("role %s MayAddServers = %v, want %v", r.Name, r.MayAddServers, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("admin path: %v", err)
	}
	// Users still read roles (the policy pages, the permission check).
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		_, err := store.FindRoleByName(ctx, tx, "member")
		return err
	})
	if err != nil {
		t.Errorf("user reads a role: %v", err)
	}
}

// UserMayAddServers: the admin role, or any held role with the flag.
func TestIntegrationUserMayAddServers(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	plain := newUser(t, st, "plain")
	builder := newUser(t, st, "builder")
	boss := newUser(t, st, "boss")
	nobody := newUser(t, st, "nobody")
	member := newRole(t, st, "member", false)
	builders := newRole(t, st, "builders", true)
	admin := newRole(t, st, adminRoleName, false)
	assignRole(t, st, plain, member)
	assignRole(t, st, builder, member)
	assignRole(t, st, builder, builders)
	assignRole(t, st, boss, admin)

	may := func(userID string) bool {
		t.Helper()
		var ok bool
		err := st.WithUser(ctx, userID, func(tx store.Tx) (err error) {
			ok, err = store.UserMayAddServers(ctx, tx, userID, adminRoleName)
			return err
		})
		if err != nil {
			t.Fatalf("UserMayAddServers(%s): %v", userID, err)
		}
		return ok
	}
	for _, c := range []struct {
		name, id string
		want     bool
	}{{"member", plain, false}, {"member+builders", builder, true}, {"admin", boss, true}, {"no role", nobody, false}} {
		if got := may(c.id); got != c.want {
			t.Errorf("%s: may add servers = %v, want %v", c.name, got, c.want)
		}
	}
	// In someone else's scope the answer is no (their assignments are
	// invisible): the check always runs as the user it is about.
	var ok bool
	if err := st.WithUser(ctx, plain, func(tx store.Tx) (err error) {
		ok, err = store.UserMayAddServers(ctx, tx, builder, adminRoleName)
		return err
	}); err != nil || ok {
		t.Errorf("builder checked in plain's scope = %v, %v; want false", ok, err)
	}
	// Taking the flag away takes the permission away.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.UpsertRole(ctx, tx, "builders", "", nil, false)
	}); err != nil {
		t.Fatal(err)
	}
	if may(builder) {
		t.Error("builder still may add servers after the flag was cleared")
	}
}

func TestIntegrationPermissionsMigrationDownUp(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	column := func(table, col string) bool {
		var ok bool
		if err := env.super.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)`, table, col).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	canUpdate := func(table, col string) bool {
		var ok bool
		if err := env.super.QueryRow(ctx, `SELECT has_column_privilege('gateway_app', $1, $2, 'UPDATE')`, table, col).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if err := migrations.DownTo(ctx, env.superURL, 15); err != nil {
		t.Fatalf("down to 15: %v", err)
	}
	t.Cleanup(func() { _ = migrations.Up(context.Background(), env.superURL) })
	if column("roles", "may_add_servers") || column("users", "gateway_tools_enabled") {
		t.Error("schema 16 columns still exist after down")
	}
	if !canUpdate("users", "display_name") || !canUpdate("roles", "definition") {
		t.Error("down did not restore the schema 15 grants")
	}
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("up: %v", err)
	}
	if !column("roles", "may_add_servers") || !column("users", "gateway_tools_enabled") {
		t.Error("schema 16 columns missing after up")
	}
	if canUpdate("users", "display_name") || canUpdate("roles", "may_add_servers") || canUpdate("roles", "definition") {
		t.Error("gateway_app may still update admin-owned columns")
	}
	if !canUpdate("users", "gateway_tools_enabled") {
		t.Error("gateway_app may not update gateway_tools_enabled")
	}
}
