//go:build integration

package permissions_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The Postgres adapter against its own database (gateway_permissions_test,
// quirk 01mepmn6), retrying the concurrent ALTER ROLE (quirk aihn7hjb).

const (
	testDB      = "gateway_permissions_test"
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
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPass + "'",
		"TRUNCATE users, roles, role_assignments, audit_events CASCADE",
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

// userWithRole creates a user holding a new role (bypass scope: the admin
// path).
func userWithRole(t *testing.T, st *store.Store, name, role string, mayAddServers bool) string {
	t.Helper()
	var id string
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		u := &store.User{DisplayName: name, Status: store.UserActive}
		if err := tx.Users().Create(t.Context(), u); err != nil {
			return err
		}
		id = u.ID
		if role == "" {
			return nil
		}
		if err := store.UpsertRole(t.Context(), tx, role, "", nil, mayAddServers); err != nil {
			return err
		}
		r, err := store.FindRoleByName(t.Context(), tx, role)
		if err != nil {
			return err
		}
		return tx.Roles().Assign(t.Context(), &store.RoleAssignment{UserID: id, RoleID: r.ID})
	})
	if err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	return id
}

func TestIntegrationPostgresPermissions(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	svc := permissions.NewPostgres(st, permissions.Options{})
	member := userWithRole(t, st, "member", "member", false)
	builder := userWithRole(t, st, "builder", "builders", true)
	admin := userWithRole(t, st, "admin", identity.AdminRole, false)
	nobody := userWithRole(t, st, "nobody", "", false)

	for _, c := range []struct {
		name, id string
		want     bool
	}{{"member", member, false}, {"builder", builder, true}, {"admin", admin, true}, {"no role", nobody, false}} {
		if got := svc.CanAddServers(ctx, c.id); got != c.want {
			t.Errorf("%s: CanAddServers = %v, want %v", c.name, got, c.want)
		}
	}

	// Member: may not switch the tools on; the row stays off.
	if err := svc.SetGatewayToolsEnabled(ctx, member, true); !errors.Is(err, permissions.ErrNotPermitted) {
		t.Errorf("member turns tools on: %v, want ErrNotPermitted", err)
	}
	if on, err := svc.GatewayToolsEnabled(ctx, member); err != nil || on {
		t.Errorf("member setting = %v, %v; want false", on, err)
	}
	// Builder: on persists, active; off persists.
	if err := svc.SetGatewayToolsEnabled(ctx, builder, true); err != nil {
		t.Fatalf("builder turns tools on: %v", err)
	}
	if on, err := svc.GatewayToolsEnabled(ctx, builder); err != nil || !on {
		t.Errorf("builder setting = %v, %v; want true", on, err)
	}
	if !svc.GatewayToolsActive(ctx, builder) {
		t.Error("builder's tools not active")
	}
	if err := svc.SetGatewayToolsEnabled(ctx, builder, false); err != nil {
		t.Fatalf("builder turns tools off: %v", err)
	}
	if svc.GatewayToolsActive(ctx, builder) {
		t.Error("builder's tools still active")
	}
}
