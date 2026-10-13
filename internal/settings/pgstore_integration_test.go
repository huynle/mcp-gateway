//go:build integration

package settings_test

import (
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/settings"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

func openPG(t *testing.T) *store.Store {
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
	const db = "gateway_settings_test"
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
	for _, q := range []string{"ALTER ROLE gateway_app LOGIN PASSWORD 'app-test'", "ALTER ROLE gateway_jobs LOGIN PASSWORD 'jobs-test'", "TRUNCATE users,roles,role_assignments,gateway_user_rate_limits,gateway_app_rate_limits,audit_events CASCADE", "INSERT INTO gateway_rate_settings(singleton,user_per_min,app_per_min,version,updated_by) VALUES(true,NULL,NULL,1,NULL) ON CONFLICT(singleton) DO UPDATE SET user_per_min=NULL,app_per_min=NULL,version=1,updated_by=NULL"} {
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

func TestIntegrationPersistedRateSettingsAndRLS(t *testing.T) {
	st := openPG(t)
	ctx := t.Context()
	var admin, user, other string
	err := st.WithJobs(ctx, func(tx store.Tx) error {
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
	s := settings.New(settings.NewPostgresStore(st), settings.Options{DefaultUserPerMinute: 60, DefaultAppPerMinute: 600})
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOrg(ctx, admin, 600, 3000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApp(ctx, admin, "brain", ptr(1000)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, admin, user, ptr(800)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSelf(ctx, user, ptr(500)); err != nil {
		t.Fatal(err)
	}
	if u, a := s.Limits(ctx, user, "brain"); u != 500 || a != 1000 {
		t.Fatalf("effective=%d/%d", u, a)
	}
	// gateway_app user scope cannot read or update another user's row.
	err = st.WithUser(ctx, other, func(tx store.Tx) error { _, err := store.GetGatewayUserRateLimit(ctx, tx, user); return err })
	if err == nil {
		t.Fatal("other user read rate row")
	}
	err = st.WithUser(ctx, user, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE gateway_user_rate_limits SET admin_per_min=99999 WHERE user_id=$1`, user)
		return err
	})
	if err == nil {
		t.Fatal("user changed its administrator override")
	}
}
