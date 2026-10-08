//go:build integration

package policy_test

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The policy integration test runs against its own database
// (gateway_policy_test, created from GATEWAY_TEST_DATABASE_URL) so it never
// races the store package's TRUNCATE (quirk 01mepmn6). It needs a superuser
// URL and gives the two application roles a temporary LOGIN password.

const (
	policyTestDB = "gateway_policy_test"
	appPassword  = "gateway-app-test"
	jobsPass     = "gateway-jobs-test"
	dexIssuer    = "http://localhost:15556/dex"
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, policyTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+policyTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + policyTestDB
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
		"TRUNCATE users, identities, sessions, roles, role_assignments, user_restrictions, policy_versions, audit_events CASCADE",
	} {
		if err := execRetryingConcurrentUpdate(ctx, super, stmt); err != nil {
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

// TestIntegrationRolesVersionsAndAssignments persists roles through the
// service, checks the policy_versions rows (hash, cedar, created_by), the
// audit rows, and that an assignment made by the identity module becomes
// effective after Invalidate.
func TestIntegrationRolesVersionsAndAssignments(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)

	idSvc, err := identity.New(identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		BootstrapAdmins: []string{dexIssuer + "|admin-subject"},
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, identity.NewPostgresStore(st), log)
	if err != nil {
		t.Fatal(err)
	}
	adminSign, err := idSvc.SignIn(ctx, "dex", identity.Claims{Issuer: dexIssuer, Subject: "admin-subject", Name: "Admin", Email: "admin@example.com", EmailVerified: true})
	if err != nil {
		t.Fatalf("SignIn admin: %v", err)
	}
	adminID := adminSign.Principal.UserID
	aliceSign, err := idSvc.SignIn(ctx, "dex", identity.Claims{Issuer: dexIssuer, Subject: "alice-subject", Name: "Alice", Email: "alice@example.com", EmailVerified: true})
	if err != nil {
		t.Fatalf("SignIn alice: %v", err)
	}
	aliceID := aliceSign.Principal.UserID

	rec := audit.NewStoreRecorder(st)
	svc, err := policy.New(policy.NewPostgresStore(st), policy.Options{Audit: rec, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	listItems := connectors.Tool{App: "fake", Name: "list_items", Kind: connectors.KindRead}

	// The default role exists (created on sign-in) but grants nothing.
	v0, err := svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.Decide(ctx, policy.Input{UserID: aliceID, Tool: listItems, AccountLabel: "company"})
	if err != nil || d.Outcome != policy.OutcomeHidden {
		t.Fatalf("alice before any rule = %+v, %v", d, err)
	}

	// The admin grants the member role a read.
	member, err := svc.Role(ctx, "member")
	if err != nil {
		t.Fatal(err)
	}
	member.Rules = []policy.ToolRule{{App: "fake", Tool: "list_items", Outcome: policy.OutcomeAllow}}
	if err := svc.SaveRole(ctx, adminID, member); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}
	v1, _ := svc.Current(ctx)
	if v1.Version == v0.Version || v1.ID == v0.ID || v1.ID == "" {
		t.Fatalf("version did not change: %+v -> %+v", v0, v1)
	}
	d, _ = svc.Decide(ctx, policy.Input{UserID: aliceID, Tool: listItems, AccountLabel: "company"})
	if d.Outcome != policy.OutcomeAllow || d.Version != v1.Version || d.VersionID != v1.ID {
		t.Errorf("alice after rule = %+v", d)
	}

	// policy_versions rows: the first by the system, the second by the admin.
	type row struct {
		hash, cedar string
		createdBy   *string
	}
	var rows []row
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		rs, err := tx.Query(ctx, `SELECT version_hash, cedar, created_by FROM policy_versions ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.hash, &r.cedar, &r.createdBy); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].hash != v0.Version || rows[0].createdBy != nil || rows[1].hash != v1.Version || rows[1].createdBy == nil || *rows[1].createdBy != adminID || rows[1].cedar != v1.Cedar {
		t.Errorf("policy_versions rows = %+v (v0=%s v1=%s admin=%s)", rows, v0.Version, v1.Version, adminID)
	}
	// Through the repository too.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		pv, err := tx.PolicyVersions().Get(ctx, v1.ID)
		if err != nil {
			return err
		}
		if pv.VersionHash != v1.Version || pv.CreatedBy == nil || *pv.CreatedBy != adminID {
			t.Errorf("PolicyVersions().Get = %+v", pv)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The admin's change is a user audit event.
	events, err := rec.ListForUser(ctx, adminID, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev.ResourceIdentity["action"] == "role_saved" && ev.ResourceIdentity["role"] == "member" && ev.PolicyVersion == v1.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("no role_saved audit event for the admin: %+v", events)
	}

	// A role created, flagged default, then deleted.
	if err := svc.SaveRole(ctx, adminID, policy.Role{Name: "auditor", Description: "Read everything", Rules: []policy.ToolRule{{App: "fake", Tool: "*", Outcome: policy.OutcomeAllow}}, PersonalAccounts: map[string]policy.Allowance{"fake": policy.AllowanceDeny}}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Role(ctx, "auditor")
	if err != nil || got.Description != "Read everything" || got.PersonalAccounts["fake"] != policy.AllowanceDeny || len(got.Rules) != 1 {
		t.Errorf("auditor round trip = %+v, %v", got, err)
	}
	if err := svc.SetDefaultRole(ctx, adminID, "auditor"); err != nil {
		t.Fatal(err)
	}
	if name, _ := svc.DefaultRole(ctx); name != "auditor" {
		t.Errorf("DefaultRole = %q", name)
	}
	if err := svc.SetDefaultRole(ctx, adminID, "member"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetDefaultRole(ctx, adminID, "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetDefaultRole(ghost) = %v", err)
	}
	// Identity assigns alice the auditor role behind the service's back.
	if err := idSvc.SetUserRole(ctx, adminID, aliceID, "auditor"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteRole(ctx, adminID, "auditor"); !errors.Is(err, policy.ErrRoleAssigned) {
		t.Errorf("DeleteRole(assigned) = %v", err)
	}
	svc.Invalidate()
	d, _ = svc.Decide(ctx, policy.Input{UserID: aliceID, Tool: connectors.Tool{App: "fake", Name: "create_item", Kind: connectors.KindWrite}, AccountLabel: "personal"})
	if d.Outcome != policy.OutcomeDeny {
		t.Errorf("alice as auditor on a personal account = %+v", d)
	}
	if err := idSvc.SetUserRole(ctx, adminID, aliceID, "member"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteRole(ctx, adminID, "auditor"); err != nil {
		t.Errorf("DeleteRole(unassigned) = %v", err)
	}
	if _, err := svc.Role(ctx, "auditor"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("deleted role still there: %v", err)
	}
	// A second service over the same database sees the same version and
	// does not add a row for it.
	svc2, _ := policy.New(policy.NewPostgresStore(st), policy.Options{Log: log})
	c1, _ := svc.Current(ctx)
	c2, err := svc2.Current(ctx)
	if err != nil || c2.Version != c1.Version || c2.ID != c1.ID {
		t.Errorf("second replica = %+v, %v; want %+v", c2, err, c1)
	}
	var n int
	_ = st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM policy_versions WHERE version_hash = $1`, c1.Version).Scan(&n)
	})
	if n != 1 {
		t.Errorf("rows for the current version = %d, want 1", n)
	}
}

// execRetryingConcurrentUpdate runs stmt, retrying when PostgreSQL reports
// "tuple concurrently updated" (SQLSTATE XX000): every package's
// integration bootstrap ALTERs the same cluster-global roles and `go test`
// runs packages in parallel.
func execRetryingConcurrentUpdate(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}
