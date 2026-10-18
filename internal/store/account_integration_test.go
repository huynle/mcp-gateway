//go:build integration

package store_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// accountFixture is alice with one row of everything a user owns, and
// bob with a token of his own (which must never show up for alice).
type accountFixture struct {
	alice, bob   string
	connectionID string
	approvalID   string
	server       *store.MCPServer
}

func newAccountFixture(t *testing.T, env *testEnv, st *store.Store) *accountFixture {
	t.Helper()
	ctx := t.Context()
	f := &accountFixture{alice: newUser(t, st, "Alice Example"), bob: newUser(t, st, "Bob Example")}
	appID := newVendorApp(t, st)
	f.connectionID = newConnection(t, st, f.alice, appID, "alice@example.com")
	newToken(t, st, f.alice, "alicetok", "laptop", time.Now().Add(24*time.Hour))
	newToken(t, st, f.bob, "bobtoken", "bob-laptop", time.Now().Add(24*time.Hour))
	f.server = newMCPServer(t, st, f.alice, "alice-notes")
	if _, err := env.super.Exec(ctx, `UPDATE mcp_servers SET url = 'https://user:pw@notes.example.com/mcp?key=secret' WHERE id = $1`, f.server.ID); err != nil {
		t.Fatal(err)
	}
	err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		return store.CreateMCPTunnel(ctx, tx, &store.MCPTunnel{OwnerUserID: f.alice, Name: "laptop", TokenHash: []byte("tunnel-hash-alice")})
	})
	if err != nil {
		t.Fatal(err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if err := tx.Identities().Create(ctx, &store.Identity{UserID: f.alice, Issuer: "https://idp.example.com", Subject: "alice-sub"}); err != nil {
			return err
		}
		return tx.Sessions().Create(ctx, &store.Session{UserID: f.alice, TokenHash: []byte("session-alice"), ExpiresAt: time.Now().Add(time.Hour)})
	})
	if err != nil {
		t.Fatal(err)
	}
	var policyID string
	if err := env.super.QueryRow(ctx, `INSERT INTO policy_versions (version_hash, cedar) VALUES ('acct-test', '') RETURNING id`).Scan(&policyID); err != nil {
		t.Fatal(err)
	}
	if err := env.super.QueryRow(ctx, `
		INSERT INTO approvals (user_id, connection_id, tool, digest, payload_key_id, payload_wrapped_key, payload_nonce, payload_ciphertext,
			status, policy_version_id, expires_at)
		VALUES ($1, $2, 'github.create_issue', '\x01', 'k', '\x02', '\x03', '\x04', 'pending', $3, now() + interval '1 hour')
		RETURNING id`, f.alice, f.connectionID, policyID).Scan(&f.approvalID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.super.Exec(ctx, `INSERT INTO gateway_user_rate_limits (user_id, self_per_min) VALUES ($1, 5)`, f.alice); err != nil {
		t.Fatal(err)
	}
	if _, err := env.super.Exec(ctx, `INSERT INTO gateway_user_resource_caps (user_id, servers) VALUES ($1, 3), ($2, 4)`, f.alice, f.bob); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := env.super.Exec(ctx, `INSERT INTO audit_events (user_id, tool, decision) VALUES ($1, 'github.list_repos', 'allow')`, f.alice); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.super.Exec(ctx, `INSERT INTO audit_events (user_id, tool, decision) VALUES ($1, 'github.list_repos', 'allow')`, f.bob); err != nil {
		t.Fatal(err)
	}
	return f
}

func exportAs(t *testing.T, st *store.Store, userID, section string, limit int) ([]map[string]any, bool) {
	t.Helper()
	var rows []json.RawMessage
	var truncated bool
	err := st.WithUser(t.Context(), userID, func(tx store.Tx) error {
		var err error
		rows, truncated, err = store.ExportSection(t.Context(), tx, section, userID, limit)
		return err
	})
	if err != nil {
		t.Fatalf("export %s: %v", section, err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			t.Fatalf("export %s: row is not a JSON object: %s", section, r)
		}
		out = append(out, m)
	}
	return out, truncated
}

func TestIntegrationAccountExportSections(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	f := newAccountFixture(t, env, st)

	want := map[string]int{
		"profile": 1, "identities": 1, "roles": 0, "connections": 1, "tokens": 1, "harness_grants": 0,
		"mcp_servers": 1, "mcp_server_connections": 0, "tunnels": 1, "approvals": 1, "ledger_operations": 0,
		"audit_events": 3, "rate_limits": 1, "resource_caps": 1,
	}
	if len(store.ExportSections) != len(want) {
		t.Errorf("ExportSections = %v", store.ExportSections)
	}
	forbidden := []string{"token_hash", "ciphertext", "wrapped", "payload", "nonce", "digest", "auth_config", "header_config", "secret"}
	for _, section := range store.ExportSections {
		rows, truncated := exportAs(t, st, f.alice, section, 100)
		if n, ok := want[section]; !ok || len(rows) != n || truncated {
			t.Errorf("section %s: %d rows (truncated %v), want %d", section, len(rows), truncated, want[section])
		}
		for _, r := range rows {
			for k, v := range r {
				for _, bad := range forbidden {
					if strings.Contains(k, bad) {
						t.Errorf("section %s exports column %q", section, k)
					}
				}
				if s, ok := v.(string); ok && (s == f.bob || strings.Contains(s, "bob")) {
					t.Errorf("section %s leaks bob: %s=%v", section, k, v)
				}
			}
		}
	}
	srv, _ := exportAs(t, st, f.alice, "mcp_servers", 100)
	if got := srv[0]["url"]; got != "https://notes.example.com/mcp" {
		t.Errorf("mcp server url = %v, want userinfo and query stripped", got)
	}
	audit, truncated := exportAs(t, st, f.alice, "audit_events", 2)
	if len(audit) != 2 || !truncated {
		t.Errorf("capped audit export = %d rows truncated=%v, want 2, true", len(audit), truncated)
	}
	if _, _, err := store.ExportSection(t.Context(), nil, "users; DROP TABLE users", f.alice, 1); err == nil {
		t.Error("unknown section accepted")
	}
	// Row-level security backs the explicit filter: bob's scope asking for
	// alice's rows gets nothing.
	if rows, _ := exportAs(t, st, f.bob, "tokens", 100); len(rows) != 1 {
		t.Errorf("bob's own tokens = %d, want 1", len(rows))
	}
	err := st.WithUser(t.Context(), f.bob, func(tx store.Tx) error {
		rows, _, err := store.ExportSection(t.Context(), tx, "tokens", f.alice, 100)
		if len(rows) != 0 {
			t.Errorf("bob's scope exported %d of alice's tokens", len(rows))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationAccountLastUserAuditAction(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "alice")
	at := func() *time.Time {
		var got *time.Time
		err := st.WithUser(ctx, alice, func(tx store.Tx) error {
			var err error
			got, err = store.LastUserAuditAction(ctx, tx, alice, "user.data_exported")
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := at(); got != nil {
		t.Fatalf("no export yet, got %v", got)
	}
	if _, err := env.super.Exec(ctx, `INSERT INTO audit_events (event_type, user_id, decision, resource) VALUES ('user', $1, 'allow', '{"action":"user.data_exported"}')`, alice); err != nil {
		t.Fatal(err)
	}
	if got := at(); got == nil || time.Since(*got) > time.Minute {
		t.Errorf("last export = %v, want just now", got)
	}
}

func TestIntegrationAccountDeleteUserData(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	f := newAccountFixture(t, env, st)
	admin := newRoleFor(t, st, "admin", f.alice, f.bob)
	// carol owns a published server: a deletion blocker the service checks.
	carol := newUser(t, st, "carol")
	pub := newMCPServer(t, st, carol, "carol-pub")
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.PublishMCPServer(ctx, tx, pub.ID, []string{admin})
	})
	if err != nil {
		t.Fatal(err)
	}

	var del *store.UserDeletion
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.LockAccountDeletion(ctx, tx); err != nil {
			return err
		}
		names, err := store.PublishedMCPServersOwnedBy(ctx, tx, carol)
		if err != nil || len(names) != 1 || names[0] != "carol-pub" {
			t.Errorf("carol's published servers = %v, %v", names, err)
		}
		if names, _ := store.PublishedMCPServersOwnedBy(ctx, tx, f.alice); len(names) != 0 {
			t.Errorf("alice's published servers = %v, want none", names)
		}
		if n, err := store.CountActiveUsersWithRole(ctx, tx, "admin"); err != nil || n != 2 {
			t.Errorf("active admins = %d, %v; want 2", n, err)
		}
		ids, err := store.ListIdentitiesForUser(ctx, tx, f.alice)
		if err != nil || len(ids) != 1 || ids[0].Subject != "alice-sub" {
			t.Errorf("alice identities = %v, %v", ids, err)
		}
		del, err = store.DeleteUserData(ctx, tx, f.alice, time.Now())
		return err
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(del.ServerIDs) != 1 || del.ServerIDs[0] != f.server.ID || del.Tunnels != 1 || del.Approvals != 1 || del.Connections != 1 {
		t.Errorf("deletion = %+v", del)
	}

	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := env.super.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}
	checks := map[string]string{
		"identities":                     `SELECT count(*) FROM identities WHERE user_id = $1`,
		"sessions":                       `SELECT count(*) FROM sessions WHERE user_id = $1`,
		"live tokens":                    `SELECT count(*) FROM tokens WHERE user_id = $1 AND revoked_at IS NULL`,
		"token names":                    `SELECT count(*) FROM tokens WHERE user_id = $1 AND name <> 'deleted'`,
		"connection secrets":             `SELECT count(*) FROM connection_secrets WHERE user_id = $1`,
		"named connections":              `SELECT count(*) FROM connections WHERE user_id = $1 AND (display_name <> '' OR external_account_id NOT LIKE 'deleted:%' OR status <> 'revoked')`,
		"approval payloads":              `SELECT count(*) FROM approvals WHERE user_id = $1 AND (payload_ciphertext IS NOT NULL OR status <> 'expired')`,
		"servers":                        `SELECT count(*) FROM mcp_servers WHERE owner_user_id = $1`,
		"tunnels":                        `SELECT count(*) FROM mcp_tunnels WHERE owner_user_id = $1`,
		"role assignments":               `SELECT count(*) FROM role_assignments WHERE user_id = $1`,
		"rate limits":                    `SELECT count(*) FROM gateway_user_rate_limits WHERE user_id = $1`,
		"resource caps":                  `SELECT count(*) FROM gateway_user_resource_caps WHERE user_id = $1`,
		"personal fields on user":        `SELECT count(*) FROM users WHERE id = $1 AND (display_name <> '' OR last_company_sign_in_at IS NOT NULL OR gateway_tools_enabled)`,
		"user not tombstoned":            `SELECT count(*) FROM users WHERE id = $1 AND (status <> 'deleted' OR deleted_at IS NULL)`,
		"refresh tokens still live":      `SELECT count(*) FROM oauth_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`,
		"unconsumed authorization codes": `SELECT count(*) FROM oauth_authorization_codes WHERE user_id = $1`,
	}
	for what, sql := range checks {
		if n := count(sql, f.alice); n != 0 {
			t.Errorf("after delete: %s = %d, want 0", what, n)
		}
	}
	// History stays: audit rows (append-only legal record) under the
	// pseudonymous id; bob is untouched.
	if n := count(`SELECT count(*) FROM audit_events WHERE user_id = $1`, f.alice); n != 3 {
		t.Errorf("alice's audit rows = %d, want 3 kept", n)
	}
	if n := count(`SELECT count(*) FROM tokens WHERE user_id = $1 AND revoked_at IS NULL`, f.bob); n != 1 {
		t.Errorf("bob's live tokens = %d, want 1", n)
	}
	if n := count(`SELECT count(*) FROM admin_users WHERE id = $1 AND status = 'deleted' AND deleted_at IS NOT NULL`, f.alice); n != 1 {
		t.Errorf("admin_users does not show the tombstone")
	}
	// A deleted user cannot be re-enabled or disabled, and leaves the
	// admin user list.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.SetUserStatus(ctx, tx, f.alice, store.UserActive, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("enable deleted user = %v, want ErrNotFound", err)
		}
		if err := store.SetUserStatus(ctx, tx, f.alice, store.UserDisabled, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("disable deleted user = %v, want ErrNotFound", err)
		}
		users, err := store.ListUsers(ctx, tx)
		for _, u := range users {
			if u.ID == f.alice {
				t.Error("deleted user still listed")
			}
		}
		if n, _ := store.CountActiveUsersWithRole(ctx, tx, "admin"); n != 1 {
			t.Errorf("active admins after delete = %d, want 1", n)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// gateway_app cannot run the deletion.
	err = st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		_, err := store.DeleteUserData(ctx, tx, f.bob, time.Now())
		return err
	})
	if err == nil {
		t.Error("DeleteUserData through gateway_app succeeded, want permission error")
	}
}
