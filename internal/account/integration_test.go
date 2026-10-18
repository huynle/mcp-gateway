//go:build integration

package account_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/account"
	"github.com/huynle/mcp-gateway/internal/store"
)

// fakeIdentity is the identity service seen by account: bootstrap admins
// and the disable hooks (recorded, with whether they got a transaction).
type fakeIdentity struct {
	bootstrap map[string]bool
	hooked    []string
	withTx    bool
	fail      error
}

func (f *fakeIdentity) RunDisableHooks(_ context.Context, tx store.Tx, userID string) error {
	f.hooked = append(f.hooked, userID)
	f.withTx = tx != nil
	return f.fail
}

func (f *fakeIdentity) IsBootstrapAdmin(issuer, subject string) bool {
	return f.bootstrap[issuer+"|"+subject]
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type fixture struct {
	env  *testEnv
	st   *store.Store
	id   *fakeIdentity
	clk  *clock
	svc  *account.Service
	gone []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	f := &fixture{env: env, st: st, id: &fakeIdentity{bootstrap: map[string]bool{}}, clk: &clock{t: time.Now().UTC()}}
	f.svc = account.New(st, f.id, account.Options{
		Now: f.clk.now,
		OnDeleted: func(_ context.Context, userID string, _ *store.UserDeletion) {
			f.gone = append(f.gone, userID)
		},
	})
	return f
}

// user creates a user with an identity, signed in at signedIn.
func (f *fixture) user(t *testing.T, name, subject string, signedIn time.Time) string {
	t.Helper()
	id := newUser(t, f.st, name)
	if _, err := f.env.super.Exec(t.Context(), `UPDATE users SET last_company_sign_in_at = $2 WHERE id = $1`, id, signedIn); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.super.Exec(t.Context(), `INSERT INTO identities (user_id, issuer, subject) VALUES ($1, 'https://idp.example', $2)`, id, subject); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) makeAdmin(t *testing.T, userIDs ...string) {
	t.Helper()
	var roleID string
	if err := f.env.super.QueryRow(t.Context(), `INSERT INTO roles (name) VALUES ('admin') ON CONFLICT (name) DO UPDATE SET name = 'admin' RETURNING id`).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	for _, u := range userIDs {
		if _, err := f.env.super.Exec(t.Context(), `INSERT INTO role_assignments (user_id, role_id) VALUES ($1, $2)`, u, roleID); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.super.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func TestIntegrationExportIsOwnDataAuditedAndRateLimited(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice := f.user(t, "Alice", "alice-sub", f.clk.t)
	bob := f.user(t, "Bob", "bob-sub", f.clk.t)
	for _, u := range []string{alice, bob} {
		err := f.st.WithUser(ctx, u, func(tx store.Tx) error {
			return tx.Tokens().Create(ctx, &store.Token{UserID: u, PublicID: u[:8], Name: "laptop", TokenHash: []byte("hash-" + u), ExpiresAt: f.clk.t.Add(time.Hour)})
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	if err := f.svc.Export(ctx, alice, &buf); err != nil {
		t.Fatalf("Export: %v", err)
	}
	var doc struct {
		Format     string `json:"format"`
		UserID     string `json:"user_id"`
		ExportedAt string `json:"exported_at"`
		RowLimits  map[string]int
		Sections   map[string]struct {
			Rows      []map[string]any `json:"rows"`
			Truncated bool             `json:"truncated"`
			Note      string           `json:"note"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("export is not JSON: %v\n%s", err, buf.String())
	}
	if doc.Format != account.ExportFormat || doc.UserID != alice || doc.ExportedAt == "" {
		t.Errorf("header = %q %q %q", doc.Format, doc.UserID, doc.ExportedAt)
	}
	for _, s := range store.ExportSections {
		if _, ok := doc.Sections[s]; !ok {
			t.Errorf("section %s missing", s)
		}
	}
	if toks := doc.Sections["tokens"].Rows; len(toks) != 1 || toks[0]["name"] != "laptop" {
		t.Errorf("tokens section = %v", toks)
	}
	if strings.Contains(buf.String(), bob) || strings.Contains(buf.String(), "hash-") {
		t.Error("export contains bob's id or a token hash")
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE user_id = $1 AND event_type = 'user' AND resource->>'action' = 'user.data_exported'`, alice); n != 1 {
		t.Errorf("export audit events = %d, want 1", n)
	}

	// A second export inside the window is refused, with the wait.
	f.clk.t = f.clk.t.Add(5 * time.Minute)
	err := f.svc.Export(ctx, alice, &bytes.Buffer{})
	var soon *account.ExportTooSoonError
	if !errors.As(err, &soon) || !errors.Is(err, account.ErrExportTooSoon) || soon.RetryAfter <= 0 || soon.RetryAfter > 6*time.Minute {
		t.Fatalf("second export = %v, want ExportTooSoonError with ~5m wait", err)
	}
	// Bob is not affected by alice's limit; alice can export again later.
	if err := f.svc.Export(ctx, bob, &bytes.Buffer{}); err != nil {
		t.Errorf("bob export: %v", err)
	}
	f.clk.t = f.clk.t.Add(6 * time.Minute)
	if err := f.svc.Export(ctx, alice, &bytes.Buffer{}); err != nil {
		t.Errorf("export after the window: %v", err)
	}
}

func TestIntegrationDeleteSelfNeedsRecentSignIn(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice := f.user(t, "Alice", "alice-sub", f.clk.t.Add(-time.Hour))

	st, err := f.svc.Status(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if st.Fresh || len(st.Blockers) != 0 {
		t.Errorf("status = %+v, want stale, no blockers", st)
	}
	if err := f.svc.DeleteSelf(ctx, alice); !errors.Is(err, account.ErrReauthRequired) {
		t.Fatalf("DeleteSelf with an hour-old sign-in = %v, want ErrReauthRequired", err)
	}
	if len(f.id.hooked) != 0 {
		t.Error("hooks ran for a refused deletion")
	}

	if _, err := f.env.super.Exec(ctx, `UPDATE users SET last_company_sign_in_at = $2 WHERE id = $1`, alice, f.clk.t.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.svc.Status(ctx, alice); !st.Fresh {
		t.Errorf("status after sign-in = %+v, want fresh", st)
	}
	if err := f.svc.DeleteSelf(ctx, alice); err != nil {
		t.Fatalf("DeleteSelf: %v", err)
	}
	if len(f.id.hooked) != 1 || f.id.hooked[0] != alice || !f.id.withTx {
		t.Errorf("disable hooks = %v (tx %v), want alice in the transaction", f.id.hooked, f.id.withTx)
	}
	if n := f.count(t, `SELECT count(*) FROM users WHERE id = $1 AND status = 'deleted' AND display_name = ''`, alice); n != 1 {
		t.Error("user not tombstoned")
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE user_id = $1 AND resource->>'action' = 'user.deleted' AND resource->>'by' = 'self'`, alice); n != 1 {
		t.Errorf("user.deleted events = %d, want 1", n)
	}
	if len(f.gone) != 1 || f.gone[0] != alice {
		t.Errorf("OnDeleted = %v", f.gone)
	}
	if err := f.svc.DeleteSelf(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
}

func TestIntegrationDeleteBlockers(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	now := f.clk.t
	root := f.user(t, "Root", "root-sub", now)
	f.id.bootstrap["https://idp.example|root-sub"] = true
	admin := f.user(t, "Admin", "admin-sub", now)
	owner := f.user(t, "Owner", "owner-sub", now)
	f.makeAdmin(t, admin)
	if _, err := f.env.super.Exec(ctx, `INSERT INTO mcp_servers (name, url, owner_user_id, audience) VALUES ('team-wiki', 'https://wiki.example/mcp', $1, 'published')`, owner); err != nil {
		t.Fatal(err)
	}

	blocked := func(err error, want string) {
		t.Helper()
		var be *account.BlockedError
		if !errors.As(err, &be) || !errors.Is(err, account.ErrBlocked) {
			t.Fatalf("err = %v, want BlockedError", err)
		}
		if !strings.Contains(strings.Join(be.Reasons, " "), want) {
			t.Errorf("reasons = %v, want one mentioning %q", be.Reasons, want)
		}
	}
	blocked(f.svc.DeleteSelf(ctx, root), "GATEWAY_BOOTSTRAP_ADMINS")
	blocked(f.svc.DeleteSelf(ctx, admin), "last admin")
	blocked(f.svc.DeleteSelf(ctx, owner), "team-wiki")
	if st, _ := f.svc.Status(ctx, owner); len(st.Blockers) != 1 {
		t.Errorf("owner status blockers = %v", st.Blockers)
	}
	blocked(f.svc.DeleteByAdmin(ctx, admin, owner), "team-wiki")
	if err := f.svc.DeleteByAdmin(ctx, admin, admin); !errors.Is(err, account.ErrOwnAccount) {
		t.Errorf("admin deleting self through the admin path = %v, want ErrOwnAccount", err)
	}
	if len(f.id.hooked) != 0 {
		t.Errorf("hooks ran for refused deletions: %v", f.id.hooked)
	}

	// With a second admin the first may go, deleted by the other (no
	// fresh sign-in needed on the admin path), recorded with the actor.
	if _, err := f.env.super.Exec(ctx, `UPDATE users SET last_company_sign_in_at = now() - interval '2 days' WHERE id = $1`, admin); err != nil {
		t.Fatal(err)
	}
	other := f.user(t, "Other", "other-sub", now)
	f.makeAdmin(t, other)
	if err := f.svc.DeleteByAdmin(ctx, other, admin); err != nil {
		t.Fatalf("DeleteByAdmin: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE user_id = $1 AND resource->>'action' = 'user.deleted' AND resource->>'target_user_id' = $2 AND resource->>'by' = 'admin'`, other, admin); n != 1 {
		t.Errorf("admin user.deleted events = %d, want 1", n)
	}
	// A failing hook rolls everything back.
	plain := f.user(t, "Plain", "plain-sub", now)
	f.id.fail = errors.New("vendor down")
	if err := f.svc.DeleteByAdmin(ctx, other, plain); err == nil {
		t.Error("deletion succeeded although a hook failed")
	}
	if n := f.count(t, `SELECT count(*) FROM users WHERE id = $1 AND status = 'active' AND display_name = 'Plain'`, plain); n != 1 {
		t.Error("a failed deletion changed the user")
	}
	if err := f.svc.DeleteByAdmin(ctx, other, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown user = %v, want ErrNotFound", err)
	}
}
