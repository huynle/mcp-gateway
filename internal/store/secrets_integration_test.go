//go:build integration

package store_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Integration tests for ephemeral secrets (migration 00031,
// docs/plans/2026-10-23-ephemeral-secrets-design.md).

func secretHash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func testSecretValue() store.Encrypted {
	return store.Encrypted{KeyID: "k1", WrappedDataKey: []byte("wrapped"), Nonce: []byte("nonce-12byte"), Ciphertext: []byte("ciphertext")}
}

// newPendingSecret inserts a pending request of owner bound to serverID /
// tool / arg with the given uses, as owner.
func newPendingSecret(t *testing.T, st *store.Store, owner, serverID, name string, uses int) *store.Secret {
	t.Helper()
	arg := "password"
	s := &store.Secret{
		OwnerUserID: owner, HarnessID: "tok-" + owner, Label: "label " + name,
		ServerID: serverID, Tool: "notes.login", Arg: &arg,
		UsesTotal: uses, UsesLeft: uses, TTL: 15 * time.Minute,
		LinkExpiresAt: time.Now().Add(10 * time.Minute),
		RequestHash:   secretHash("req-" + name), HandleHash: secretHash("sec_" + name),
	}
	err := st.WithUser(t.Context(), owner, func(tx store.Tx) error { return store.CreateSecret(t.Context(), tx, s) })
	if err != nil {
		t.Fatalf("create secret %s: %v", name, err)
	}
	if s.ID == "" || s.State != store.SecretPending || s.CreatedAt.IsZero() {
		t.Fatalf("created secret = %+v", s)
	}
	return s
}

func provideSecret(t *testing.T, st *store.Store, s *store.Secret) *store.Secret {
	t.Helper()
	var got *store.Secret
	err := st.WithUser(t.Context(), s.OwnerUserID, func(tx store.Tx) error {
		var err error
		got, err = store.ProvideSecret(t.Context(), tx, s.ID, s.RequestHash, testSecretValue(), time.Now())
		return err
	})
	if err != nil {
		t.Fatalf("provide %s: %v", s.Label, err)
	}
	return got
}

func secretBinding(s *store.Secret) store.SecretBinding {
	return store.SecretBinding{ServerID: s.ServerID, Tool: s.Tool, Arg: s.Arg}
}

func TestIntegrationSecretsLifecycleAndRowSecurity(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	srv := newMCPServer(t, st, alice, "alice-vault")
	s := newPendingSecret(t, st, alice, srv.ID, "one", 2)

	// Bob sees nothing of alice's rows and cannot change them.
	err := st.WithUser(ctx, bob, func(tx store.Tx) error {
		if _, err := store.GetSecret(ctx, tx, s.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob get = %v, want ErrNotFound", err)
		}
		if _, err := store.GetSecretByRequestHash(ctx, tx, s.RequestHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob by request = %v, want ErrNotFound", err)
		}
		if _, err := store.GetSecretByHandleHash(ctx, tx, s.HandleHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob by handle = %v, want ErrNotFound", err)
		}
		if list, err := store.ListSecrets(ctx, tx, alice); err != nil || len(list) != 0 {
			t.Errorf("bob lists alice's = %d, %v", len(list), err)
		}
		if _, err := store.ProvideSecret(ctx, tx, s.ID, s.RequestHash, testSecretValue(), time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob provide = %v, want ErrNotFound", err)
		}
		if _, err := store.DenySecret(ctx, tx, s.RequestHash, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob deny = %v, want ErrNotFound", err)
		}
		if _, err := store.RevokeSecret(ctx, tx, s.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob revoke = %v, want ErrNotFound", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE secrets SET label = 'x' WHERE id = $1`, s.ID)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("bob raw update = %d rows, %v", tag.RowsAffected(), err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Inserting a row for alice is refused by the policy's WITH CHECK.
	other := *s
	other.ID, other.RequestHash, other.HandleHash = "", secretHash("req-forged"), secretHash("sec_forged")
	if err := st.WithUser(ctx, bob, func(tx store.Tx) error { return store.CreateSecret(ctx, tx, &other) }); err == nil {
		t.Error("bob created a secret owned by alice")
	}

	// Pending is not consumable.
	var c *store.Secret
	consume := func(owner, harness string, b store.SecretBinding) error {
		return st.WithUser(ctx, owner, func(tx store.Tx) error {
			var err error
			c, err = store.ConsumeSecret(ctx, tx, s.HandleHash, owner, harness, b, time.Now())
			return err
		})
	}
	if err := consume(alice, s.HarnessID, secretBinding(s)); !errors.Is(err, store.ErrSecretNotConsumable) {
		t.Fatalf("consume pending = %v", err)
	}

	p := provideSecret(t, st, s)
	if p.State != store.SecretProvided || p.Value == nil || p.ExpiresAt == nil || p.ProvidedAt == nil ||
		p.ExpiresAt.Sub(*p.ProvidedAt) != 15*time.Minute {
		t.Fatalf("provided = %+v", p)
	}
	// Single use: a second provide finds no pending row.
	err = st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := store.ProvideSecret(ctx, tx, s.ID, s.RequestHash, testSecretValue(), time.Now())
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second provide = %v, want ErrNotFound", err)
	}

	// Mismatches: other harness, tool, arg, NULL arg, other owner.
	wrongTool := secretBinding(s)
	wrongTool.Tool = "notes.other"
	otherArg := "token"
	wrongArg := secretBinding(s)
	wrongArg.Arg = &otherArg
	nullArg := secretBinding(s)
	nullArg.Arg = nil
	for name, try := range map[string]func() error{
		"harness": func() error { return consume(alice, "other-harness", secretBinding(s)) },
		"tool":    func() error { return consume(alice, s.HarnessID, wrongTool) },
		"arg":     func() error { return consume(alice, s.HarnessID, wrongArg) },
		"nullarg": func() error { return consume(alice, s.HarnessID, nullArg) },
		"owner":   func() error { return consume(bob, s.HarnessID, secretBinding(s)) },
	} {
		if err := try(); !errors.Is(err, store.ErrSecretNotConsumable) {
			t.Errorf("consume with wrong %s = %v", name, err)
		}
	}

	if err := consume(alice, s.HarnessID, secretBinding(s)); err != nil || c.UsesLeft != 1 || c.Value == nil ||
		!bytes.Equal(c.Value.Ciphertext, []byte("ciphertext")) {
		t.Fatalf("consume = %+v, %v", c, err)
	}
	if err := consume(alice, s.HarnessID, secretBinding(s)); err != nil || c.UsesLeft != 0 {
		t.Fatalf("second consume = %+v, %v", c, err)
	}
	if err := consume(alice, s.HarnessID, secretBinding(s)); !errors.Is(err, store.ErrSecretNotConsumable) {
		t.Fatalf("consume used up = %v", err)
	}
	// Refund gives one use back, capped at uses_total.
	refund := func() error {
		return st.WithUser(ctx, alice, func(tx store.Tx) error { return store.RefundSecret(ctx, tx, s.ID, time.Now()) })
	}
	if err := refund(); err != nil {
		t.Fatalf("refund: %v", err)
	}
	if err := refund(); err != nil {
		t.Fatalf("second refund: %v", err)
	}
	if err := refund(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refund over cap = %v, want ErrNotFound", err)
	}
	var list []store.Secret
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		var err error
		list, err = store.ListSecrets(ctx, tx, alice)
		return err
	}); err != nil || len(list) != 1 || list[0].UsesLeft != 2 {
		t.Fatalf("alice list = %+v, %v", list, err)
	}

	// Revoke wipes the value at once; a revoked row cannot be revoked again.
	var r *store.Secret
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		var err error
		r, err = store.RevokeSecret(ctx, tx, s.ID, time.Now())
		return err
	}); err != nil || r.State != store.SecretRevoked || r.Value != nil || r.EndedAt == nil {
		t.Fatalf("revoke = %+v, %v", r, err)
	}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := store.RevokeSecret(ctx, tx, s.ID, time.Now())
		return err
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second revoke = %v", err)
	}
	if err := refund(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refund revoked = %v", err)
	}

	// Deny moves a pending request to denied.
	d := newPendingSecret(t, st, alice, srv.ID, "deny", 1)
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		var err error
		r, err = store.DenySecret(ctx, tx, d.RequestHash, time.Now())
		return err
	}); err != nil || r.State != store.SecretDenied || r.EndedAt == nil {
		t.Fatalf("deny = %+v, %v", r, err)
	}
}

func TestIntegrationSecretsRequestCounts(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	srv := newMCPServer(t, st, alice, "alice-vault")
	a := newPendingSecret(t, st, alice, srv.ID, "a", 1)
	newPendingSecret(t, st, alice, srv.ID, "b", 1)
	provideSecret(t, st, a)
	if _, err := env.super.Exec(ctx, `UPDATE secrets SET created_at = now() - interval '2 hours'
		WHERE label = 'label a'`); err != nil {
		t.Fatal(err)
	}
	var pending, recent int
	err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		if err := store.LockSecretRequests(ctx, tx, alice); err != nil {
			return err
		}
		var err error
		pending, recent, err = store.CountSecretRequests(ctx, tx, alice, time.Now().Add(-time.Hour), time.Now())
		return err
	})
	if err != nil || pending != 1 || recent != 1 {
		t.Fatalf("counts = %d pending, %d recent, %v; want 1, 1", pending, recent, err)
	}
}

func TestIntegrationSecretsSingleUseUnderConcurrency(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	alice := newUser(t, st, "Alice")
	srv := newMCPServer(t, st, alice, "alice-vault")
	s := newPendingSecret(t, st, alice, srv.ID, "race", 1)
	provideSecret(t, st, s)

	var wins, losses atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := st.WithUser(t.Context(), alice, func(tx store.Tx) error {
				_, err := store.ConsumeSecret(t.Context(), tx, s.HandleHash, alice, s.HarnessID, secretBinding(s), time.Now())
				return err
			})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrSecretNotConsumable):
				losses.Add(1)
			default:
				t.Errorf("consume: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || losses.Load() != 9 {
		t.Fatalf("wins = %d, losses = %d; want exactly one use", wins.Load(), losses.Load())
	}
}

func TestIntegrationSecretsExpireWipesCiphertext(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	srv := newMCPServer(t, st, alice, "alice-vault")

	usedUp := newPendingSecret(t, st, alice, srv.ID, "used", 1)
	provideSecret(t, st, usedUp)
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := store.ConsumeSecret(ctx, tx, usedUp.HandleHash, alice, usedUp.HarnessID, secretBinding(usedUp), time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ttlPassed := newPendingSecret(t, st, alice, srv.ID, "ttl", 3)
	provideSecret(t, st, ttlPassed)
	live := newPendingSecret(t, st, alice, srv.ID, "live", 3)
	provideSecret(t, st, live)
	linkPassed := newPendingSecret(t, st, alice, srv.ID, "link", 1)
	stillPending := newPendingSecret(t, st, alice, srv.ID, "pending", 1)
	old := newPendingSecret(t, st, alice, srv.ID, "old", 1)
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := store.DenySecret(ctx, tx, old.RequestHash, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE secrets SET expires_at = now() - interval '1 second' WHERE id = '` + ttlPassed.ID + `'`,
		`UPDATE secrets SET link_expires_at = now() - interval '1 second' WHERE id = '` + linkPassed.ID + `'`,
		`UPDATE secrets SET ended_at = now() - interval '8 days' WHERE id = '` + old.ID + `'`,
	} {
		if _, err := env.super.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}

	var res store.SecretExpiry
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		res, err = store.ExpireSecrets(ctx, tx, time.Now(), 7*24*time.Hour)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res.Expired != 3 || res.Deleted != 1 {
		t.Fatalf("expiry = %+v; want 3 expired (used up, ttl, link), 1 deleted", res)
	}
	state := func(id string) (string, bool) {
		var st string
		var hasValue bool
		err := env.super.QueryRow(ctx, `SELECT state, value_ciphertext IS NOT NULL FROM secrets WHERE id = $1`, id).Scan(&st, &hasValue)
		if err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		return st, hasValue
	}
	for _, id := range []string{usedUp.ID, ttlPassed.ID, linkPassed.ID} {
		if s, v := state(id); s != store.SecretExpired || v {
			t.Errorf("%s: state %s, value kept %v", id, s, v)
		}
	}
	if s, v := state(live.ID); s != store.SecretProvided || !v {
		t.Errorf("live: state %s, value kept %v", s, v)
	}
	if s, _ := state(stillPending.ID); s != store.SecretPending {
		t.Errorf("pending: state %s", s)
	}
	var n int
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE id = $1`, old.ID).Scan(&n); err != nil || n != 0 {
		t.Errorf("old ended row count = %d, %v; want deleted", n, err)
	}
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE value_ciphertext IS NOT NULL AND state <> 'provided'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("ciphertext outside provided rows = %d, %v", n, err)
	}
}

func TestIntegrationSecretsRevokeUserSecrets(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	srv := newMCPServer(t, st, alice, "alice-vault")
	p := newPendingSecret(t, st, alice, srv.ID, "p", 1)
	provideSecret(t, st, p)
	newPendingSecret(t, st, alice, srv.ID, "q", 1)
	b := newPendingSecret(t, st, bob, srv.ID, "bob", 1)
	var n int64
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		n, err = store.RevokeUserSecrets(ctx, tx, alice, time.Now())
		return err
	}); err != nil || n != 2 {
		t.Fatalf("revoke user secrets = %d, %v; want 2", n, err)
	}
	var live int
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE owner_user_id = $1
		AND (state <> 'revoked' OR value_ciphertext IS NOT NULL)`, alice).Scan(&live); err != nil || live != 0 {
		t.Fatalf("alice's unrevoked = %d, %v", live, err)
	}
	var bs string
	if err := env.super.QueryRow(ctx, `SELECT state FROM secrets WHERE id = $1`, b.ID).Scan(&bs); err != nil || bs != store.SecretPending {
		t.Fatalf("bob's secret = %s, %v", bs, err)
	}
}
