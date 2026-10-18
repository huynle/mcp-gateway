//go:build integration

package store_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Public sign-up storage (migration 00027): the pending status and its
// guarded transitions, single-use invites and the new-account counter.
func TestIntegrationSignupStorage(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	admin := newUser(t, st, "Admin")
	now := time.Now().UTC().Truncate(time.Microsecond)

	// A pending user can be created; transitions are guarded by the
	// current status.
	var pending string
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		u := &store.User{DisplayName: "Newcomer", Status: store.UserPending}
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		pending = u.ID
		if u.Status != store.UserPending {
			t.Errorf("created status = %q, want pending", u.Status)
		}
		if err := store.TransitionUserStatus(ctx, tx, pending, store.UserDisabled, store.UserActive, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("disabled->active on a pending user = %v, want ErrNotFound", err)
		}
		if err := store.TransitionUserStatus(ctx, tx, pending, store.UserPending, store.UserActive, now); err != nil {
			return err
		}
		got, err := tx.Users().Get(ctx, pending)
		if err != nil {
			return err
		}
		if got.Status != store.UserActive || got.DisabledAt != nil {
			t.Errorf("after approve = %+v, want active", got)
		}
		if err := store.TransitionUserStatus(ctx, tx, pending, store.UserActive, store.UserDisabled, now); err != nil {
			return err
		}
		got, _ = tx.Users().Get(ctx, pending)
		if got.Status != store.UserDisabled || got.DisabledAt == nil {
			t.Errorf("after disable = %+v, want disabled with disabled_at", got)
		}
		return store.SetUserStatus(ctx, tx, pending, store.UserPending, now)
	})
	if err != nil {
		t.Fatalf("pending status: %v", err)
	}

	// A pending user's own scope sees their row; nothing else changes for
	// row-level security.
	if err := st.WithUser(ctx, pending, func(tx store.Tx) error {
		u, err := tx.Users().Get(ctx, pending)
		if err == nil && u.Status != store.UserPending {
			t.Errorf("own row status = %q, want pending", u.Status)
		}
		return err
	}); err != nil {
		t.Fatalf("pending user scope: %v", err)
	}

	// Invites: hashed, single use, expiry and revocation honoured.
	hash := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
	var good, expired, revoked store.SignupInvite
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		good = store.SignupInvite{CodeHash: hash("good"), Label: "for bob", CreatedBy: &admin, ExpiresAt: now.Add(time.Hour)}
		expired = store.SignupInvite{CodeHash: hash("old"), CreatedBy: &admin, ExpiresAt: now.Add(-time.Minute)}
		revoked = store.SignupInvite{CodeHash: hash("gone"), CreatedBy: &admin, ExpiresAt: now.Add(time.Hour)}
		for _, inv := range []*store.SignupInvite{&good, &expired, &revoked} {
			if err := store.CreateSignupInvite(ctx, tx, inv); err != nil {
				return err
			}
		}
		if err := store.RevokeSignupInvite(ctx, tx, revoked.ID, now); err != nil {
			return err
		}
		if err := store.RevokeSignupInvite(ctx, tx, revoked.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second revoke = %v, want ErrNotFound", err)
		}
		for name, h := range map[string][]byte{"expired": hash("old"), "revoked": hash("gone"), "unknown": hash("nope")} {
			if _, err := store.ConsumeSignupInvite(ctx, tx, h, pending, now); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("consume %s = %v, want ErrNotFound", name, err)
			}
		}
		id, err := store.ConsumeSignupInvite(ctx, tx, hash("good"), pending, now)
		if err != nil {
			return err
		}
		if id != good.ID {
			t.Errorf("consumed id = %s, want %s", id, good.ID)
		}
		if _, err := store.ConsumeSignupInvite(ctx, tx, hash("good"), admin, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second consume = %v, want ErrNotFound (single use)", err)
		}
		list, err := store.ListSignupInvites(ctx, tx, 50)
		if err != nil {
			return err
		}
		if len(list) != 3 {
			t.Fatalf("listed %d invites, want 3", len(list))
		}
		for _, inv := range list {
			if inv.ID == good.ID && (inv.UsedAt == nil || inv.UsedBy == nil || *inv.UsedBy != pending || inv.Label != "for bob") {
				t.Errorf("used invite = %+v", inv)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("invites: %v", err)
	}

	// The request-path role cannot read or write sign-up tables.
	err = st.WithUser(ctx, admin, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `SELECT count(*) FROM signup_invites`)
		return err
	})
	if !isPermissionDenied(err) {
		t.Errorf("gateway_app reading signup_invites = %v, want permission denied", err)
	}

	// The new-account counter: per key and global inside the window,
	// rows older than the prune cutoff dropped.
	keyA, keyB := hash("ip-a"), hash("ip-b")
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.LockSignups(ctx, tx); err != nil {
			return err
		}
		for _, ev := range []struct {
			key []byte
			at  time.Time
		}{{keyA, now.Add(-2 * time.Hour)}, {keyA, now.Add(-10 * time.Minute)}, {keyA, now}, {keyB, now}} {
			if err := store.RecordSignupEvent(ctx, tx, ev.key, ev.at, time.Time{}); err != nil {
				return err
			}
		}
		global, perKey, err := store.CountSignupEvents(ctx, tx, keyA, now.Add(-time.Hour))
		if err != nil {
			return err
		}
		if global != 3 || perKey != 2 {
			t.Errorf("counts = %d global / %d key, want 3 / 2", global, perKey)
		}
		if err := store.RecordSignupEvent(ctx, tx, keyB, now, now.Add(-time.Hour)); err != nil {
			return err
		}
		global, _, err = store.CountSignupEvents(ctx, tx, keyA, now.Add(-24*time.Hour))
		if err != nil {
			return err
		}
		if global != 4 {
			t.Errorf("after prune: %d events in 24h, want 4 (the 2h-old one pruned)", global)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("signup events: %v", err)
	}
}
