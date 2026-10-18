//go:build integration

package store_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
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

// A tunnel token only authenticates while its owner is active: a pending
// or disabled owner's tunnel cannot connect (fail closed).
func TestIntegrationTunnelOwnerMustBeActive(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	owner := newUser(t, st, "Owner")
	tun := &store.MCPTunnel{OwnerUserID: owner, Name: "laptop", TokenHash: []byte("tun-hash")}
	if err := st.WithUser(ctx, owner, func(tx store.Tx) error { return store.CreateMCPTunnel(ctx, tx, tun) }); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{store.UserPending, store.UserDisabled, store.UserActive} {
		err := st.WithJobs(ctx, func(tx store.Tx) error {
			if err := store.SetUserStatus(ctx, tx, owner, status, time.Now()); err != nil {
				return err
			}
			_, err := store.GetMCPTunnelByTokenHash(ctx, tx, []byte("tun-hash"))
			if status == store.UserActive && err != nil {
				t.Errorf("active owner: %v", err)
			}
			if status != store.UserActive && !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s owner: %v, want ErrNotFound", status, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Migrations 00027 (pending) and 00029 (deleted) both widen
// users_status_check: at the latest version a user can be pending and
// another deleted, and going down to 26 and up again works (00029's down
// keeps pending, 00027's down disables it).
func TestIntegrationUserStatusesAcrossSignupAndDeletion(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	now := time.Now().UTC()

	var pending, deleted string
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		p := &store.User{DisplayName: "Waiting", Status: store.UserPending}
		if err := tx.Users().Create(ctx, p); err != nil {
			return err
		}
		pending = p.ID
		d := &store.User{DisplayName: "Leaving", Status: store.UserActive}
		if err := tx.Users().Create(ctx, d); err != nil {
			return err
		}
		deleted = d.ID
		if _, err := store.DeleteUserData(ctx, tx, deleted, now); err != nil {
			return err
		}
		// A pending user can be deleted too (an admin removing a sign-up).
		q := &store.User{DisplayName: "Spam", Status: store.UserPending}
		if err := tx.Users().Create(ctx, q); err != nil {
			return err
		}
		_, err := store.DeleteUserData(ctx, tx, q.ID, now)
		return err
	})
	if err != nil {
		t.Fatalf("pending + deleted at the latest schema: %v", err)
	}
	status := func(id string) string {
		var s string
		if err := env.super.QueryRow(ctx, `SELECT status FROM users WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if status(pending) != store.UserPending || status(deleted) != store.UserDeleted {
		t.Fatalf("statuses = %s / %s", status(pending), status(deleted))
	}

	// Down to 26 and back up.
	if err := migrations.DownTo(ctx, env.superURL, 26); err != nil {
		t.Fatalf("down to 26: %v", err)
	}
	if v, err := migrations.Version(ctx, env.superURL); err != nil || v != 26 {
		t.Fatalf("version after down = %d, %v", v, err)
	}
	if status(pending) != store.UserDisabled || status(deleted) != store.UserDisabled {
		t.Errorf("after down: %s / %s, want disabled / disabled", status(pending), status(deleted))
	}
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if v, err := migrations.Version(ctx, env.superURL); err != nil || v != store.ExpectedSchemaVersion {
		t.Fatalf("version after up = %d, %v", v, err)
	}
	if _, err := env.super.Exec(ctx, `UPDATE users SET status = 'pending' WHERE id = $1`, pending); err != nil {
		t.Errorf("pending after the round trip: %v", err)
	}

	// Going down only past 00029 leaves pending rows pending.
	if err := migrations.DownTo(ctx, env.superURL, 27); err != nil {
		t.Fatalf("down to 27: %v", err)
	}
	if status(pending) != store.UserPending {
		t.Errorf("00029 down changed a pending user to %s", status(pending))
	}
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("up: %v", err)
	}
}
