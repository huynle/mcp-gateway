//go:build integration

package store_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// The identity module's lookups (repo_identity_lookup.go): pre-auth
// lookups by issuer+subject and session hash through the bypass scope,
// sign-in bookkeeping, role get-or-create and the admin user list.
func TestIntegrationIdentityLookups(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)

	userID := newUser(t, st, "Alice")
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Identity by issuer+subject needs the bypass scope; nothing is visible
	// before a user is known.
	var identityID string
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		if _, err := store.FindIdentity(ctx, tx, "https://idp.test", "sub-1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FindIdentity before create = %v, want ErrNotFound", err)
		}
		i := &store.Identity{UserID: userID, Issuer: "https://idp.test", Subject: "sub-1"}
		if err := tx.Identities().Create(ctx, i); err != nil {
			return err
		}
		identityID = i.ID
		got, err := store.FindIdentity(ctx, tx, "https://idp.test", "sub-1")
		if err != nil {
			return err
		}
		if got.ID != identityID || got.UserID != userID {
			t.Errorf("FindIdentity = %+v, want id %s user %s", got, identityID, userID)
		}
		return store.RecordSignIn(ctx, tx, userID, identityID, "Alice Example", now)
	})
	if err != nil {
		t.Fatalf("identity round trip: %v", err)
	}

	// The sign-in stamp is visible to the user's own scope.
	err = st.WithUser(ctx, userID, func(tx store.Tx) error {
		u, err := tx.Users().Get(ctx, userID)
		if err != nil {
			return err
		}
		if u.LastCompanySignInAt == nil || !u.LastCompanySignInAt.Equal(now) || u.DisplayName != "Alice Example" {
			t.Errorf("user after RecordSignIn = %+v, want last sign-in %v and the new display name", u, now)
		}
		i, err := tx.Identities().Get(ctx, identityID)
		if err != nil {
			return err
		}
		if i.LastSignInAt == nil || !i.LastSignInAt.Equal(now) {
			t.Errorf("identity after RecordSignIn = %+v, want last sign-in %v", i, now)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read back sign-in: %v", err)
	}

	// Roles: EnsureRole is idempotent; assignments are replaceable; the
	// user's roles are readable under their own scope.
	var memberID, adminID string
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if _, err := store.FindRoleByName(ctx, tx, "member"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FindRoleByName before create = %v, want ErrNotFound", err)
		}
		member, err := store.EnsureRole(ctx, tx, "member", "default role")
		if err != nil {
			return err
		}
		again, err := store.EnsureRole(ctx, tx, "member", "ignored on second call")
		if err != nil {
			return err
		}
		if again.ID != member.ID || again.Description != "default role" {
			t.Errorf("EnsureRole second call = %+v, want the existing row %+v", again, member)
		}
		memberID = member.ID
		admin, err := store.EnsureRole(ctx, tx, "admin", "")
		if err != nil {
			return err
		}
		adminID = admin.ID
		if err := store.AssignRoleIfMissing(ctx, tx, userID, memberID, nil); err != nil {
			return err
		}
		if err := store.AssignRoleIfMissing(ctx, tx, userID, memberID, nil); err != nil {
			return err
		}
		if err := store.AssignRoleIfMissing(ctx, tx, userID, adminID, &userID); err != nil {
			return err
		}
		all, err := store.ListRoles(ctx, tx)
		if err != nil {
			return err
		}
		if len(all) != 2 || all[0].Name != "admin" || all[1].Name != "member" {
			t.Errorf("ListRoles = %+v, want admin, member", all)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("roles: %v", err)
	}
	err = st.WithUser(ctx, userID, func(tx store.Tx) error {
		roles, err := store.RolesForUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if len(roles) != 2 || roles[0].Name != "admin" || roles[1].Name != "member" {
			t.Errorf("RolesForUser = %+v, want admin, member", roles)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("roles for user: %v", err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.SetUserRole(ctx, tx, userID, memberID, nil); err != nil {
			return err
		}
		roles, err := store.RolesForUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if len(roles) != 1 || roles[0].ID != memberID {
			t.Errorf("RolesForUser after SetUserRole = %+v, want only member", roles)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("set user role: %v", err)
	}

	// Sessions by hash, touch, revoke.
	hash := sha256.Sum256([]byte("secret"))
	var sessionID string
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if _, err := store.FindSessionByTokenHash(ctx, tx, hash[:]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FindSessionByTokenHash before create = %v, want ErrNotFound", err)
		}
		s := &store.Session{UserID: userID, TokenHash: hash[:], ExpiresAt: now.Add(time.Hour)}
		if err := tx.Sessions().Create(ctx, s); err != nil {
			return err
		}
		sessionID = s.ID
		if err := store.TouchSession(ctx, tx, s.ID, now); err != nil {
			return err
		}
		got, err := store.FindSessionByTokenHash(ctx, tx, hash[:])
		if err != nil {
			return err
		}
		if got.ID != sessionID || got.LastSeenAt == nil || !got.LastSeenAt.Equal(now) || got.RevokedAt != nil {
			t.Errorf("session after touch = %+v", got)
		}
		second := &store.Session{UserID: userID, TokenHash: []byte("other"), ExpiresAt: now.Add(time.Hour)}
		if err := tx.Sessions().Create(ctx, second); err != nil {
			return err
		}
		if err := store.RevokeSession(ctx, tx, second.ID, now); err != nil {
			return err
		}
		n, err := store.RevokeUserSessions(ctx, tx, userID, now.Add(time.Minute))
		if err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("RevokeUserSessions revoked %d sessions, want 1 (the other was already revoked)", n)
		}
		got, err = store.FindSessionByTokenHash(ctx, tx, hash[:])
		if err != nil {
			return err
		}
		if got.RevokedAt == nil {
			t.Error("session should be revoked")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("sessions: %v", err)
	}

	// Status and the admin list.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.SetUserStatus(ctx, tx, userID, store.UserDisabled, now); err != nil {
			return err
		}
		users, err := store.ListUsers(ctx, tx)
		if err != nil {
			return err
		}
		if len(users) != 1 || users[0].Status != store.UserDisabled || users[0].DisabledAt == nil {
			t.Errorf("ListUsers after disable = %+v", users)
		}
		if err := store.SetUserStatus(ctx, tx, userID, store.UserActive, now); err != nil {
			return err
		}
		users, err = store.ListUsers(ctx, tx)
		if err != nil {
			return err
		}
		if users[0].Status != store.UserActive || users[0].DisabledAt != nil {
			t.Errorf("ListUsers after enable = %+v", users)
		}
		if err := store.SetUserStatus(ctx, tx, userID, "weird", now); err == nil {
			t.Error("SetUserStatus accepted an unknown status")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		err := store.SetUserStatus(ctx, tx, "00000000-0000-0000-0000-000000000000", store.UserDisabled, now)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetUserStatus on a missing user = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("missing user: %v", err)
	}

	// Through the request-path role another user's rows stay hidden.
	other := newUser(t, st, "Bob")
	err = st.WithUser(ctx, other, func(tx store.Tx) error {
		users, err := store.ListUsers(ctx, tx)
		if err != nil {
			return err
		}
		if len(users) != 1 || users[0].ID != other {
			t.Errorf("ListUsers under a user scope = %+v, want only self", users)
		}
		if _, err := store.FindSessionByTokenHash(ctx, tx, hash[:]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("another user's session visible under a user scope: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("rls: %v", err)
	}
}
