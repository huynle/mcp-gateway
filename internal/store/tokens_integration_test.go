//go:build integration

package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// newToken inserts a token for userID under that user's scope.
func newToken(t *testing.T, st *store.Store, userID, publicID, name string, expiresAt time.Time) *store.Token {
	t.Helper()
	tok := &store.Token{UserID: userID, PublicID: publicID, Name: name, TokenHash: []byte("hash-" + publicID), ExpiresAt: expiresAt}
	err := st.WithUser(t.Context(), userID, func(tx store.Tx) error {
		return tx.Tokens().Create(t.Context(), tok)
	})
	if err != nil {
		t.Fatalf("create token %s: %v", publicID, err)
	}
	return tok
}

func TestIntegrationTokenLookupsAndRLS(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	signedIn := now.Add(-time.Hour)

	userA := newUser(t, st, "alice")
	userB := newUser(t, st, "bob")
	// A sign-in so the lookup can report last_company_sign_in_at.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET last_company_sign_in_at = $2 WHERE id = $1`, userA, signedIn)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	tokA := newToken(t, st, userA, "aaaaaaaa", "laptop", now.Add(24*time.Hour))
	tokA2 := newToken(t, st, userA, "aaaaaaa2", "desktop", now.Add(48*time.Hour))
	tokB := newToken(t, st, userB, "bbbbbbbb", "phone", now.Add(24*time.Hour))

	// Create returns the row's identity and persists the public id.
	if tokA.ID == "" || tokA.PublicID != "aaaaaaaa" || tokA.CreatedAt.IsZero() {
		t.Fatalf("created token = %+v", tokA)
	}
	// A duplicate public id is refused.
	err := st.WithUser(ctx, userA, func(tx store.Tx) error {
		return tx.Tokens().Create(ctx, &store.Token{UserID: userA, PublicID: "aaaaaaaa", Name: "dup", TokenHash: []byte("other"), ExpiresAt: now.Add(time.Hour)})
	})
	if err == nil {
		t.Error("duplicate public id accepted")
	}

	// The pre-auth lookup runs through the bypass scope and joins the owner.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		got, err := store.FindTokenByPublicID(ctx, tx, "aaaaaaaa")
		if err != nil {
			return err
		}
		if got.Token.ID != tokA.ID || got.Token.UserID != userA || string(got.Token.TokenHash) != "hash-aaaaaaaa" || got.Token.PublicID != "aaaaaaaa" {
			t.Errorf("lookup = %+v", got.Token)
		}
		if got.UserStatus != store.UserActive || got.LastCompanySignInAt == nil || !got.LastCompanySignInAt.Equal(signedIn) {
			t.Errorf("owner = status %q sign-in %v, want active %v", got.UserStatus, got.LastCompanySignInAt, signedIn)
		}
		if _, err := store.FindTokenByPublicID(ctx, tx, "nope0000"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unknown public id = %v, want ErrNotFound", err)
		}
		// Touching last_used_at.
		if err := store.TouchToken(ctx, tx, tokA.ID, now); err != nil {
			return err
		}
		got, err = store.FindTokenByPublicID(ctx, tx, "aaaaaaaa")
		if err != nil {
			return err
		}
		if got.Token.LastUsedAt == nil || !got.Token.LastUsedAt.Equal(now) {
			t.Errorf("last_used_at = %v, want %v", got.Token.LastUsedAt, now)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("jobs lookup: %v", err)
	}

	// Under the app role without a user scope the lookup sees nothing.
	err = st.WithUser(ctx, userB, func(tx store.Tx) error {
		_, err := store.FindTokenByPublicID(ctx, tx, "aaaaaaaa")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("user B looking up A's token = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Listing is scoped: A sees A's two tokens newest first, B sees only B's.
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		list, err := store.ListTokensForUser(ctx, tx, userA)
		if err != nil {
			return err
		}
		if len(list) != 2 || list[0].ID != tokA2.ID || list[1].ID != tokA.ID {
			t.Errorf("A's tokens = %+v", list)
		}
		for _, tok := range list {
			if tok.PublicID == "" {
				t.Errorf("listed token without public id: %+v", tok)
			}
		}
		// Asking for B's rows under A's scope yields nothing (RLS), never B's tokens.
		other, err := store.ListTokensForUser(ctx, tx, userB)
		if err != nil {
			return err
		}
		if len(other) != 0 {
			t.Errorf("A listing B's tokens = %+v", other)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// B cannot revoke A's token: the update affects no visible row.
	err = st.WithUser(ctx, userB, func(tx store.Tx) error {
		err := store.RevokeToken(ctx, tx, tokA.ID, now)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B revoking A's token = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A revokes their own; a second revoke keeps the first timestamp.
	later := now.Add(time.Minute)
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		if err := store.RevokeToken(ctx, tx, tokA.ID, now); err != nil {
			return err
		}
		if err := store.RevokeToken(ctx, tx, tokA.ID, later); err != nil {
			return err
		}
		got, err := tx.Tokens().Get(ctx, tokA.ID)
		if err != nil {
			return err
		}
		if got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
			t.Errorf("revoked_at = %v, want %v", got.RevokedAt, now)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Revoking every token of a user (the disable hook) runs under the
	// bypass scope and leaves other users alone.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		n, err := store.RevokeUserTokens(ctx, tx, userA, later)
		if err != nil {
			return err
		}
		if n != 1 { // tokA was already revoked
			t.Errorf("revoked %d of A's tokens, want 1", n)
		}
		b, err := store.FindTokenByPublicID(ctx, tx, tokB.PublicID)
		if err != nil {
			return err
		}
		if b.Token.RevokedAt != nil {
			t.Errorf("B's token revoked by A's purge: %+v", b.Token)
		}
		a2, err := store.FindTokenByPublicID(ctx, tx, tokA2.PublicID)
		if err != nil {
			return err
		}
		if a2.Token.RevokedAt == nil || !a2.Token.RevokedAt.Equal(later) {
			t.Errorf("A's second token revoked_at = %v, want %v", a2.Token.RevokedAt, later)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The admin projection shows the public id and never the hash.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		var publicID string
		if err := tx.QueryRow(ctx, `SELECT public_id FROM admin_tokens WHERE id = $1`, tokA.ID).Scan(&publicID); err != nil {
			return err
		}
		if publicID != "aaaaaaaa" {
			t.Errorf("admin_tokens.public_id = %q", publicID)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'admin_tokens' AND column_name = 'token_hash'`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Error("admin_tokens exposes token_hash")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
