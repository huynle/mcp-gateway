//go:build integration

package identity_test

import (
	"errors"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The sign-up flows against PostgreSQL: pending users, approval with the
// default role, single-use invites and the new-account limit, all through
// the production store adapter (bypass role, advisory lock).
func TestIntegrationSignupModes(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM signup_events`)
		if err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM signup_invites`)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	newSvc := func(mode string) *identity.Service {
		cfg := testConfig(dexProvider())
		cfg.SignupMode = mode
		cfg.SignupPerIPPerHour, cfg.SignupGlobalPerHour = 2, 100
		svc, err := identity.New(cfg, identity.NewPostgresStore(st), slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		return svc
	}

	approval := newSvc(config.SignupApproval)
	res, err := approval.SignInWith(ctx, "dex", claimsFor("pg-pending"), identity.Attempt{ClientIP: "203.0.113.5"})
	if err != nil || !res.Pending {
		t.Fatalf("approval sign-in = %+v, %v", res, err)
	}
	uid := res.PendingUser.UserID
	if err := approval.ApproveUser(ctx, "", uid); err != nil {
		t.Fatalf("ApproveUser: %v", err)
	}
	res, err = approval.SignIn(ctx, "dex", claimsFor("pg-pending"))
	if err != nil || res.Pending || !slices.Equal(res.Principal.Roles, []string{"member"}) {
		t.Fatalf("after approval = %+v, %v", res, err)
	}

	invite := newSvc(config.SignupInvite)
	if _, err := invite.SignInWith(ctx, "dex", claimsFor("pg-invitee"), identity.Attempt{ClientIP: "203.0.113.9"}); !errors.Is(err, identity.ErrInviteRequired) {
		t.Fatalf("no invite = %v", err)
	}
	code, _, err := invite.CreateInvite(ctx, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invite.SignInWith(ctx, "dex", claimsFor("pg-invitee"), identity.Attempt{ClientIP: "203.0.113.9", InviteCode: code}); err != nil {
		t.Fatalf("with invite: %v", err)
	}
	if _, err := invite.SignInWith(ctx, "dex", claimsFor("pg-other"), identity.Attempt{ClientIP: "203.0.113.9", InviteCode: code}); !errors.Is(err, identity.ErrInviteInvalid) {
		t.Fatalf("reused invite = %v", err)
	}

	open := newSvc(config.SignupOpen)
	if _, err := open.SignInWith(ctx, "dex", claimsFor("pg-open-1"), identity.Attempt{ClientIP: "203.0.113.5"}); err != nil {
		t.Fatalf("second account from .5: %v", err)
	}
	if _, err := open.SignInWith(ctx, "dex", claimsFor("pg-open-2"), identity.Attempt{ClientIP: "203.0.113.5"}); !errors.Is(err, identity.ErrSignupRateLimited) {
		t.Fatalf("third account from .5 = %v, want rate limited", err)
	}
	// The refused sign-up left no user behind.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.FindIdentity(ctx, tx, dexIssuer, "pg-open-2")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("refused sign-up created an identity: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
