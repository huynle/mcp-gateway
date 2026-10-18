package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Public sign-up (GATEWAY_SIGNUP_MODE): what happens to an account that
// signs in for the first time.
//
//   - open: the account is active at once with the default role (the
//     behaviour before sign-up modes existed);
//   - approval: the account is created pending, without any role. A pending
//     session never becomes a Principal: Middleware attaches a PendingUser
//     instead, so every route that asks for a principal (portal pages,
//     OAuth consent, connect flows, tunnels) treats it as anonymous, and
//     every credential check (tokens, OAuth codes and refresh tokens)
//     already refuses a user that is not active. An admin approves
//     (active + default role) or rejects (disabled) it on /admin/users;
//   - invite: the account needs a single-use invite code an admin created
//     on /admin/users; without a valid one nothing is created.
//
// Existing users and bootstrap admins are never affected. New-account
// creation is rate limited per client IP and globally (rolling hour).

// PendingPath is where a pending user lands after signing in; the portal
// serves the "waiting for approval" page there.
const PendingPath = "/pending"

// signupWindow is the rolling window of the new-account limits.
const signupWindow = time.Hour

// Default new-account limits when Config leaves them zero.
const (
	defaultSignupPerIP  = 10
	defaultSignupGlobal = 100
)

// Invite codes: a recognisable prefix (secret scanners, support) and 32
// random bytes. Only the SHA-256 is stored.
const (
	invitePrefix    = "mgwi_"
	inviteRandBytes = 32
	// MaxInviteTTL bounds an invite's lifetime.
	MaxInviteTTL = 30 * 24 * time.Hour
	// MaxInviteLabel bounds the admin's note on an invite.
	MaxInviteLabel = 100
	// maxInviteListed is how many invites the admin page shows.
	maxInviteListed = 50
)

// Sign-up errors.
var (
	// ErrSignupRateLimited: too many accounts were created recently; the
	// error is a *SignupRateLimitedError.
	ErrSignupRateLimited = errors.New("identity: too many new accounts")
	// ErrInviteRequired: invite mode and the sign-in carried no code.
	ErrInviteRequired = errors.New("identity: an invite is required to sign up")
	// ErrInviteInvalid: the code is malformed, unknown, used, revoked or
	// expired (deliberately indistinguishable).
	ErrInviteInvalid = errors.New("identity: the invite is invalid or expired")
	// ErrNotPending: approve or reject of a user that is not pending.
	ErrNotPending = errors.New("identity: user is not pending approval")
	// ErrUserPending: enable of a pending user (approve it instead).
	ErrUserPending = errors.New("identity: user is pending approval")
)

// SignupRateLimitedError names the limit that refused a new account:
// "ip" or "global".
type SignupRateLimitedError struct{ Scope string }

func (e *SignupRateLimitedError) Error() string {
	return ErrSignupRateLimited.Error() + " (" + e.Scope + ")"
}

// Unwrap makes errors.Is(err, ErrSignupRateLimited) hold.
func (e *SignupRateLimitedError) Unwrap() error { return ErrSignupRateLimited }

// Attempt is what the browser brings to a sign-in besides the verified
// claims.
type Attempt struct {
	// ClientIP keys the per-IP new-account limit (never stored: only a
	// hash of it is).
	ClientIP string
	// InviteCode is honoured in invite mode only.
	InviteCode string
	// trusted marks SignIn's in-process callers: exempt from the
	// new-account limit. An Attempt built outside the package (the
	// callback included) is never trusted, so an empty ClientIP still
	// counts (as one "unknown" client) rather than skipping the limit.
	trusted bool
}

// PendingUser is a signed-in account waiting for approval. It is attached
// by Middleware instead of a Principal; only the pending page and sign-out
// use it.
type PendingUser struct {
	UserID      string
	DisplayName string
	SessionID   string
	CSRFToken   string
}

type pendingKey struct{}

// PendingFrom returns the pending account attached by Middleware, or nil.
func PendingFrom(ctx context.Context) *PendingUser {
	p, _ := ctx.Value(pendingKey{}).(*PendingUser)
	return p
}

// WithPendingUser attaches a pending account to ctx (tests and trusted
// callers).
func WithPendingUser(ctx context.Context, p *PendingUser) context.Context {
	return context.WithValue(ctx, pendingKey{}, p)
}

// SignupMode is the configured sign-up mode.
func (s *Service) SignupMode() string { return s.cfg.SignupMode }

// BaseURL is the public origin (invite links).
func (s *Service) BaseURL() string { return s.cfg.BaseURL }

// SetAudit installs the recorder for sign-up and admin user events.
func (s *Service) SetAudit(rec audit.Recorder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = rec
}

// ClientIP is the per-IP key of a request: Config.ClientIP, else the host
// part of RemoteAddr.
func (s *Service) ClientIP(r *http.Request) string {
	if s.cfg.ClientIP != nil {
		return s.cfg.ClientIP(r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// signupClientKey is the stored per-IP key: a hash, never the address.
func signupClientKey(ip string) []byte {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = "unknown"
	}
	sum := sha256.Sum256([]byte("mcp-gateway/signup-ip:" + ip))
	return sum[:]
}

// checkSignupRate refuses a new account when the rolling-hour limits are
// reached. It locks sign-ups for the rest of tx so concurrent sign-ups
// cannot overshoot.
func (s *Service) checkSignupRate(ctx context.Context, tx Tx, key []byte, now time.Time) error {
	if err := tx.LockSignups(ctx); err != nil {
		return err
	}
	global, perIP, err := tx.CountSignups(ctx, key, now.Add(-signupWindow))
	if err != nil {
		return err
	}
	switch {
	case global >= s.cfg.SignupGlobalPerHour:
		return &SignupRateLimitedError{Scope: "global"}
	case perIP >= s.cfg.SignupPerIPPerHour:
		return &SignupRateLimitedError{Scope: "ip"}
	}
	return nil
}

// newUserStatus is the status of a non-bootstrap account created in the
// configured mode.
func (s *Service) newUserStatus() string {
	if s.cfg.SignupMode == config.SignupApproval {
		return store.UserPending
	}
	return store.UserActive
}

// --- invites ---------------------------------------------------------------------

// newInviteCode returns a fresh code and its stored hash.
func newInviteCode() (string, []byte, error) {
	raw := make([]byte, inviteRandBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("identity: invite code: %w", err)
	}
	code := invitePrefix + base64.RawURLEncoding.EncodeToString(raw)
	return code, hashInvite(code), nil
}

func hashInvite(code string) []byte {
	sum := sha256.Sum256([]byte("mcp-gateway/invite:" + code))
	return sum[:]
}

// validInviteShape reports whether code looks like an invite code (the
// lookup decides whether it is one).
func validInviteShape(code string) bool {
	body, ok := strings.CutPrefix(code, invitePrefix)
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	return err == nil && len(raw) == inviteRandBytes
}

// CreateInvite creates a single-use invite valid for ttl (at most
// MaxInviteTTL) and returns the code, shown to the admin once. label is
// the admin's note (kept out of the audit trail).
func (s *Service) CreateInvite(ctx context.Context, actorID, label string, ttl time.Duration) (string, store.SignupInvite, error) {
	label = strings.TrimSpace(label)
	if ttl <= 0 || ttl > MaxInviteTTL {
		return "", store.SignupInvite{}, fmt.Errorf("identity: invite lifetime must be between 1 second and %v", MaxInviteTTL)
	}
	if len(label) > MaxInviteLabel {
		return "", store.SignupInvite{}, fmt.Errorf("identity: invite label must be at most %d bytes", MaxInviteLabel)
	}
	code, hash, err := newInviteCode()
	if err != nil {
		return "", store.SignupInvite{}, err
	}
	inv := store.SignupInvite{CodeHash: hash, Label: label, ExpiresAt: s.now().Add(ttl)}
	if actorID != "" {
		inv.CreatedBy = &actorID
	}
	if err := s.store.Bypass(ctx, func(tx Tx) error { return tx.CreateInvite(ctx, &inv) }); err != nil {
		return "", store.SignupInvite{}, err
	}
	s.record(ctx, actorID, map[string]string{
		"action": "signup_invite.created", "invite_id": inv.ID, "expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339),
	}, "succeeded")
	s.log.Info("signup invite created", "event", "identity.invite_created", "invite_id", inv.ID, "actor_user_id", actorID)
	return code, inv, nil
}

// RevokeInvite revokes an unused invite (store.ErrNotFound otherwise).
func (s *Service) RevokeInvite(ctx context.Context, actorID, inviteID string) error {
	if err := s.store.Bypass(ctx, func(tx Tx) error { return tx.RevokeInvite(ctx, inviteID, s.now()) }); err != nil {
		return err
	}
	s.record(ctx, actorID, map[string]string{"action": "signup_invite.revoked", "invite_id": inviteID}, "succeeded")
	s.log.Info("signup invite revoked", "event", "identity.invite_revoked", "invite_id", inviteID, "actor_user_id", actorID)
	return nil
}

// ListInvites returns the newest invites (admin metadata; no codes).
func (s *Service) ListInvites(ctx context.Context) ([]store.SignupInvite, error) {
	var out []store.SignupInvite
	err := s.store.Bypass(ctx, func(tx Tx) error {
		var err error
		out, err = tx.ListInvites(ctx, maxInviteListed)
		return err
	})
	return out, err
}

// --- approval ----------------------------------------------------------------------

// ApproveUser activates a pending user and assigns the default role.
// store.ErrNotFound for an unknown user, ErrNotPending for one that is not
// pending.
func (s *Service) ApproveUser(ctx context.Context, actorID, userID string) error {
	now := s.now()
	var role string
	err := s.store.Bypass(ctx, func(tx Tx) error {
		if err := s.requirePending(ctx, tx, userID); err != nil {
			return err
		}
		if err := tx.TransitionUserStatus(ctx, userID, store.UserPending, store.UserActive, now); err != nil {
			return notPending(err)
		}
		r, err := s.defaultRole(ctx, tx)
		if err != nil {
			return err
		}
		role = r.Name
		var by *string
		if actorID != "" {
			by = &actorID
		}
		return tx.AssignRole(ctx, userID, r.ID, by)
	})
	if err != nil {
		return err
	}
	s.record(ctx, actorID, map[string]string{"action": "user.approved", "target_user_id": userID, "role": role}, "succeeded")
	s.log.Info("user approved", "event", "identity.user_approved", "user_id", userID, "actor_user_id", actorID, "role", role)
	return nil
}

// RejectUser disables a pending user: sessions end and the disable hooks
// run, exactly as DisableUser. store.ErrNotFound for an unknown user,
// ErrNotPending for one that is not pending.
func (s *Service) RejectUser(ctx context.Context, actorID, userID string) error {
	revoked, err := s.disable(ctx, userID, store.UserPending)
	if err != nil {
		return err
	}
	s.record(ctx, actorID, map[string]string{"action": "user.rejected", "target_user_id": userID}, "succeeded")
	s.log.Info("user rejected", "event", "identity.user_rejected", "user_id", userID, "actor_user_id", actorID, "sessions_revoked", revoked)
	return nil
}

func (s *Service) requirePending(ctx context.Context, tx Tx, userID string) error {
	u, err := tx.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.Status != store.UserPending {
		return ErrNotPending
	}
	return nil
}

// notPending maps a lost transition race (the row changed status between
// the read and the update) to ErrNotPending.
func notPending(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotPending
	}
	return err
}

// --- audit ------------------------------------------------------------------------

// record writes an audit event under userID ("" for system events). A
// failure is logged: the change is already committed.
func (s *Service) record(ctx context.Context, userID string, resource map[string]string, outcome string) {
	s.mu.RLock()
	rec := s.audit
	s.mu.RUnlock()
	if rec == nil {
		return
	}
	decision := "allow"
	if outcome == "denied" {
		decision = "deny"
	}
	ev := audit.Event{
		Time:             s.now(),
		UserID:           userID,
		ResourceIdentity: resource,
		Decision:         decision,
		Outcome:          outcome,
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if err := rec.Record(ctx, ev); err != nil {
		s.log.Error("audit event not recorded", "event", "identity.audit_failed", "action", resource["action"],
			"error", observability.RedactError(err))
	}
}
