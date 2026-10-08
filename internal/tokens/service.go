package tokens

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Limits from decision uamxx6ba and the portal's defaults.
const (
	// MaxExpiryDays is the longest a token may live.
	MaxExpiryDays = 90
	// DefaultExpiryDays applies when the request does not say.
	DefaultExpiryDays = 30
	// MaxNameLen bounds the display name.
	MaxNameLen = 100
	// DefaultSignInMaxAge is how long a token keeps working without a
	// company sign-in (GATEWAY_TOKEN_SIGNIN_MAX_AGE, 30 days).
	DefaultSignInMaxAge = 30 * 24 * time.Hour
	// touchInterval throttles last_used_at writes.
	touchInterval = time.Minute
)

// ErrInvalid reports a Create request that fails validation; the wrapped
// message says which field.
var ErrInvalid = errors.New("tokens: invalid request")

// Reason classifies an authentication failure; it is the auth_failures_total
// label and the log attribute.
type Reason string

// Every reason Authenticate can return.
const (
	ReasonMalformed    Reason = "malformed"
	ReasonUnknown      Reason = "unknown"
	ReasonRevoked      Reason = "revoked"
	ReasonExpired      Reason = "expired"
	ReasonUserDisabled Reason = "user_disabled"
	ReasonSignInStale  Reason = "signin_stale"
)

// StaleMessage is what a user whose company sign-in is too old is told.
const StaleMessage = "sign in to the portal to reactivate your tokens"

// Error is a rejected bearer token. PublicID is set when the token parsed
// (it is safe to show and log); the secret never is.
type Error struct {
	Reason   Reason
	PublicID string
}

func (e *Error) Error() string { return "tokens: " + e.Message() }

// Message is the user-facing explanation; the /mcp endpoint may echo it.
func (e *Error) Message() string {
	switch e.Reason {
	case ReasonMalformed:
		return "malformed token"
	case ReasonUnknown:
		return "unknown token"
	case ReasonRevoked:
		return "token revoked"
	case ReasonExpired:
		return "token expired"
	case ReasonUserDisabled:
		return "user disabled"
	case ReasonSignInStale:
		return StaleMessage
	}
	return "invalid token"
}

// Principal is an authenticated token: who it belongs to, which token it is
// and what the token itself allows. The pipeline combines Scope with the
// user's role; this package does not know about policy.
type Principal struct {
	UserID   string
	TokenID  string
	PublicID string
	Scope    Scope
}

// Authenticator turns a bearer string into a Principal. Service implements
// it; the /mcp endpoint depends on the interface so it can be composed with
// the OAuth access-token authenticator and faked in tests.
type Authenticator interface {
	// Authenticate returns a *Error (with a Reason) for every rejected
	// token and a plain error only when the lookup itself failed.
	Authenticate(ctx context.Context, bearer string) (*Principal, error)
}

// Config is the service configuration.
type Config struct {
	// SignInMaxAge: a token stops working when its owner's last company
	// sign-in is older than this. Zero is invalid; use DefaultSignInMaxAge.
	SignInMaxAge time.Duration
}

// CreateRequest is what the portal form submits.
type CreateRequest struct {
	Name string
	// ExpiryDays in [1, MaxExpiryDays]; 0 means DefaultExpiryDays.
	ExpiryDays int
	ReadOnly   bool
	// AllowList is the free-text app/tool list (see ParseAllowList).
	AllowList string
}

// Info is a token as the portal shows it: never the hash.
type Info struct {
	ID         string
	UserID     string
	PublicID   string
	Name       string
	Scope      Scope
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// Prefix is the recognisable, non-secret start of the token ("mgw_" +
// public id) that lists and logs may show.
func (i Info) Prefix() string { return Prefix + i.PublicID }

// Active reports whether the token is neither revoked nor expired at now.
func (i Info) Active(now time.Time) bool { return i.RevokedAt == nil && now.Before(i.ExpiresAt) }

// Created is the result of Create: the stored token and the full token
// string, which exists nowhere else.
type Created struct {
	Token Info
	Raw   string
}

// Service owns token creation, listing, revocation and authentication.
type Service struct {
	cfg     Config
	store   Store
	metrics *observability.Metrics
	audit   audit.Recorder
	log     *slog.Logger
	now     func() time.Time
}

// New builds the service. metrics, rec and log may be nil (no metrics, no
// audit events, default logger).
func New(cfg Config, st Store, metrics *observability.Metrics, rec audit.Recorder, log *slog.Logger) (*Service, error) {
	if cfg.SignInMaxAge <= 0 {
		return nil, errors.New("tokens: sign-in max age must be positive")
	}
	if st == nil {
		return nil, errors.New("tokens: store must not be nil")
	}
	if rec == nil {
		rec = audit.NopRecorder{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		cfg:     cfg,
		store:   st,
		metrics: metrics,
		audit:   rec,
		log:     log,
		now:     func() time.Time { return time.Now().UTC() },
	}, nil
}

// SetClock replaces the time source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Create mints a token for userID. The returned Created.Raw is the only
// copy of the full token; the store keeps the hash.
func (s *Service) Create(ctx context.Context, userID string, req CreateRequest) (*Created, error) {
	name := strings.TrimSpace(req.Name)
	switch {
	case name == "":
		return nil, fmt.Errorf("%w: name is required", ErrInvalid)
	case len(name) > MaxNameLen:
		return nil, fmt.Errorf("%w: name must be at most %d characters", ErrInvalid, MaxNameLen)
	}
	days := req.ExpiryDays
	if days == 0 {
		days = DefaultExpiryDays
	}
	if days < 1 || days > MaxExpiryDays {
		return nil, fmt.Errorf("%w: expiry must be between 1 and %d days", ErrInvalid, MaxExpiryDays)
	}
	scope, err := ParseAllowList(req.AllowList)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	scope.ReadOnly = req.ReadOnly
	scopeDoc, err := scope.MarshalStore()
	if err != nil {
		return nil, err
	}
	g, err := Generate()
	if err != nil {
		return nil, err
	}
	now := s.now()
	row := &store.Token{
		UserID:    userID,
		PublicID:  g.PublicID,
		Name:      name,
		TokenHash: g.Hash,
		ReadOnly:  req.ReadOnly,
		Scope:     scopeDoc,
		ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour),
	}
	err = s.store.AsUser(ctx, userID, func(tx Tx) error { return tx.CreateToken(ctx, row) })
	if err != nil {
		return nil, err
	}
	info := toInfo(*row, scope)
	s.log.Info("token created", "event", "tokens.created", "user_id", userID, "token_id", info.ID,
		"public_id", info.PublicID, "expires_at", info.ExpiresAt, "read_only", scope.ReadOnly, "restricted", scope.IsRestricted())
	s.record(ctx, userID, info, "token_created")
	return &Created{Token: info, Raw: g.Raw}, nil
}

// List returns userID's tokens, newest first, including revoked and
// expired ones so the user can see the history.
func (s *Service) List(ctx context.Context, userID string) ([]Info, error) {
	var out []Info
	err := s.store.AsUser(ctx, userID, func(tx Tx) error {
		rows, err := tx.ListTokensForUser(ctx, userID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			scope, err := ScopeFromStore(r.Scope, r.ReadOnly)
			if err != nil {
				return err
			}
			out = append(out, toInfo(r, scope))
		}
		return nil
	})
	return out, err
}

// Revoke revokes one of userID's tokens. Another user's token is
// store.ErrNotFound (row-level security hides it); revoking twice is not
// an error.
func (s *Service) Revoke(ctx context.Context, userID, tokenID string) error {
	now := s.now()
	var revokedAt time.Time
	err := s.store.AsUser(ctx, userID, func(tx Tx) error {
		var err error
		revokedAt, err = tx.RevokeToken(ctx, tokenID, now)
		return err
	})
	if err != nil {
		return err
	}
	if !revokedAt.Equal(now) {
		return nil // already revoked earlier: nothing new to log or audit
	}
	s.log.Info("token revoked", "event", "tokens.revoked", "user_id", userID, "token_id", tokenID)
	s.record(ctx, userID, Info{ID: tokenID}, "token_revoked")
	return nil
}

// DisableHook returns the identity.DisableHook that revokes every token of
// a user being disabled, inside the disabling transaction when there is
// one (tx is nil on non-PostgreSQL stores; then it uses Bypass).
func (s *Service) DisableHook() identity.DisableHook {
	return func(ctx context.Context, tx store.Tx, userID string) error {
		now := s.now()
		var n int64
		var err error
		if tx != nil {
			n, err = pgTx{tx}.RevokeUserTokens(ctx, userID, now)
		} else {
			err = s.store.Bypass(ctx, func(t Tx) error {
				n, err = t.RevokeUserTokens(ctx, userID, now)
				return err
			})
		}
		if err != nil {
			return fmt.Errorf("tokens: revoke on disable: %w", err)
		}
		s.log.Info("tokens revoked on disable", "event", "tokens.revoked_on_disable", "user_id", userID, "revoked", n)
		return nil
	}
}

// Authenticate implements Authenticator: parse, one narrow bypass lookup
// by public id, constant-time hash compare, then revocation, expiry, owner
// status and sign-in freshness. Every rejection increments
// auth_failures_total{reason} and logs the reason and public id, never the
// secret. A successful call touches last_used_at at most once a minute,
// best-effort.
func (s *Service) Authenticate(ctx context.Context, bearer string) (*Principal, error) {
	publicID, secret, err := Parse(bearer)
	if err != nil {
		return nil, s.reject(ReasonMalformed, "")
	}
	var lookup *store.TokenLookup
	err = s.store.Bypass(ctx, func(tx Tx) error {
		var err error
		lookup, err = tx.FindTokenByPublicID(ctx, publicID)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, s.reject(ReasonUnknown, publicID)
	case err != nil:
		s.log.Error("token lookup failed", "event", "tokens.lookup_failed", "public_id", publicID, "error", observability.RedactError(err))
		return nil, fmt.Errorf("tokens: lookup: %w", err)
	}
	tok := &lookup.Token
	if subtle.ConstantTimeCompare(HashSecret(secret), tok.TokenHash) != 1 {
		return nil, s.reject(ReasonUnknown, publicID)
	}
	now := s.now()
	switch {
	case tok.RevokedAt != nil:
		return nil, s.reject(ReasonRevoked, publicID)
	case !now.Before(tok.ExpiresAt):
		return nil, s.reject(ReasonExpired, publicID)
	case lookup.UserStatus != store.UserActive:
		return nil, s.reject(ReasonUserDisabled, publicID)
	case lookup.LastCompanySignInAt == nil || now.Sub(*lookup.LastCompanySignInAt) > s.cfg.SignInMaxAge:
		return nil, s.reject(ReasonSignInStale, publicID)
	}
	scope, err := ScopeFromStore(tok.Scope, tok.ReadOnly)
	if err != nil {
		s.log.Error("token scope unreadable", "event", "tokens.scope_invalid", "public_id", publicID, "error", observability.RedactError(err))
		return nil, err
	}
	if tok.LastUsedAt == nil || now.Sub(*tok.LastUsedAt) >= touchInterval {
		s.touch(ctx, tok.ID, publicID, now)
	}
	return &Principal{UserID: tok.UserID, TokenID: tok.ID, PublicID: publicID, Scope: scope}, nil
}

// touch records last_used_at in its own transaction so a failure can be
// logged and ignored: it must never fail authentication (quirk 01mepmn6:
// a failed statement would abort the lookup transaction).
func (s *Service) touch(ctx context.Context, id, publicID string, now time.Time) {
	err := s.store.Bypass(ctx, func(tx Tx) error { return tx.TouchToken(ctx, id, now) })
	if err != nil {
		s.log.Warn("last_used_at not updated", "event", "tokens.touch_failed", "public_id", publicID, "error", observability.RedactError(err))
	}
}

// reject counts and logs a failure and builds its error.
func (s *Service) reject(reason Reason, publicID string) error {
	if s.metrics != nil {
		s.metrics.AuthFailure(string(reason))
	}
	s.log.Warn("token rejected", "event", "tokens.auth_failed", "reason", string(reason), "public_id", publicID)
	return &Error{Reason: reason, PublicID: publicID}
}

// record files a user audit event; a failure is logged, never surfaced,
// because the action it describes has already been committed.
func (s *Service) record(ctx context.Context, userID string, info Info, action string) {
	ev := audit.Event{
		Time:             s.now(),
		UserID:           userID,
		TokenID:          info.ID,
		ResourceIdentity: map[string]string{"action": action},
		Decision:         "allow",
		Outcome:          "succeeded",
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if info.Name != "" {
		ev.ResourceIdentity["name"] = info.Name
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.Error("audit event not recorded", "event", "tokens.audit_failed", "action", action, "error", observability.RedactError(err))
	}
}

func toInfo(t store.Token, scope Scope) Info {
	return Info{
		ID:         t.ID,
		UserID:     t.UserID,
		PublicID:   t.PublicID,
		Name:       t.Name,
		Scope:      scope,
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
	}
}
