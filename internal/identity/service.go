package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Role names the service relies on.
const (
	// AdminRole manages users, roles and settings in the portal. It never
	// bypasses tool policy (decision uamxx6ba).
	AdminRole = "admin"
)

// Sentinel errors.
var (
	ErrUnknownProvider = errors.New("identity: unknown provider")
	ErrNotAllowed      = errors.New("identity: account not allowed to sign in")
	ErrUserDisabled    = errors.New("identity: user is disabled")
)

// Config is the identity service configuration, taken from config.Config.
type Config struct {
	// BaseURL is the public origin, used to build redirect URIs.
	BaseURL string
	// Providers are the configured company identity providers.
	Providers []config.OIDCProvider
	// DefaultRole is assigned to users created on first sign-in.
	DefaultRole string
	// BootstrapAdmins are "issuer|subject" pairs granted AdminRole on
	// every sign-in.
	BootstrapAdmins []string
	// IdleTimeout and AbsoluteTimeout bound browser sessions.
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	// CookieSecure sets the Secure flag on cookies.
	CookieSecure bool
	// HTTPClient talks to the providers; nil means a 30 s default.
	HTTPClient *http.Client
}

// FromConfig derives the identity Config from the gateway configuration.
func FromConfig(c config.Config) Config {
	return Config{
		BaseURL:         c.BaseURL,
		Providers:       c.OIDCProviders,
		DefaultRole:     c.DefaultRole,
		BootstrapAdmins: c.BootstrapAdmins,
		IdleTimeout:     c.SessionIdleTimeout,
		AbsoluteTimeout: c.SessionAbsoluteTimeout,
		CookieSecure:    c.SessionCookieSecure,
	}
}

// DisableHook runs inside the transaction that disables a user so other
// modules (tokens, OAuth sessions, connections) can revoke their rows
// atomically. tx is nil when the service runs on a non-PostgreSQL Store.
type DisableHook func(ctx context.Context, tx store.Tx, userID string) error

// ProviderInfo describes a sign-in option for the portal.
type ProviderInfo struct {
	Name        string
	DisplayName string
}

// Principal is the signed-in user attached to a request.
type Principal struct {
	UserID      string
	DisplayName string
	Roles       []string
	SessionID   string
	// CSRFToken is derived from the session secret; forms echo it back.
	CSRFToken string
}

// IsAdmin reports whether the principal holds AdminRole.
func (p *Principal) IsAdmin() bool { return p != nil && slices.Contains(p.Roles, AdminRole) }

// UserSummary is one row of the admin user list.
type UserSummary struct {
	store.User
	Roles []string
}

// SignInResult is a completed sign-in: the new principal and the session
// cookie to set.
type SignInResult struct {
	Principal *Principal
	Created   bool
	Cookie    *http.Cookie
}

// Service owns users, identities, sessions and the sign-in flow.
type Service struct {
	cfg       Config
	providers []*provider
	byName    map[string]*provider
	admins    map[string]bool // "issuer|subject"
	store     Store
	log       *slog.Logger
	now       func() time.Time

	mu           sync.RWMutex
	hooks        []DisableHook
	errorHandler ErrorHandler
}

// New builds the service. Provider discovery is lazy (first use), so a
// provider outage does not block gateway startup.
func New(cfg Config, st Store, log *slog.Logger) (*Service, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.DefaultRole == "" {
		return nil, errors.New("identity: default role must not be empty")
	}
	if cfg.IdleTimeout <= 0 || cfg.AbsoluteTimeout <= 0 {
		return nil, errors.New("identity: session timeouts must be positive")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	s := &Service{
		cfg:    cfg,
		byName: map[string]*provider{},
		admins: map[string]bool{},
		store:  st,
		log:    log,
		now:    func() time.Time { return time.Now().UTC() },
	}
	for _, pc := range cfg.Providers {
		if _, dup := s.byName[pc.Name]; dup {
			return nil, fmt.Errorf("identity: provider %q configured twice", pc.Name)
		}
		p := newProvider(pc, strings.TrimRight(cfg.BaseURL, "/")+"/auth/"+pc.Name+"/callback", cfg.HTTPClient)
		s.providers = append(s.providers, p)
		s.byName[pc.Name] = p
	}
	for _, a := range cfg.BootstrapAdmins {
		issuer, subject, ok := strings.Cut(a, "|")
		if !ok {
			return nil, fmt.Errorf("identity: bootstrap admin %q must be issuer|subject", a)
		}
		s.admins[adminKey(strings.TrimSpace(issuer), strings.TrimSpace(subject))] = true
	}
	return s, nil
}

func adminKey(issuer, subject string) string { return issuer + "|" + subject }

// SetClock replaces the time source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Providers lists the configured providers in configuration order.
func (s *Service) Providers() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(s.providers))
	for _, p := range s.providers {
		out = append(out, ProviderInfo{Name: p.cfg.Name, DisplayName: p.cfg.DisplayName})
	}
	return out
}

// OnDisable registers a hook that runs whenever a user is disabled.
func (s *Service) OnDisable(h DisableHook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks = append(s.hooks, h)
}

// SignIn completes a company sign-in with verified claims from provider
// providerName: it enforces the provider's allow-list, creates the user on
// first sign-in with the default role (identity = issuer+subject, never
// email; no cross-provider linking), grants bootstrap admins the admin
// role, records the sign-in time and opens a fresh session.
func (s *Service) SignIn(ctx context.Context, providerName string, c Claims) (*SignInResult, error) {
	p, ok := s.byName[providerName]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, providerName)
	}
	if reason := allow(p.cfg, c); reason != "" {
		s.log.Warn("sign-in rejected",
			"event", "identity.signin_rejected",
			"provider", providerName, "issuer", c.Issuer, "subject", c.Subject,
			"reason", reason, "domain", domainOf(p.cfg, c))
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, reason)
	}

	now := s.now()
	secret, hash, err := newSessionSecret()
	if err != nil {
		return nil, err
	}
	var (
		user    *store.User
		created bool
		roles   []string
		session *store.Session
	)
	err = s.store.Bypass(ctx, func(tx Tx) error {
		var ident *store.Identity
		ident, err := tx.FindIdentity(ctx, c.Issuer, c.Subject)
		switch {
		case errors.Is(err, store.ErrNotFound):
			user, err = tx.CreateUser(ctx, c.displayName())
			if err != nil {
				return err
			}
			if ident, err = tx.CreateIdentity(ctx, user.ID, c.Issuer, c.Subject); err != nil {
				return err
			}
			role, err := s.defaultRole(ctx, tx)
			if err != nil {
				return err
			}
			if err := tx.AssignRole(ctx, user.ID, role.ID, nil); err != nil {
				return err
			}
			created = true
		case err != nil:
			return err
		default:
			if user, err = tx.GetUser(ctx, ident.UserID); err != nil {
				return err
			}
			if user.Status != store.UserActive {
				return ErrUserDisabled
			}
		}
		if s.admins[adminKey(c.Issuer, c.Subject)] {
			role, err := tx.EnsureRole(ctx, AdminRole, "Manages users, roles, vendor apps and settings")
			if err != nil {
				return err
			}
			if err := tx.AssignRole(ctx, user.ID, role.ID, nil); err != nil {
				return err
			}
		}
		if err := tx.RecordSignIn(ctx, user.ID, ident.ID, c.displayName(), now); err != nil {
			return err
		}
		if roles, err = roleNames(ctx, tx, user.ID); err != nil {
			return err
		}
		session, err = tx.CreateSession(ctx, user.ID, hash, now.Add(s.cfg.AbsoluteTimeout))
		return err
	})
	if err != nil {
		if errors.Is(err, ErrUserDisabled) {
			s.log.Warn("sign-in rejected",
				"event", "identity.signin_rejected",
				"provider", providerName, "issuer", c.Issuer, "subject", c.Subject,
				"user_id", user.ID, "reason", "user_disabled")
		}
		return nil, err
	}
	s.log.Info("user signed in",
		"event", "identity.signin",
		"provider", providerName, "issuer", c.Issuer, "subject", c.Subject,
		"user_id", user.ID, "created", created, "roles", roles)
	return &SignInResult{
		Principal: &Principal{
			UserID:      user.ID,
			DisplayName: c.displayName(),
			Roles:       roles,
			SessionID:   session.ID,
			CSRFToken:   csrfToken(secret),
		},
		Created: created,
		Cookie:  s.sessionCookie(secret, now.Add(s.cfg.AbsoluteTimeout)),
	}, nil
}

// defaultRole is the role a new user receives: the one admins flagged as
// default in the portal when there is one, else the configured
// DefaultRole (created on first use).
func (s *Service) defaultRole(ctx context.Context, tx Tx) (*store.Role, error) {
	role, err := tx.FindDefaultRole(ctx)
	switch {
	case err == nil:
		return role, nil
	case errors.Is(err, store.ErrNotFound):
		return tx.EnsureRole(ctx, s.cfg.DefaultRole, "Default role for new users")
	default:
		return nil, err
	}
}

func roleNames(ctx context.Context, tx Tx, userID string) ([]string, error) {
	roles, err := tx.RolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, r.Name)
	}
	slices.Sort(names)
	return names, nil
}

// DisableUser disables a user, revokes every session and runs the
// registered hooks in the same transaction. actorID is the acting admin
// ("" for system) and is only logged.
func (s *Service) DisableUser(ctx context.Context, actorID, userID string) error {
	now := s.now()
	var revoked int64
	err := s.store.Bypass(ctx, func(tx Tx) error {
		if err := tx.SetUserStatus(ctx, userID, store.UserDisabled, now); err != nil {
			return err
		}
		var err error
		if revoked, err = tx.RevokeUserSessions(ctx, userID, now); err != nil {
			return err
		}
		return s.RunDisableHooks(ctx, tx.Raw(), userID)
	})
	if err != nil {
		return err
	}
	s.log.Info("user disabled", "event", "identity.user_disabled", "user_id", userID, "actor_user_id", actorID, "sessions_revoked", revoked)
	return nil
}

// EnableUser re-activates a disabled user. Nothing revoked on disable is
// restored.
func (s *Service) EnableUser(ctx context.Context, actorID, userID string) error {
	err := s.store.Bypass(ctx, func(tx Tx) error {
		return tx.SetUserStatus(ctx, userID, store.UserActive, s.now())
	})
	if err != nil {
		return err
	}
	s.log.Info("user enabled", "event", "identity.user_enabled", "user_id", userID, "actor_user_id", actorID)
	return nil
}

// SetUserRole replaces the user's roles with the named existing role.
func (s *Service) SetUserRole(ctx context.Context, actorID, userID, roleName string) error {
	err := s.store.Bypass(ctx, func(tx Tx) error {
		role, err := tx.FindRoleByName(ctx, roleName)
		if err != nil {
			return err
		}
		var by *string
		if actorID != "" {
			by = &actorID
		}
		return tx.SetUserRole(ctx, userID, role.ID, by)
	})
	if err != nil {
		return err
	}
	s.log.Info("user role set", "event", "identity.user_role_set", "user_id", userID, "actor_user_id", actorID, "role", roleName)
	return nil
}

// ListUsers returns every user with their role names (admin metadata).
func (s *Service) ListUsers(ctx context.Context) ([]UserSummary, error) {
	var out []UserSummary
	err := s.store.Bypass(ctx, func(tx Tx) error {
		users, err := tx.ListUsers(ctx)
		if err != nil {
			return err
		}
		for _, u := range users {
			names, err := roleNames(ctx, tx, u.ID)
			if err != nil {
				return err
			}
			out = append(out, UserSummary{User: u, Roles: names})
		}
		return nil
	})
	return out, err
}

// ListRoles returns every role.
func (s *Service) ListRoles(ctx context.Context) ([]store.Role, error) {
	var out []store.Role
	err := s.store.Bypass(ctx, func(tx Tx) error {
		var err error
		out, err = tx.ListRoles(ctx)
		return err
	})
	slices.SortFunc(out, func(a, b store.Role) int { return strings.Compare(a.Name, b.Name) })
	return out, err
}
