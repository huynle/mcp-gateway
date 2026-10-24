package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/store"
)

// DefaultAPIKeyHeader carries an api_key when the server's auth_config
// names neither a header nor a query parameter.
const DefaultAPIKeyHeader = "X-API-Key"

// Authorizer is a client.Authorizer that can react to an upstream 401.
// Unauthorized is called after the upstream rejected the credential this
// Authorizer supplied: an OAuth authorizer refreshes once (nil = retry),
// and on the next call, or when no refresh is possible, marks the user's
// connection needs_reconnect and returns ErrNeedsReconnect. Static
// per-user credentials go straight to needs_reconnect; shared ones return
// ErrSharedCredentialRejected (only the owner or an admin can fix them).
type Authorizer interface {
	client.Authorizer
	Unauthorized(ctx context.Context) error
}

// ForUser returns the Authorizer for userID's calls to server, per the
// server's credential mode and auth kind: the user's own connection
// (per_user) or the server's shared credential (shared), plus the user's
// values for per-user headers. The caller (the federation connector) has
// already checked the user may use the server. Errors: ErrNotConnected,
// ErrNeedsReconnect, ErrNotConfigured (owner-only causes:
// ErrSharedMissing, ErrModeInvalid), ErrUnsupported, and, when the
// service requires per-user headers, ErrUserHeaderMissing.
func (s *Service) ForUser(ctx context.Context, server *store.MCPServer, userID string) (Authorizer, error) {
	if server == nil || userID == "" {
		return nil, fmt.Errorf("%w: no server or user", ErrNotConfigured)
	}
	kind := server.AuthKind
	switch kind {
	case store.MCPAuthNone:
		return noAuth{}, nil
	case store.MCPAuthOAuth, store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders:
	default:
		return nil, fmt.Errorf("%w: auth kind %q", ErrModeInvalid, kind)
	}
	hc := parseHeaderConfig(server.HeaderConfig)
	switch server.CredentialMode {
	case store.MCPCredentialPerUser:
		b, err := s.userBundle(ctx, server, userID)
		if err != nil {
			return nil, err
		}
		if kind == store.MCPAuthOAuth && b.OAuth == nil {
			return nil, ErrNotConnected
		}
		extra, err := s.userHeaders(b.Headers, hc.PerUser)
		if err != nil {
			return nil, err
		}
		if kind == store.MCPAuthOAuth {
			return &oauthAuthorizer{s: s, server: server, userID: userID, tok: b.OAuth, extra: extra}, nil
		}
		return s.staticAuthorizer(server, userID, b, extra, false)
	case store.MCPCredentialShared:
		if kind == store.MCPAuthOAuth {
			return nil, fmt.Errorf("%w: shared OAuth tokens", ErrUnsupported)
		}
		b, err := s.sharedBundle(ctx, server)
		if err != nil {
			return nil, err
		}
		var extra map[string]string
		if len(hc.PerUser) > 0 {
			ub, err := s.userBundle(ctx, server, userID)
			var values map[string]string
			switch {
			case err == nil:
				values = ub.Headers
			case s.requireHeaders && !errors.Is(err, ErrNotConnected) && !errors.Is(err, ErrNeedsReconnect):
				return nil, err
			}
			if extra, err = s.userHeaders(values, hc.PerUser); err != nil {
				return nil, err
			}
		}
		return s.staticAuthorizer(server, userID, b, extra, true)
	}
	return nil, fmt.Errorf("%w: credential mode %q", ErrModeInvalid, server.CredentialMode)
}

// userHeaders picks the user's values of the declared per-user headers.
// A declared header without a value is left out, or, when the service
// requires them, refused with ErrUserHeaderMissing.
func (s *Service) userHeaders(values map[string]string, names []string) (map[string]string, error) {
	extra := pick(values, names)
	if s.requireHeaders {
		for _, n := range names {
			if _, ok := extra[http.CanonicalHeaderKey(n)]; !ok {
				return nil, ErrUserHeaderMissing
			}
		}
	}
	return extra, nil
}

// userBundle loads and opens userID's active connection to server.
func (s *Service) userBundle(ctx context.Context, server *store.MCPServer, userID string) (*secretBundle, error) {
	var c *store.MCPUserConnection
	err := s.store.AsUser(ctx, userID, func(tx Tx) (err error) {
		c, err = tx.GetUserConnection(ctx, server.ID, userID)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, ErrNotConnected
	case err != nil:
		return nil, fmt.Errorf("auth: load connection: %w", err)
	case c.Status != store.MCPConnectionActive:
		return nil, ErrNeedsReconnect
	}
	b, err := s.openUserBundle(ctx, server, c)
	if err != nil {
		// Sealed for another auth kind or key: the user has to set it again.
		return nil, ErrNeedsReconnect
	}
	return b, nil
}

// sharedBundle loads the server's shared credential (bypass scope: users
// of a published server never read the row themselves).
func (s *Service) sharedBundle(ctx context.Context, server *store.MCPServer) (*secretBundle, error) {
	var sec *store.MCPServerSharedSecret
	err := s.store.Bypass(ctx, func(tx Tx) (err error) {
		sec, err = tx.GetSharedSecret(ctx, server.ID)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, fmt.Errorf("%w: no shared credential", ErrSharedMissing)
	case err != nil:
		return nil, fmt.Errorf("auth: load shared credential: %w", err)
	}
	var b secretBundle
	if err := s.open(ctx, aadShared(server), sec.Secret, &b); err != nil {
		return nil, fmt.Errorf("%w: shared credential unreadable", ErrSharedMissing)
	}
	return &b, nil
}

func pick(values map[string]string, names []string) map[string]string {
	var out map[string]string
	for _, n := range names {
		k := http.CanonicalHeaderKey(n)
		for vk, v := range values {
			if http.CanonicalHeaderKey(vk) == k && v != "" {
				if out == nil {
					out = map[string]string{}
				}
				out[k] = v
			}
		}
	}
	return out
}

// staticAuthorizer builds the authorizer for a non-OAuth credential.
func (s *Service) staticAuthorizer(server *store.MCPServer, userID string, b *secretBundle, extra map[string]string, shared bool) (Authorizer, error) {
	a := &staticAuthorizer{s: s, serverID: server.ID, userID: userID, shared: shared, headers: map[string]string{}}
	switch server.AuthKind {
	case store.MCPAuthAPIKey:
		if b.APIKey == "" {
			return nil, s.missing(shared)
		}
		cfg := parseAuthConfig(server.AuthConfig).APIKey
		switch {
		case cfg != nil && cfg.Header != "":
			a.headers[http.CanonicalHeaderKey(cfg.Header)] = b.APIKey
		case cfg != nil && cfg.Query != "":
			a.queryName, a.queryValue = cfg.Query, b.APIKey
		default:
			a.headers[DefaultAPIKeyHeader] = b.APIKey
		}
	case store.MCPAuthBearer:
		if b.Bearer == "" {
			return nil, s.missing(shared)
		}
		a.headers["Authorization"] = "Bearer " + b.Bearer
	case store.MCPAuthHeaders:
		if len(b.Headers) == 0 {
			return nil, s.missing(shared)
		}
		for k, v := range b.Headers {
			a.headers[http.CanonicalHeaderKey(k)] = v
		}
	}
	for k, v := range extra {
		if _, taken := a.headers[k]; !taken {
			a.headers[k] = v
		}
	}
	return a, nil
}

func (s *Service) missing(shared bool) error {
	if shared {
		return fmt.Errorf("%w: shared credential incomplete", ErrSharedMissing)
	}
	return ErrNeedsReconnect
}

type noAuth struct{}

func (noAuth) Authorize(context.Context, *http.Request) error { return nil }
func (noAuth) Unauthorized(context.Context) error {
	return fmt.Errorf("%w: the server now requires authentication", ErrNowRequiresAuth)
}

// staticAuthorizer adds fixed headers (and optionally a query parameter).
type staticAuthorizer struct {
	s                     *Service
	serverID, userID      string
	shared                bool
	headers               map[string]string
	queryName, queryValue string
}

func (a *staticAuthorizer) Authorize(_ context.Context, req *http.Request) error {
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}
	if a.queryName != "" {
		q := req.URL.Query()
		q.Set(a.queryName, a.queryValue)
		req.URL.RawQuery = q.Encode()
	}
	return nil
}

func (a *staticAuthorizer) Unauthorized(ctx context.Context) error {
	if a.shared {
		a.s.log.Warn("shared credential rejected", "event", "federation.auth_shared_rejected", "server_id", a.serverID)
		return ErrSharedCredentialRejected
	}
	a.s.markNeedsReconnect(ctx, a.serverID, a.userID, "rejected")
	return ErrNeedsReconnect
}

// oauthAuthorizer adds the user's OAuth access token, refreshing it when
// it is about to expire. One instance serves one (user, server) for a
// while (a session); it caches the token in memory and serialises its own
// refreshes; the database lock serialises them across instances.
type oauthAuthorizer struct {
	s       *Service
	server  *store.MCPServer
	userID  string
	extra   map[string]string
	mu      sync.Mutex
	tok     *tokenBundle
	retried bool
}

func (a *oauthAuthorizer) Authorize(ctx context.Context, req *http.Request) error {
	a.mu.Lock()
	tok := a.tok
	if !tok.fresh(a.s.clock(), a.s.skew) {
		nt, err := a.s.userToken(ctx, a.server, a.userID, "")
		if err != nil {
			a.mu.Unlock()
			return err
		}
		a.tok, tok = nt, nt
	}
	a.mu.Unlock()
	for k, v := range a.extra {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	return nil
}

func (a *oauthAuthorizer) Unauthorized(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.retried {
		a.s.markNeedsReconnect(ctx, a.server.ID, a.userID, "rejected_after_refresh")
		return ErrNeedsReconnect
	}
	a.retried = true
	nt, err := a.s.userToken(ctx, a.server, a.userID, a.tok.AccessToken)
	if err != nil {
		return err
	}
	a.tok = nt
	return nil
}

// Reauth runs call; when it fails with an upstream HTTP 401 and az is an
// Authorizer, it lets az react (one refresh) and runs call once more; a
// second 401 makes az give up (needs_reconnect). Other errors are returned
// as they are.
func Reauth(ctx context.Context, az client.Authorizer, call func() error) error {
	err := call()
	a, ok := az.(Authorizer)
	if !ok || !unauthorized(err) {
		return err
	}
	if uerr := a.Unauthorized(ctx); uerr != nil {
		return uerr
	}
	err = call()
	if !unauthorized(err) {
		return err
	}
	if uerr := a.Unauthorized(ctx); uerr != nil {
		return uerr
	}
	return err
}

func unauthorized(err error) bool {
	var ce *client.Error
	return errors.As(err, &ce) && ce.Class == client.ClassAuthRequired && ce.Status == http.StatusUnauthorized
}
