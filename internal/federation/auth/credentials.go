package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/huynle/mcp-gateway/internal/store"
)

// ErrForbidden means the actor is neither the server's owner nor an admin.
var ErrForbidden = errors.New("auth: only the server's owner or an admin may change its credentials")

// maxSecretValue bounds a credential value.
const maxSecretValue = 8 << 10

// Actor is who changes a server's shared settings. Admin must only be set
// by a caller that checked the user is an admin: it switches to the bypass
// scope. Otherwise row-level security and an owner check apply.
type Actor struct {
	UserID string
	Admin  bool
}

// Credential is a non-OAuth credential: the field of the server's auth
// kind (APIKey for api_key, Bearer for bearer, Headers for headers), and
// optionally Headers holding values of per-user headers.
type Credential struct {
	APIKey  string
	Bearer  string
	Headers map[string]string
}

// SetSharedCredential stores the server's shared credential (credential
// mode shared), sealed to the server and auth kind. Owner or admin only.
// It is never shown again; SecretKeys records only what it holds.
func (s *Service) SetSharedCredential(ctx context.Context, actor Actor, serverID string, c Credential) error {
	return s.asActor(ctx, actor, serverID, func(tx Tx, server *store.MCPServer) error {
		if err := validateCredential(server.AuthKind, c, nil); err != nil {
			return err
		}
		b := secretBundle{APIKey: c.APIKey, Bearer: c.Bearer, Headers: canonicalHeaders(c.Headers)}
		enc, err := s.seal(ctx, aadShared(server), b)
		if err != nil {
			return err
		}
		if err := tx.SetSharedSecret(ctx, &store.MCPServerSharedSecret{ServerID: server.ID, Secret: enc, SecretKeys: secretKeys(b)}); err != nil {
			return fmt.Errorf("auth: store shared credential: %w", err)
		}
		s.log.Info("shared credential set", "event", "federation.auth_shared_set", "server_id", server.ID, "actor_id", actor.UserID, "admin", actor.Admin, "kind", server.AuthKind)
		return nil
	})
}

// SetUserCredential stores userID's own credential for a server they can
// see: their key, token or headers when the server is per_user with a
// non-OAuth kind; otherwise only values for the server's declared per-user
// headers (kept next to an OAuth token, if any). Setting it marks the
// connection active again.
func (s *Service) SetUserCredential(ctx context.Context, userID, serverID string, c Credential) error {
	if userID == "" {
		return store.ErrNotFound
	}
	return s.store.AsUser(ctx, userID, func(tx Tx) error {
		server, err := tx.GetServer(ctx, serverID)
		if err != nil {
			return err
		}
		perUser := parseHeaderConfig(server.HeaderConfig).PerUser
		ownCredential := server.CredentialMode == store.MCPCredentialPerUser &&
			slices.Contains([]string{store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders}, server.AuthKind)
		if ownCredential {
			if err := validateCredential(server.AuthKind, c, perUser); err != nil {
				return err
			}
		} else if err := validateCredential("", c, perUser); err != nil {
			return err
		}
		conn := &store.MCPUserConnection{ServerID: server.ID, UserID: userID, Status: store.MCPConnectionActive}
		b := &secretBundle{}
		if prev, err := tx.GetUserConnection(ctx, server.ID, userID); err == nil {
			if old, err := s.openUserBundle(ctx, server, prev); err == nil && old.OAuth != nil {
				// Keep the OAuth connection (and its status) untouched.
				b.OAuth = old.OAuth
				conn.Status, conn.Scopes, conn.ExpiresAt = prev.Status, prev.Scopes, prev.ExpiresAt
			}
		}
		b.APIKey, b.Bearer, b.Headers = c.APIKey, c.Bearer, canonicalHeaders(c.Headers)
		if conn.Secret, err = s.seal(ctx, aadUserConnection(userID, server), b); err != nil {
			return err
		}
		if err := tx.UpsertUserConnection(ctx, conn); err != nil {
			return fmt.Errorf("auth: store credential: %w", err)
		}
		s.log.Info("user credential set", "event", "federation.auth_user_credential_set", "user_id", userID, "server_id", server.ID, "kind", server.AuthKind)
		return nil
	})
}

// SetStaticClient stores an OAuth client registered by hand at the
// server's authorization server (owner or admin). It takes precedence over
// CIMD and DCR. issuer, when set, pins the client to that AS. The secret
// may be empty (public client).
func (s *Service) SetStaticClient(ctx context.Context, actor Actor, serverID, clientID, clientSecret, issuer string) error {
	if clientID == "" || hasCTL(clientID) || len(clientID) > maxSecretValue || hasCTL(clientSecret) || len(clientSecret) > maxSecretValue {
		return fmt.Errorf("%w: client ID or secret", ErrInvalidCredential)
	}
	if issuer != "" && !absHTTPURL(issuer) {
		return fmt.Errorf("%w: issuer must be an absolute URL", ErrInvalidCredential)
	}
	return s.asActor(ctx, actor, serverID, func(tx Tx, server *store.MCPServer) error {
		row := &store.MCPOAuthClient{ServerID: server.ID, Method: store.MCPOAuthClientStatic, ClientID: clientID, Issuer: issuer}
		if clientSecret != "" {
			enc, err := s.seal(ctx, aadOAuthClient(server, store.MCPOAuthClientStatic), clientSecret)
			if err != nil {
				return err
			}
			row.ClientSecret = &enc
		}
		if err := tx.UpsertOAuthClient(ctx, row); err != nil {
			return fmt.Errorf("auth: store static client: %w", err)
		}
		s.log.Info("static oauth client set", "event", "federation.auth_static_client_set", "server_id", server.ID, "actor_id", actor.UserID, "admin", actor.Admin)
		return nil
	})
}

// Disconnect deletes userID's connection to serverID (tokens or key).
// Tokens are not revoked at the authorization server.
func (s *Service) Disconnect(ctx context.Context, userID, serverID string) error {
	err := s.store.AsUser(ctx, userID, func(tx Tx) error {
		_, err := tx.DeleteUserConnection(ctx, serverID, userID)
		return err
	})
	if err != nil {
		return fmt.Errorf("auth: disconnect: %w", err)
	}
	s.log.Info("disconnected", "event", "federation.auth_disconnected", "user_id", userID, "server_id", serverID)
	return nil
}

// asActor runs fn on the server as the actor: admins through the bypass
// scope, everyone else as themselves and only on their own servers.
func (s *Service) asActor(ctx context.Context, actor Actor, serverID string, fn func(Tx, *store.MCPServer) error) error {
	if actor.UserID == "" && !actor.Admin {
		return ErrForbidden
	}
	run := func(tx Tx) error {
		server, err := tx.GetServer(ctx, serverID)
		if err != nil {
			return err
		}
		if !actor.Admin && server.OwnerUserID != actor.UserID {
			return ErrForbidden
		}
		return fn(tx, server)
	}
	if actor.Admin {
		return s.store.Bypass(ctx, run)
	}
	return s.store.AsUser(ctx, actor.UserID, run)
}

// validateCredential checks c for auth kind (kind "" = only per-user
// header values allowed). Header names in perUser are always allowed as
// extra headers; for kind headers every valid name is.
func validateCredential(kind string, c Credential, perUser []string) error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrInvalidCredential, what) }
	for _, v := range []string{c.APIKey, c.Bearer} {
		if hasCTL(v) || len(v) > maxSecretValue {
			return bad("value contains control characters or is too long")
		}
	}
	switch kind {
	case store.MCPAuthAPIKey:
		if c.APIKey == "" || c.Bearer != "" {
			return bad("an API key is required")
		}
	case store.MCPAuthBearer:
		if c.Bearer == "" || c.APIKey != "" {
			return bad("a bearer token is required")
		}
	case store.MCPAuthHeaders:
		if len(c.Headers) == 0 || c.APIKey != "" || c.Bearer != "" {
			return bad("at least one header is required")
		}
	case "":
		if c.APIKey != "" || c.Bearer != "" || len(c.Headers) == 0 {
			return bad("only values for the server's per-user headers can be set")
		}
	default:
		return fmt.Errorf("%w: auth kind %q takes no stored credential", ErrUnsupported, kind)
	}
	for name, v := range c.Headers {
		if !validHeaderName(name) {
			return bad("invalid or reserved header name")
		}
		if v == "" || hasCTL(v) || len(v) > maxSecretValue {
			return bad("invalid header value")
		}
		if kind != store.MCPAuthHeaders && !slices.ContainsFunc(perUser, func(p string) bool {
			return http.CanonicalHeaderKey(p) == http.CanonicalHeaderKey(name)
		}) {
			return bad("header is not a declared per-user header")
		}
	}
	return nil
}

// reservedCredentialHeaders are set by the transport or the MCP SDK.
var reservedCredentialHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Content-Type": true, "Accept": true, "Connection": true,
	"Transfer-Encoding": true, "Te": true, "Trailer": true, "Upgrade": true, "Keep-Alive": true,
	"Last-Event-Id": true, "Cache-Control": true, "Accept-Encoding": true,
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return false
		}
	}
	k := http.CanonicalHeaderKey(name)
	return !reservedCredentialHeaders[k] && !strings.HasPrefix(k, "Mcp-") && !strings.HasPrefix(k, "Proxy-")
}

func hasCTL(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func canonicalHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}

// secretKeys names what a bundle holds, without values.
func secretKeys(b secretBundle) []string {
	var out []string
	if b.APIKey != "" {
		out = append(out, "api_key")
	}
	if b.Bearer != "" {
		out = append(out, "bearer")
	}
	for k := range b.Headers {
		out = append(out, "header:"+k)
	}
	sort.Strings(out)
	return out
}
