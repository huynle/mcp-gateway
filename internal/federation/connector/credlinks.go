package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Credential links (GATEWAY_CREDENTIAL_LINKS_ENABLED, plan 1 of
// docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md):
// a credential problem the caller can fix answers -32042 (URL elicitation
// required) with a link to the portal page that fixes it, instead of the
// -32031 text. The class never changes, so audit rows, the ledger and the
// secrets stage's refund list see what they saw before. Without the flag
// every answer is byte for byte what it was.
//
//   - user-fixable (no_account, auth_required, needs_reconnect,
//     user_header_missing on a server that takes a credential or header
//     values from each user): the connection link (OAuth sign-in or the
//     "My connection" section), for whoever calls;
//   - owner-only (server_not_configured, shared_credential_rejected, and
//     the user-fixable classes on a server users cannot fix): the edit
//     link, for the server's owner only; everyone else gets today's
//     answer, so nobody else learns the edit page or the cause;
//   - anything else (credentials_unavailable, upstream failures): as is.

// ClassUserHeaderMissing is the class of a call refused because a
// per-user header the server declares has no value for the caller
// (auth.ErrUserHeaderMissing; only with credential links).
const ClassUserHeaderMissing = "user_header_missing"

// errTunnelURL is the cause credentialLink is given for endpoint()
// failures: of those, only the invalid tunnel URL (server_not_configured)
// is a credential-link case.
var errTunnelURL = errors.New("connector: the server's tunnel URL is invalid")

// userFixableClasses are answered with the connection link.
var userFixableClasses = []string{"no_account", "auth_required", "needs_reconnect", ClassUserHeaderMissing}

// ownerClasses are answered with the edit link, to the owner only.
var ownerClasses = []string{"server_not_configured", "shared_credential_rejected"}

// credentialLink returns answer (the error the gateway gives without
// credential links) or, with the flag on, its -32042 form for user (see
// above). cause is the error answer was mapped from; it picks the owner's
// message.
func (m *Manager) credentialLink(user string, server *store.MCPServer, cause, answer error) error {
	var te *mcp.ToolError
	if !m.o.CredentialLinks || server == nil || !errors.As(answer, &te) {
		return answer
	}
	class := te.Class()
	switch {
	case slices.Contains(userFixableClasses, class) && needsUserCredential(server):
		return m.userLink(user, server, class)
	case slices.Contains(userFixableClasses, class), slices.Contains(ownerClasses, class):
		if user != "" && user == server.OwnerUserID {
			return m.ownerLink(user, server, class, ownerReason(class, cause))
		}
	}
	return answer
}

// userLink is the -32042 answer pointing user at their connection.
func (m *Manager) userLink(user string, server *store.MCPServer, class string) error {
	url := ConnectLink(m.o.BaseURL, server)
	text := "connect your account at " + url
	switch class {
	case "needs_reconnect":
		text = "your connection has expired or was rejected; reconnect it at " + url
	case ClassUserHeaderMissing:
		url = m.link(ConnectionPath(server.ID))
		text = "set your values for the server's per-user headers at " + url
	}
	return m.elicitation(user, server, class, url, server.Name+": "+text+", then retry", "Connect "+server.Name)
}

// ownerLink is the -32042 answer pointing the server's owner at its
// settings.
func (m *Manager) ownerLink(user string, server *store.MCPServer, class, reason string) error {
	url := EditLink(m.o.BaseURL, server.ID)
	return m.elicitation(user, server, class, url,
		server.Name+": "+reason+"; as the server's owner, fix it at "+url+", then retry", "Set up "+server.Name)
}

func (m *Manager) elicitation(user string, server *store.MCPServer, class, url, message, label string) error {
	return mcp.NewURLElicitationRequired(class, message,
		[]mcp.URLElicitation{{ElicitationID: credentialElicitationID(user, server.ID, class), URL: url, Message: label}},
		map[string]any{"server": server.Name})
}

// link is path as an absolute link under BaseURL.
func (m *Manager) link(path string) string {
	return strings.TrimRight(m.o.BaseURL, "/") + path
}

// ownerReason says what is wrong, for the owner (never upstream text).
func ownerReason(class string, cause error) string {
	switch {
	case class == "shared_credential_rejected":
		return "the server rejected the shared credential"
	case errors.Is(cause, errTunnelURL):
		return "the server's tunnel URL is invalid"
	case errors.Is(cause, auth.ErrSharedMissing):
		return "the shared credential is missing or incomplete"
	case errors.Is(cause, auth.ErrNowRequiresAuth):
		return "the server now requires authentication"
	case errors.Is(cause, auth.ErrModeInvalid), errors.Is(cause, auth.ErrUnsupported):
		return "the server's authentication setup is not valid"
	case class == "server_not_configured":
		return "the server's authentication is not set up"
	}
	return "the server asked for authentication"
}

// credentialElicitationID is stable for (user, server, class), so a harness can
// tell a repeated answer from a new one, and differs across users. It is
// a hash: neither ID appears in it.
func credentialElicitationID(user, serverID, class string) string {
	sum := sha256.Sum256([]byte("credential-link\x00" + user + "\x00" + serverID + "\x00" + class))
	return "gwc_" + hex.EncodeToString(sum[:16])
}

// needsUserCredential is NeedsUserCredential.
func needsUserCredential(s *store.MCPServer) bool { return NeedsUserCredential(s) }

// NeedsUserCredential: every user brings their own credential (per-user
// mode with an auth kind other than none) or values for per-user headers.
// Credential links, the elicitation relay and the servers portal
// (internal/federation/portal) all use this rule.
func NeedsUserCredential(s *store.MCPServer) bool {
	if len(perUserHeaders(s.HeaderConfig)) > 0 {
		return true
	}
	return s.CredentialMode == store.MCPCredentialPerUser && slices.Contains(
		[]string{store.MCPAuthOAuth, store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders}, s.AuthKind)
}

// perUserHeaders reads header_config.per_user.
func perUserHeaders(raw json.RawMessage) []string {
	var hc struct {
		PerUser []string `json:"per_user"`
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &hc)
	}
	return hc.PerUser
}

// MissingAccount implements mcp.MissingAccounter for the account stage:
// with credential links, a per-user server (auth kind other than none)
// the caller may use but has no connection to answers no_account as a
// -32042 with the connection link. Built-in apps go to the fallback's
// hook, if it has one; servers the caller cannot see get nil (today's
// no_account, nothing revealed).
func (a accounts) MissingAccount(ctx context.Context, userID, app string) error {
	if !a.m.o.Registry.IsServerApp(app) {
		if ma, ok := a.fallback.(mcp.MissingAccounter); ok {
			return ma.MissingAccount(ctx, userID, app)
		}
		return nil
	}
	if !a.m.o.CredentialLinks {
		return nil
	}
	e, ok := a.m.entry(app)
	if !ok || !a.m.canSee(ctx, userID, e.server.ID) {
		return nil
	}
	s := e.server
	if s.CredentialMode != store.MCPCredentialPerUser || s.AuthKind == store.MCPAuthNone {
		return nil
	}
	return a.m.userLink(userID, &s, "no_account")
}

var _ mcp.MissingAccounter = accounts{}
