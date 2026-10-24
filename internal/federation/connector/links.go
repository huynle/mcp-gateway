package connector

import (
	"strings"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Portal paths of a server (relative; prefix GATEWAY_BASE_URL for links).
// They live here, not in the servers portal (internal/federation/portal,
// which imports this package), so the connector's credential-link errors,
// the portal and the gateway.* management tools build the same links
// without an import cycle. The portal and gatewaytools delegate.

// ServerPath is the server page.
func ServerPath(id string) string { return "/servers/" + id }

// ConnectionPath is the "My connection" section of the server page, where
// a user enters their API key, bearer token or header values.
func ConnectionPath(id string) string { return ServerPath(id) + "#connection" }

// ConnectPath starts (or restarts) the upstream OAuth sign-in.
func ConnectPath(id string) string { return ServerPath(id) + "/connect" }

// ReviewPath is the tool review page.
func ReviewPath(id string) string { return ServerPath(id) + "/review" }

// EditPath is the owner's settings page (shared credential, static
// OAuth client).
func EditPath(id string) string { return ServerPath(id) + "/edit" }

// ConnectPathOf is where the caller connects to s: the OAuth sign-in for a
// per-user OAuth server, the credential form on the server page otherwise.
func ConnectPathOf(s *store.MCPServer) string {
	if s.CredentialMode == store.MCPCredentialPerUser && s.AuthKind == store.MCPAuthOAuth {
		return ConnectPath(s.ID)
	}
	return ConnectionPath(s.ID)
}

// ConnectLink is ConnectPathOf as an absolute link under base (the
// gateway's public base URL; a trailing slash is ignored).
func ConnectLink(base string, s *store.MCPServer) string {
	return strings.TrimRight(base, "/") + ConnectPathOf(s)
}

// EditLink is EditPath as an absolute link under base.
func EditLink(base, id string) string {
	return strings.TrimRight(base, "/") + EditPath(id)
}
