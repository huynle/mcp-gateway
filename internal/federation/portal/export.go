package portal

import (
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The helpers below are shared with the gateway.* MCP management tools
// (internal/federation/gatewaytools, Brain task 99b5yzdb), so the tools
// and the pages word failures, connection states and settings the same
// way.

// DetectMessage is the class-level text of an auth detection failure
// (never upstream text), as the add form shows it.
func DetectMessage(err error) string { return detectMessage(err) }

// UpstreamMessage is the user-facing text of a federation client error
// class.
var UpstreamMessage = upstreamMessage

// ConnectionState is the caller's connection to s as the pages label it
// ("connected", "needs connect", "needs reconnect", "shared credential",
// "no connection needed") and whether s takes a credential from each user.
func ConnectionState(s *store.MCPServer, conn *store.MCPUserConnection) (label string, needed bool) {
	c := connectionState(s, conn)
	return c.Label, c.Needed
}

// SecretKind reports whether an auth kind is a static secret (api_key,
// bearer, headers) entered on the portal.
func SecretKind(kind string) bool { return secretKind(kind) }

// ValidHeaderName reports whether name may be configured as a header:
// an HTTP token that the transport or the MCP SDK does not own.
func ValidHeaderName(name string) bool { return validHeaderName(name) }

// ValidQueryName reports whether name may carry an API key as a query
// parameter.
func ValidQueryName(name string) bool { return queryNameRE.MatchString(name) }

// AbsHTTPSURL reports whether raw is an absolute https URL without user
// info, fragment or control characters (the add form's rule).
func AbsHTTPSURL(raw string) bool { return absHTTPSURL(raw) }

// Portal paths of a server (relative; prefix GATEWAY_BASE_URL for links).
// They live in the connector (connector/links.go), which builds the same
// links for its credential errors and cannot import this package.

// ServerPath is the server page.
func ServerPath(id string) string { return connector.ServerPath(id) }

// ConnectionPath is the "My connection" section of the server page, where
// a user enters their API key, bearer token or header values.
func ConnectionPath(id string) string { return connector.ConnectionPath(id) }

// ConnectPath starts (or restarts) the upstream OAuth sign-in.
func ConnectPath(id string) string { return connector.ConnectPath(id) }

// ReviewPath is the tool review page.
func ReviewPath(id string) string { return connector.ReviewPath(id) }

// EditPath is the owner's settings page (shared credential, static
// OAuth client).
func EditPath(id string) string { return connector.EditPath(id) }
