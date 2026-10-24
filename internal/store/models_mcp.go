package store

import (
	"encoding/json"
	"time"
)

// Models for user-added MCP servers (migration 00014; Brain plan 0omkv2e1,
// decision yhd5kcaz).

// MCP server transports. A tunnelled server keeps transport auto and has a
// tunnel://<tunnel id> URL.
const (
	MCPTransportAuto           = "auto"
	MCPTransportStreamableHTTP = "streamable_http"
	MCPTransportSSE            = "sse"
)

// MCP server audiences. Servers start private; only an admin publishes.
const (
	MCPAudiencePrivate   = "private"
	MCPAudiencePublished = "published"
)

// MCP server credential modes.
const (
	MCPCredentialPerUser = "per_user"
	MCPCredentialShared  = "shared"
)

// MCP server auth kinds.
const (
	MCPAuthOAuth   = "oauth"
	MCPAuthAPIKey  = "api_key"
	MCPAuthBearer  = "bearer"
	MCPAuthHeaders = "headers"
	MCPAuthNone    = "none"
	MCPAuthAuto    = "auto"
)

// MCP server statuses.
const (
	MCPServerActive   = "active"
	MCPServerDisabled = "disabled"
	MCPServerError    = "error"
)

// MCP per-user connection statuses (same vocabulary as v1 connections).
const (
	MCPConnectionActive         = ConnectionActive
	MCPConnectionNeedsReconnect = ConnectionNeedsReconnect
	MCPConnectionRevoked        = ConnectionRevoked
)

// MCP OAuth client registration methods.
const (
	MCPOAuthClientDCR    = "dcr"
	MCPOAuthClientCIMD   = "cimd"
	MCPOAuthClientStatic = "static"
)

// MCP snapshot statuses.
const (
	MCPSnapshotPending    = "pending"
	MCPSnapshotApproved   = "approved"
	MCPSnapshotSuperseded = "superseded"
)

// MCPServer is a user-added upstream MCP server. Name is the tool prefix
// (<name>.<tool>): lowercase [a-z0-9_-], 1-63 characters, unique. AuthConfig
// and HeaderConfig hold only non-secret settings (header and query parameter
// names, OAuth metadata cache, scopes, static non-secret headers, names of
// per-user headers); secrets live in MCPServerSharedSecret,
// MCPUserConnection and MCPOAuthClient. LastErrorClass is a class-level
// error, never upstream text.
type MCPServer struct {
	ID                   string
	Name                 string
	URL                  string
	Transport            string
	OwnerUserID          string
	Audience             string
	CredentialMode       string
	AuthKind             string
	AuthConfig           json.RawMessage
	HeaderConfig         json.RawMessage
	Status               string
	LastErrorClass       *string
	CreatedAt, UpdatedAt time.Time
	// ElicitationOrigins are the exact https://host[:port] origins, besides
	// the server's own registrable domain, its URL elicitations may point
	// to (migration 00032; never nil when read). Written only by
	// SetMCPServerElicitationOrigins: CreateMCPServer and UpdateMCPServer
	// ignore it.
	ElicitationOrigins []string
}

// MCPServerSharedSecret is a server's shared credential (credential mode
// shared), envelope-encrypted. SecretKeys names what the bundle holds
// (header names, query parameter) without the values. OwnerUserID mirrors
// the server's owner and is filled in by the store.
type MCPServerSharedSecret struct {
	ServerID    string
	OwnerUserID string
	Secret      Encrypted
	SecretKeys  []string
	UpdatedAt   time.Time
}

// MCPUserConnection is one user's credential for one server: an OAuth
// token bundle or a personal API key, envelope-encrypted.
type MCPUserConnection struct {
	ID                   string
	ServerID             string
	UserID               string
	Status               string
	Scopes               []string
	Secret               Encrypted
	ExpiresAt            *time.Time
	LastRefreshedAt      *time.Time
	CreatedAt, UpdatedAt time.Time
}

// MCPOAuthClient is the gateway's OAuth client at a server's authorization
// server. ClientSecret is nil for public clients (CIMD, most DCR).
// OwnerUserID mirrors the server's owner and is filled in by the store.
type MCPOAuthClient struct {
	ServerID     string
	OwnerUserID  string
	Method       string
	ClientID     string
	ClientSecret *Encrypted
	Issuer       string
	RegisteredAt time.Time
}

// MCPSnapshot is one discovered capability set of a server. Version counts
// up per server; at most one snapshot per server is approved. Review holds
// the reviewer's per-tool decisions (enabled, kind override).
type MCPSnapshot struct {
	ID                string
	ServerID          string
	Version           int
	Status            string
	DiscoveredAt      time.Time
	ApprovedBy        *string
	ApprovedAt        *time.Time
	Tools             json.RawMessage
	Resources         json.RawMessage
	ResourceTemplates json.RawMessage
	Prompts           json.RawMessage
	Review            json.RawMessage
}

// MCPTunnel is a user's outbound tunnel registration; only the hash of its
// token is stored.
type MCPTunnel struct {
	ID          string
	OwnerUserID string
	Name        string
	TokenHash   []byte
	CreatedAt   time.Time
	LastSeenAt  *time.Time
	RevokedAt   *time.Time
	// MachineID and ServerName link the tunnel to an enrolled machine's
	// server (schema 30); such a tunnel has no TokenHash. Both "" for a
	// legacy tunnel.
	MachineID  string
	ServerName string
}

// NetguardAllowHost is an admin SSRF allow-list entry: a host name pattern
// or a CIDR that server URLs may resolve to despite the private-address
// block.
type NetguardAllowHost struct {
	ID        string
	Pattern   string
	Note      string
	CreatedBy *string
	CreatedAt time.Time
}
