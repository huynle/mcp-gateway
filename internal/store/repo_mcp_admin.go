package store

import (
	"context"
	"fmt"
	"time"
)

// Admin listings of user-added MCP servers and tunnels over the secret-free
// views admin_mcp_servers and admin_mcp_tunnels (migration 00014). The
// views are security_invoker: run these under WithJobs to see every row
// (under WithUser they show only what row-level security lets the user
// see).

// AdminMCPServer is one row of admin_mcp_servers plus the owner's display
// name and the newest / approved snapshot versions (0 when none).
type AdminMCPServer struct {
	MCPServer
	OwnerDisplayName        string
	HasSharedCredential     bool
	PublishedRoleIDs        []string
	UserConnectionCount     int64
	LatestSnapshotVersion   int
	ApprovedSnapshotVersion int
}

// AdminMCPTunnel is one row of admin_mcp_tunnels (no token hash) plus the
// owner's display name.
type AdminMCPTunnel struct {
	ID               string
	OwnerUserID      string
	OwnerDisplayName string
	Name             string
	CreatedAt        time.Time
	LastSeenAt       *time.Time
	RevokedAt        *time.Time
}

const adminMCPServerSelect = `
	SELECT v.id, v.name, v.url, v.transport, v.owner_user_id, v.audience, v.credential_mode, v.auth_kind,
		v.auth_config, v.header_config, v.status, v.last_error_class, v.created_at, v.updated_at,
		coalesce(u.display_name, ''), v.has_shared_credential, v.published_role_ids::text[], v.user_connection_count,
		coalesce((SELECT max(sn.version) FROM mcp_server_snapshots sn WHERE sn.server_id = v.id), 0),
		coalesce((SELECT sn.version FROM mcp_server_snapshots sn WHERE sn.server_id = v.id AND sn.status = 'approved'), 0),
		v.elicitation_origins
	FROM admin_mcp_servers v LEFT JOIN users u ON u.id = v.owner_user_id`

func scanAdminMCPServer(row interface{ Scan(dest ...any) error }, s *AdminMCPServer) error {
	return row.Scan(&s.ID, &s.Name, &s.URL, &s.Transport, &s.OwnerUserID, &s.Audience, &s.CredentialMode, &s.AuthKind,
		&s.AuthConfig, &s.HeaderConfig, &s.Status, &s.LastErrorClass, &s.CreatedAt, &s.UpdatedAt,
		&s.OwnerDisplayName, &s.HasSharedCredential, &s.PublishedRoleIDs, &s.UserConnectionCount,
		&s.LatestSnapshotVersion, &s.ApprovedSnapshotVersion, &s.ElicitationOrigins)
}

// ListAdminMCPServers returns every server by name (WithJobs).
func ListAdminMCPServers(ctx context.Context, q Querier) ([]AdminMCPServer, error) {
	rows, err := q.Query(ctx, adminMCPServerSelect+` ORDER BY v.name`)
	if err != nil {
		return nil, fmt.Errorf("store: list admin mcp servers: %w", err)
	}
	defer rows.Close()
	var out []AdminMCPServer
	for rows.Next() {
		var s AdminMCPServer
		if err := scanAdminMCPServer(rows, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetAdminMCPServer returns one server of the admin view (ErrNotFound).
func GetAdminMCPServer(ctx context.Context, q Querier, id string) (*AdminMCPServer, error) {
	var s AdminMCPServer
	if err := scanAdminMCPServer(q.QueryRow(ctx, adminMCPServerSelect+` WHERE v.id = $1`, id), &s); err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

const adminMCPTunnelSelect = `
	SELECT t.id, t.owner_user_id, coalesce(u.display_name, ''), t.name, t.created_at, t.last_seen_at, t.revoked_at
	FROM admin_mcp_tunnels t LEFT JOIN users u ON u.id = t.owner_user_id`

func scanAdminMCPTunnel(row interface{ Scan(dest ...any) error }, t *AdminMCPTunnel) error {
	return row.Scan(&t.ID, &t.OwnerUserID, &t.OwnerDisplayName, &t.Name, &t.CreatedAt, &t.LastSeenAt, &t.RevokedAt)
}

// ListAdminMCPTunnels returns every tunnel, live ones first, newest first
// (WithJobs).
func ListAdminMCPTunnels(ctx context.Context, q Querier) ([]AdminMCPTunnel, error) {
	rows, err := q.Query(ctx, adminMCPTunnelSelect+` ORDER BY (t.revoked_at IS NOT NULL), t.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list admin mcp tunnels: %w", err)
	}
	defer rows.Close()
	var out []AdminMCPTunnel
	for rows.Next() {
		var t AdminMCPTunnel
		if err := scanAdminMCPTunnel(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetAdminMCPTunnel returns one tunnel of the admin view (ErrNotFound).
func GetAdminMCPTunnel(ctx context.Context, q Querier, id string) (*AdminMCPTunnel, error) {
	var t AdminMCPTunnel
	if err := scanAdminMCPTunnel(q.QueryRow(ctx, adminMCPTunnelSelect+` WHERE t.id = $1`, id), &t); err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}
