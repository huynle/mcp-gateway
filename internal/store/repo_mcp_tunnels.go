package store

import (
	"context"
	"fmt"
	"time"
)

// MCP tunnels (migration 00014) are their owner's rows. The tunnel endpoint
// authenticates a connecting tunnel client by token hash before any user is
// known, so GetMCPTunnelByTokenHash and TouchMCPTunnel run through
// WithJobs; the portal manages tunnels under WithUser.

const mcpTunnelColumns = `id, owner_user_id, name, token_hash, created_at, last_seen_at, revoked_at`

func scanMCPTunnel(row interface{ Scan(dest ...any) error }, t *MCPTunnel) error {
	return row.Scan(&t.ID, &t.OwnerUserID, &t.Name, &t.TokenHash, &t.CreatedAt, &t.LastSeenAt, &t.RevokedAt)
}

// CreateMCPTunnel stores a tunnel; the stored row is written back into t.
func CreateMCPTunnel(ctx context.Context, q Querier, t *MCPTunnel) error {
	err := scanMCPTunnel(q.QueryRow(ctx, `
		INSERT INTO mcp_tunnels (owner_user_id, name, token_hash) VALUES ($1, $2, $3)
		RETURNING `+mcpTunnelColumns, t.OwnerUserID, t.Name, t.TokenHash), t)
	if err != nil {
		return fmt.Errorf("store: create mcp tunnel: %w", err)
	}
	return nil
}

// GetMCPTunnel returns a tunnel by ID, revoked or not.
func GetMCPTunnel(ctx context.Context, q Querier, id string) (*MCPTunnel, error) {
	var t MCPTunnel
	if err := scanMCPTunnel(q.QueryRow(ctx, `SELECT `+mcpTunnelColumns+` FROM mcp_tunnels WHERE id = $1`, id), &t); err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}

// GetMCPTunnelByTokenHash returns the tunnel whose token hashes to hash,
// revoked or not (the caller refuses revoked ones). A tunnel whose owner
// is not active (pending approval or disabled) is ErrNotFound: it must
// not connect (fail closed; schema 27).
func GetMCPTunnelByTokenHash(ctx context.Context, q Querier, hash []byte) (*MCPTunnel, error) {
	var t MCPTunnel
	if err := scanMCPTunnel(q.QueryRow(ctx, `SELECT `+mcpTunnelColumns+` FROM mcp_tunnels
		WHERE token_hash = $1 AND EXISTS (SELECT 1 FROM users u WHERE u.id = owner_user_id AND u.status = 'active')`, hash), &t); err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}

// ListMCPTunnels returns ownerID's tunnels, newest first.
func ListMCPTunnels(ctx context.Context, q Querier, ownerID string) ([]MCPTunnel, error) {
	rows, err := q.Query(ctx, `SELECT `+mcpTunnelColumns+` FROM mcp_tunnels WHERE owner_user_id = $1
		ORDER BY created_at DESC, id`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("store: list mcp tunnels: %w", err)
	}
	defer rows.Close()
	var out []MCPTunnel
	for rows.Next() {
		var t MCPTunnel
		if err := scanMCPTunnel(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeMCPTunnel revokes a live tunnel; ErrNotFound when it does not
// exist, is not the caller's, or is already revoked.
func RevokeMCPTunnel(ctx context.Context, q Querier, id string, at time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE mcp_tunnels SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, at)
	if err != nil {
		return fmt.Errorf("store: revoke mcp tunnel: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchMCPTunnel records that the tunnel client was seen at the given time.
func TouchMCPTunnel(ctx context.Context, q Querier, id string, at time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE mcp_tunnels SET last_seen_at = $2 WHERE id = $1`, id, at)
	if err != nil {
		return fmt.Errorf("store: touch mcp tunnel: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
