package store

import (
	"context"
	"fmt"
	"time"
)

// Per-user MCP server connections (migration 00014). A connection is its
// user's row only: under WithUser nobody else (not even the server's owner)
// sees it, and a user can only create or update a connection to a server
// they can see. Token refresh workers use WithJobs.

const mcpUserConnectionColumns = `id, server_id, user_id, status, scopes,
	secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext,
	expires_at, last_refreshed_at, created_at, updated_at`

func scanMCPUserConnection(row interface{ Scan(dest ...any) error }, c *MCPUserConnection) error {
	return row.Scan(&c.ID, &c.ServerID, &c.UserID, &c.Status, &c.Scopes,
		&c.Secret.KeyID, &c.Secret.WrappedDataKey, &c.Secret.Nonce, &c.Secret.Ciphertext,
		&c.ExpiresAt, &c.LastRefreshedAt, &c.CreatedAt, &c.UpdatedAt)
}

// UpsertMCPUserConnection inserts the user's connection to a server or, when
// one exists, replaces its status, scopes, secret and expiry. An empty
// Status means active. The stored row is written back into c.
func UpsertMCPUserConnection(ctx context.Context, q Querier, c *MCPUserConnection) error {
	err := scanMCPUserConnection(q.QueryRow(ctx, `
		INSERT INTO mcp_server_user_connections (server_id, user_id, status, scopes,
			secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext, expires_at)
		VALUES ($1, $2, coalesce(nullif($3, ''), 'active'), coalesce($4::text[], '{}'), $5, $6, $7, $8, $9)
		ON CONFLICT (server_id, user_id) DO UPDATE SET
			status = EXCLUDED.status,
			scopes = EXCLUDED.scopes,
			secret_key_id = EXCLUDED.secret_key_id,
			secret_wrapped_key = EXCLUDED.secret_wrapped_key,
			secret_nonce = EXCLUDED.secret_nonce,
			secret_ciphertext = EXCLUDED.secret_ciphertext,
			expires_at = EXCLUDED.expires_at,
			updated_at = now()
		RETURNING `+mcpUserConnectionColumns,
		c.ServerID, c.UserID, c.Status, c.Scopes,
		c.Secret.KeyID, c.Secret.WrappedDataKey, c.Secret.Nonce, c.Secret.Ciphertext, c.ExpiresAt,
	), c)
	if err != nil {
		return fmt.Errorf("store: upsert mcp user connection: %w", err)
	}
	return nil
}

// GetMCPUserConnection returns userID's connection to serverID.
func GetMCPUserConnection(ctx context.Context, q Querier, serverID, userID string) (*MCPUserConnection, error) {
	var c MCPUserConnection
	err := scanMCPUserConnection(q.QueryRow(ctx, `SELECT `+mcpUserConnectionColumns+`
		FROM mcp_server_user_connections WHERE server_id = $1 AND user_id = $2`, serverID, userID), &c)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

// ListMCPUserConnections returns userID's connections, oldest first.
func ListMCPUserConnections(ctx context.Context, q Querier, userID string) ([]MCPUserConnection, error) {
	rows, err := q.Query(ctx, `SELECT `+mcpUserConnectionColumns+`
		FROM mcp_server_user_connections WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list mcp user connections: %w", err)
	}
	defer rows.Close()
	var out []MCPUserConnection
	for rows.Next() {
		var c MCPUserConnection
		if err := scanMCPUserConnection(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetMCPUserConnectionStatus changes a connection's status.
func SetMCPUserConnectionStatus(ctx context.Context, q Querier, serverID, userID, status string) error {
	tag, err := q.Exec(ctx, `UPDATE mcp_server_user_connections SET status = $3, updated_at = now()
		WHERE server_id = $1 AND user_id = $2`, serverID, userID, status)
	if err != nil {
		return fmt.Errorf("store: set mcp user connection status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchMCPUserConnectionRefreshed records a successful token refresh.
func TouchMCPUserConnectionRefreshed(ctx context.Context, q Querier, serverID, userID string, at time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE mcp_server_user_connections SET last_refreshed_at = $3, updated_at = now()
		WHERE server_id = $1 AND user_id = $2`, serverID, userID, at)
	if err != nil {
		return fmt.Errorf("store: touch mcp user connection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteMCPUserConnection removes userID's connection to serverID (secret
// included) and returns how many rows went.
func DeleteMCPUserConnection(ctx context.Context, q Querier, serverID, userID string) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM mcp_server_user_connections WHERE server_id = $1 AND user_id = $2`, serverID, userID)
	if err != nil {
		return 0, fmt.Errorf("store: delete mcp user connection: %w", err)
	}
	return tag.RowsAffected(), nil
}
