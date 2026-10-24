package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// Repository functions for user-added MCP servers, their publishing and
// their server-level credentials (migration 00014). Like the connections
// module's lookups they take a Querier and run under whichever scope the
// caller opened:
//
//   - WithUser: a user creates, reads, changes and deletes their own servers
//     and reads the servers published to a role they hold; row-level
//     security hides everything else (Get returns ErrNotFound, Update and
//     Delete return ErrNotFound for rows the user may not change);
//   - WithJobs: admin listings, publishing (PublishMCPServer and
//     UnpublishMCPServer fail with permission denied under WithUser), and
//     the federation connector reading a published server's shared
//     credential on behalf of another user.

// ErrNoRoles is returned by PublishMCPServer without any role.
var ErrNoRoles = errors.New("store: publish needs at least one role")

const mcpServerColumns = `s.id, s.name, s.url, s.transport, s.owner_user_id, s.audience, s.credential_mode, s.auth_kind,
	s.auth_config, s.header_config, s.status, s.last_error_class, s.created_at, s.updated_at, s.elicitation_origins`

func scanMCPServer(row interface{ Scan(dest ...any) error }, s *MCPServer) error {
	return row.Scan(&s.ID, &s.Name, &s.URL, &s.Transport, &s.OwnerUserID, &s.Audience, &s.CredentialMode, &s.AuthKind,
		&s.AuthConfig, &s.HeaderConfig, &s.Status, &s.LastErrorClass, &s.CreatedAt, &s.UpdatedAt, &s.ElicitationOrigins)
}

func queryMCPServers(ctx context.Context, q Querier, op, sql string, args ...any) ([]MCPServer, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: %s: %w", op, err)
	}
	defer rows.Close()
	var out []MCPServer
	for rows.Next() {
		var s MCPServer
		if err := scanMCPServer(rows, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// CreateMCPServer inserts a private server owned by s.OwnerUserID. s.ID may
// be preset (so secrets' AAD can name the server before it exists) or left
// empty; empty Transport, CredentialMode, AuthKind and Status take the
// column defaults (auto, per_user, auto, active). Audience is always
// private: only an admin publishes. The stored row is written back into s.
func CreateMCPServer(ctx context.Context, q Querier, s *MCPServer) error {
	err := scanMCPServer(q.QueryRow(ctx, `
		INSERT INTO mcp_servers AS s (id, name, url, transport, owner_user_id, credential_mode, auth_kind,
			auth_config, header_config, status)
		VALUES (coalesce(nullif($1, '')::uuid, gen_random_uuid()), $2, $3, coalesce(nullif($4, ''), 'auto'), $5,
			coalesce(nullif($6, ''), 'per_user'), coalesce(nullif($7, ''), 'auto'),
			coalesce($8::jsonb, '{}'::jsonb), coalesce($9::jsonb, '{}'::jsonb), coalesce(nullif($10, ''), 'active'))
		RETURNING `+mcpServerColumns,
		s.ID, s.Name, s.URL, s.Transport, s.OwnerUserID, s.CredentialMode, s.AuthKind,
		s.AuthConfig, s.HeaderConfig, s.Status,
	), s)
	if err != nil {
		return fmt.Errorf("store: create mcp server: %w", err)
	}
	return nil
}

// GetMCPServer returns a visible server by ID.
func GetMCPServer(ctx context.Context, q Querier, id string) (*MCPServer, error) {
	var s MCPServer
	if err := scanMCPServer(q.QueryRow(ctx, `SELECT `+mcpServerColumns+` FROM mcp_servers s WHERE s.id = $1`, id), &s); err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

// GetMCPServerByName returns a visible server by its name (tool prefix).
func GetMCPServerByName(ctx context.Context, q Querier, name string) (*MCPServer, error) {
	var s MCPServer
	if err := scanMCPServer(q.QueryRow(ctx, `SELECT `+mcpServerColumns+` FROM mcp_servers s WHERE s.name = $1`, name), &s); err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

// ListMyMCPServers returns the servers userID owns, by name.
func ListMyMCPServers(ctx context.Context, q Querier, userID string) ([]MCPServer, error) {
	return queryMCPServers(ctx, q, "list my mcp servers",
		`SELECT `+mcpServerColumns+` FROM mcp_servers s WHERE s.owner_user_id = $1 ORDER BY s.name`, userID)
}

// ListVisibleMCPServers returns the servers userID may see, by name: their
// own and those published to a role they hold. The predicate repeats the
// row-level security policy so the result is the same under WithJobs.
func ListVisibleMCPServers(ctx context.Context, q Querier, userID string) ([]MCPServer, error) {
	return queryMCPServers(ctx, q, "list visible mcp servers", `
		SELECT `+mcpServerColumns+` FROM mcp_servers s
		WHERE s.owner_user_id = $1
		   OR (s.audience = 'published' AND EXISTS (
			SELECT 1 FROM mcp_server_roles sr JOIN role_assignments ra ON ra.role_id = sr.role_id
			WHERE sr.server_id = s.id AND ra.user_id = $1))
		ORDER BY s.name`, userID)
}

// ListAllMCPServers returns every server by name (admin listing, WithJobs).
func ListAllMCPServers(ctx context.Context, q Querier) ([]MCPServer, error) {
	return queryMCPServers(ctx, q, "list all mcp servers", `SELECT `+mcpServerColumns+` FROM mcp_servers s ORDER BY s.name`)
}

// UpdateMCPServer rewrites a server's editable settings (name, URL,
// transport, credential mode, auth kind, auth and header config). Owner,
// audience, status and elicitation origins
// (SetMCPServerElicitationOrigins) have their own functions. ErrNotFound when the row
// does not exist or the caller may not change it; ErrMCPServerLocked when
// the server is published and the request path (gateway_app) changes its
// address or sign-in settings (migration 00017). On the admin path such a
// change supersedes the server's approved snapshot.
func UpdateMCPServer(ctx context.Context, q Querier, s *MCPServer) error {
	err := q.QueryRow(ctx, `
		UPDATE mcp_servers SET name = $2, url = $3, transport = $4, credential_mode = $5, auth_kind = $6,
			auth_config = coalesce($7::jsonb, '{}'::jsonb), header_config = coalesce($8::jsonb, '{}'::jsonb),
			updated_at = now()
		WHERE id = $1 RETURNING updated_at`,
		s.ID, s.Name, s.URL, s.Transport, s.CredentialMode, s.AuthKind, s.AuthConfig, s.HeaderConfig,
	).Scan(&s.UpdatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == MCPServerLockedCode {
		return ErrMCPServerLocked
	}
	if err != nil {
		return notFound(err)
	}
	return nil
}

// SetMCPServerStatus sets a server's status and last error class (nil
// clears it).
func SetMCPServerStatus(ctx context.Context, q Querier, id, status string, lastErrorClass *string) error {
	tag, err := q.Exec(ctx, `UPDATE mcp_servers SET status = $2, last_error_class = $3, updated_at = now() WHERE id = $1`,
		id, status, lastErrorClass)
	if err != nil {
		return fmt.Errorf("store: set mcp server status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteMCPServer deletes a server; its role links, shared secret, OAuth
// client, every user's connection and its snapshots go with it (foreign key
// cascades, regardless of whose rows they are). Audit events are not
// touched.
func DeleteMCPServer(ctx context.Context, q Querier, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM mcp_servers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete mcp server: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PublishMCPServer publishes a server to the given roles (added to those it
// already has) and marks it published. Admin only: run it through
// WithJobs; gateway_app has no privilege for it.
func PublishMCPServer(ctx context.Context, q Querier, serverID string, roleIDs []string) error {
	if len(roleIDs) == 0 {
		return ErrNoRoles
	}
	tag, err := q.Exec(ctx, `UPDATE mcp_servers SET audience = 'published', updated_at = now() WHERE id = $1`, serverID)
	if err != nil {
		return fmt.Errorf("store: publish mcp server: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = q.Exec(ctx, `
		INSERT INTO mcp_server_roles (server_id, owner_user_id, role_id)
		SELECT s.id, s.owner_user_id, r.id FROM mcp_servers s, unnest($2::uuid[]) AS r(id)
		WHERE s.id = $1
		ON CONFLICT (server_id, role_id) DO NOTHING`, serverID, roleIDs)
	if err != nil {
		return fmt.Errorf("store: publish mcp server roles: %w", err)
	}
	return nil
}

// UnpublishMCPServer removes the given roles from a server (nil removes
// all); a server left without roles becomes private again. Admin only
// (WithJobs).
func UnpublishMCPServer(ctx context.Context, q Querier, serverID string, roleIDs []string) error {
	_, err := q.Exec(ctx, `
		DELETE FROM mcp_server_roles WHERE server_id = $1 AND ($2::uuid[] IS NULL OR role_id = ANY($2::uuid[]))`,
		serverID, roleIDs)
	if err != nil {
		return fmt.Errorf("store: unpublish mcp server roles: %w", err)
	}
	tag, err := q.Exec(ctx, `
		UPDATE mcp_servers s SET updated_at = now(),
			audience = CASE WHEN EXISTS (SELECT 1 FROM mcp_server_roles sr WHERE sr.server_id = s.id)
			                THEN 'published' ELSE 'private' END
		WHERE s.id = $1`, serverID)
	if err != nil {
		return fmt.Errorf("store: unpublish mcp server: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListMCPServerRoles returns the IDs of the roles a server is published to
// that the caller may see (all of them for the owner and WithJobs).
func ListMCPServerRoles(ctx context.Context, q Querier, serverID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT role_id FROM mcp_server_roles WHERE server_id = $1 ORDER BY role_id`, serverID)
	if err != nil {
		return nil, fmt.Errorf("store: list mcp server roles: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetMCPServerSharedSecret inserts or replaces a server's shared
// credential. Owner (WithUser) or admin (WithJobs) only; ErrNotFound when
// the server is not visible, a row-level security violation when it is
// visible but not the caller's.
func SetMCPServerSharedSecret(ctx context.Context, q Querier, s *MCPServerSharedSecret) error {
	err := q.QueryRow(ctx, `
		INSERT INTO mcp_server_shared_secrets (server_id, owner_user_id,
			secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext, secret_keys)
		SELECT s.id, s.owner_user_id, $2, $3, $4, $5, coalesce($6::text[], '{}')
		FROM mcp_servers s WHERE s.id = $1
		ON CONFLICT (server_id) DO UPDATE SET
			secret_key_id = EXCLUDED.secret_key_id,
			secret_wrapped_key = EXCLUDED.secret_wrapped_key,
			secret_nonce = EXCLUDED.secret_nonce,
			secret_ciphertext = EXCLUDED.secret_ciphertext,
			secret_keys = EXCLUDED.secret_keys,
			updated_at = now()
		RETURNING owner_user_id, secret_keys, updated_at`,
		s.ServerID, s.Secret.KeyID, s.Secret.WrappedDataKey, s.Secret.Nonce, s.Secret.Ciphertext, s.SecretKeys,
	).Scan(&s.OwnerUserID, &s.SecretKeys, &s.UpdatedAt)
	if err != nil {
		if e := notFound(err); errors.Is(e, ErrNotFound) {
			return e
		}
		return fmt.Errorf("store: set mcp shared secret: %w", err)
	}
	return nil
}

// GetMCPServerSharedSecret returns a server's shared credential (owner or
// WithJobs).
func GetMCPServerSharedSecret(ctx context.Context, q Querier, serverID string) (*MCPServerSharedSecret, error) {
	var s MCPServerSharedSecret
	err := q.QueryRow(ctx, `
		SELECT server_id, owner_user_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext,
			secret_keys, updated_at
		FROM mcp_server_shared_secrets WHERE server_id = $1`, serverID,
	).Scan(&s.ServerID, &s.OwnerUserID, &s.Secret.KeyID, &s.Secret.WrappedDataKey, &s.Secret.Nonce, &s.Secret.Ciphertext,
		&s.SecretKeys, &s.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

// DeleteMCPServerSharedSecret removes a server's shared credential and
// returns how many rows went.
func DeleteMCPServerSharedSecret(ctx context.Context, q Querier, serverID string) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM mcp_server_shared_secrets WHERE server_id = $1`, serverID)
	if err != nil {
		return 0, fmt.Errorf("store: delete mcp shared secret: %w", err)
	}
	return tag.RowsAffected(), nil
}

// UpsertMCPOAuthClient inserts or replaces the gateway's OAuth client for a
// server (owner or WithJobs; errors as SetMCPServerSharedSecret).
func UpsertMCPOAuthClient(ctx context.Context, q Querier, c *MCPOAuthClient) error {
	var keyID *string
	var wrapped, nonce, ciphertext []byte
	if c.ClientSecret != nil {
		keyID = &c.ClientSecret.KeyID
		wrapped, nonce, ciphertext = c.ClientSecret.WrappedDataKey, c.ClientSecret.Nonce, c.ClientSecret.Ciphertext
	}
	err := q.QueryRow(ctx, `
		INSERT INTO mcp_server_oauth_clients (server_id, owner_user_id, method, client_id,
			secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext, issuer)
		SELECT s.id, s.owner_user_id, $2, $3, $4, $5, $6, $7, $8
		FROM mcp_servers s WHERE s.id = $1
		ON CONFLICT (server_id) DO UPDATE SET
			method = EXCLUDED.method,
			client_id = EXCLUDED.client_id,
			secret_key_id = EXCLUDED.secret_key_id,
			secret_wrapped_key = EXCLUDED.secret_wrapped_key,
			secret_nonce = EXCLUDED.secret_nonce,
			secret_ciphertext = EXCLUDED.secret_ciphertext,
			issuer = EXCLUDED.issuer,
			registered_at = now()
		RETURNING owner_user_id, registered_at`,
		c.ServerID, c.Method, c.ClientID, keyID, wrapped, nonce, ciphertext, c.Issuer,
	).Scan(&c.OwnerUserID, &c.RegisteredAt)
	if err != nil {
		if e := notFound(err); errors.Is(e, ErrNotFound) {
			return e
		}
		return fmt.Errorf("store: upsert mcp oauth client: %w", err)
	}
	return nil
}

// GetMCPOAuthClient returns the gateway's OAuth client for a server (owner
// or WithJobs).
func GetMCPOAuthClient(ctx context.Context, q Querier, serverID string) (*MCPOAuthClient, error) {
	var c MCPOAuthClient
	var keyID *string
	var wrapped, nonce, ciphertext []byte
	err := q.QueryRow(ctx, `
		SELECT server_id, owner_user_id, method, client_id,
			secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext, issuer, registered_at
		FROM mcp_server_oauth_clients WHERE server_id = $1`, serverID,
	).Scan(&c.ServerID, &c.OwnerUserID, &c.Method, &c.ClientID, &keyID, &wrapped, &nonce, &ciphertext, &c.Issuer, &c.RegisteredAt)
	if err != nil {
		return nil, notFound(err)
	}
	if keyID != nil {
		c.ClientSecret = &Encrypted{KeyID: *keyID, WrappedDataKey: wrapped, Nonce: nonce, Ciphertext: ciphertext}
	}
	return &c, nil
}

// DeleteMCPOAuthClient removes a server's OAuth client registration and
// returns how many rows went.
func DeleteMCPOAuthClient(ctx context.Context, q Querier, serverID string) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM mcp_server_oauth_clients WHERE server_id = $1`, serverID)
	if err != nil {
		return 0, fmt.Errorf("store: delete mcp oauth client: %w", err)
	}
	return tag.RowsAffected(), nil
}

// MCPServerLockedCode is the SQLSTATE the mcp_servers_published_lock
// trigger (migration 00017) raises when the request path changes the
// address or sign-in settings of a published server.
const MCPServerLockedCode = "GW001"

// ErrMCPServerLocked: the server is published, so its URL, transport,
// auth kind and auth / header config can only be changed by an admin
// (decision q7vbxlyk point 3).
var ErrMCPServerLocked = errors.New("store: published server settings can only be changed by an admin")
