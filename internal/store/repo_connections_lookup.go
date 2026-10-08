package store

import (
	"context"
	"fmt"
	"time"
)

// Connections-module queries that the minimal VendorAppRepository and
// ConnectionRepository in tx.go do not cover. They take a Querier so they
// run under whichever scope the caller opened:
//
//   - vendor apps are global rows: admin pages write them through WithJobs
//     and the connect flow reads them through either scope;
//   - connections, connection_secrets and connect_flows are user rows: the
//     connect flow, token refresh, disconnect and the account source run
//     under WithUser so row-level security hides everyone else's;
//   - the disable hook and the keep-alive job run under WithJobs.

const vendorAppColumns = `id, vendor, name, client_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext, config, enabled, created_at, updated_at`

func scanVendorApp(row interface{ Scan(dest ...any) error }) (*VendorApp, error) {
	var a VendorApp
	err := row.Scan(&a.ID, &a.Vendor, &a.Name, &a.ClientID,
		&a.ClientSecret.KeyID, &a.ClientSecret.WrappedDataKey, &a.ClientSecret.Nonce, &a.ClientSecret.Ciphertext,
		&a.Config, &a.Enabled, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

// ListVendorApps returns every vendor app ordered by vendor and name.
func ListVendorApps(ctx context.Context, q Querier) ([]VendorApp, error) {
	rows, err := q.Query(ctx, `SELECT `+vendorAppColumns+` FROM vendor_apps ORDER BY vendor, name`)
	if err != nil {
		return nil, fmt.Errorf("store: list vendor apps: %w", err)
	}
	defer rows.Close()
	var out []VendorApp
	for rows.Next() {
		a, err := scanVendorApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// FindVendorApp returns the app registered for (vendor, name).
func FindVendorApp(ctx context.Context, q Querier, vendor, name string) (*VendorApp, error) {
	return scanVendorApp(q.QueryRow(ctx, `SELECT `+vendorAppColumns+` FROM vendor_apps WHERE vendor = $1 AND name = $2`, vendor, name))
}

// UpsertVendorApp inserts the app under a.ID (which the caller chooses so
// the secret's AAD can name it) or, when (vendor, name) already exists,
// replaces its client ID, secret, config and enabled flag. The row's
// actual ID and timestamps are written back.
func UpsertVendorApp(ctx context.Context, q Querier, a *VendorApp) error {
	err := q.QueryRow(ctx, `
		INSERT INTO vendor_apps (id, vendor, name, client_id,
			secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext, config, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, coalesce($9::jsonb, '{}'::jsonb), $10)
		ON CONFLICT (vendor, name) DO UPDATE SET
			client_id = EXCLUDED.client_id,
			secret_key_id = EXCLUDED.secret_key_id,
			secret_wrapped_key = EXCLUDED.secret_wrapped_key,
			secret_nonce = EXCLUDED.secret_nonce,
			secret_ciphertext = EXCLUDED.secret_ciphertext,
			config = EXCLUDED.config,
			enabled = EXCLUDED.enabled,
			updated_at = now()
		RETURNING id, created_at, updated_at`,
		a.ID, a.Vendor, a.Name, a.ClientID,
		a.ClientSecret.KeyID, a.ClientSecret.WrappedDataKey, a.ClientSecret.Nonce, a.ClientSecret.Ciphertext,
		a.Config, a.Enabled,
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: upsert vendor app: %w", err)
	}
	return nil
}

// ConnectionWithApp is a connection joined with its vendor app's identity.
type ConnectionWithApp struct {
	Connection
	Vendor  string
	AppName string
}

const connectionColumns = `c.id, c.user_id, c.vendor_app_id, c.external_account_id, c.label, c.display_name, c.scopes, c.status, c.last_refreshed_at, c.created_at, c.updated_at`

func scanConnection(row interface{ Scan(dest ...any) error }, c *Connection) error {
	return row.Scan(&c.ID, &c.UserID, &c.VendorAppID, &c.ExternalAccountID, &c.Label, &c.DisplayName, &c.Scopes, &c.Status,
		&c.LastRefreshedAt, &c.CreatedAt, &c.UpdatedAt)
}

// ListConnectionsForUser returns the user's connections with their vendor,
// oldest first. Under WithUser row-level security already restricts the
// rows; the user_id filter keeps the query explicit.
func ListConnectionsForUser(ctx context.Context, q Querier, userID string) ([]ConnectionWithApp, error) {
	rows, err := q.Query(ctx, `
		SELECT `+connectionColumns+`, a.vendor, a.name
		FROM connections c JOIN vendor_apps a ON a.id = c.vendor_app_id
		WHERE c.user_id = $1
		ORDER BY a.vendor, a.name, c.created_at, c.id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list connections: %w", err)
	}
	defer rows.Close()
	var out []ConnectionWithApp
	for rows.Next() {
		var c ConnectionWithApp
		if err := rows.Scan(&c.ID, &c.UserID, &c.VendorAppID, &c.ExternalAccountID, &c.Label, &c.DisplayName, &c.Scopes, &c.Status,
			&c.LastRefreshedAt, &c.CreatedAt, &c.UpdatedAt, &c.Vendor, &c.AppName); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FindConnection returns the user's connection to one external account of
// one vendor app, whatever its status.
func FindConnection(ctx context.Context, q Querier, userID, vendorAppID, externalAccountID string) (*Connection, error) {
	var c Connection
	err := scanConnection(q.QueryRow(ctx, `
		SELECT `+connectionColumns+` FROM connections c
		WHERE c.user_id = $1 AND c.vendor_app_id = $2 AND c.external_account_id = $3`, userID, vendorAppID, externalAccountID), &c)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

// LockConnection returns the connection after taking a row lock (SELECT
// ... FOR UPDATE) that lasts until the transaction ends: token refreshes
// of one connection are serialised across replicas by it.
func LockConnection(ctx context.Context, q Querier, id string) (*Connection, error) {
	var c Connection
	err := scanConnection(q.QueryRow(ctx, `SELECT `+connectionColumns+` FROM connections c WHERE c.id = $1 FOR UPDATE`, id), &c)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

// UpdateConnection rewrites the mutable fields of a connection (label,
// display name, scopes, status) and returns ErrNotFound for an invisible
// row.
func UpdateConnection(ctx context.Context, q Querier, c *Connection) error {
	err := q.QueryRow(ctx, `
		UPDATE connections SET label = $2, display_name = $3, scopes = coalesce($4::text[], '{}'), status = $5, updated_at = now()
		WHERE id = $1 RETURNING updated_at`,
		c.ID, c.Label, c.DisplayName, c.Scopes, c.Status,
	).Scan(&c.UpdatedAt)
	if err != nil {
		return notFound(err)
	}
	return nil
}

// SetConnectionStatus changes a connection's status.
func SetConnectionStatus(ctx context.Context, q Querier, id, status string) error {
	tag, err := q.Exec(ctx, `UPDATE connections SET status = $2, updated_at = now() WHERE id = $1`, id, status)
	if err != nil {
		return fmt.Errorf("store: set connection status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchConnectionRefreshed records a successful token refresh.
func TouchConnectionRefreshed(ctx context.Context, q Querier, id string, at time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE connections SET last_refreshed_at = $2, updated_at = now() WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("store: touch connection: %w", err)
	}
	return nil
}

// DeleteConnectionSecret removes the token bundle of one connection; the
// connection row and its audit trail stay. Returns how many rows went.
func DeleteConnectionSecret(ctx context.Context, q Querier, connectionID string) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM connection_secrets WHERE connection_id = $1`, connectionID)
	if err != nil {
		return 0, fmt.Errorf("store: delete connection secret: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeUserConnections marks every connection of userID revoked and
// deletes their secrets; the disable hook calls it through WithJobs. It
// returns the connections that were live before.
func RevokeUserConnections(ctx context.Context, q Querier, userID string) ([]Connection, error) {
	rows, err := q.Query(ctx, `
		UPDATE connections c SET status = 'revoked', updated_at = now()
		WHERE c.user_id = $1 AND c.status <> 'revoked'
		RETURNING `+connectionColumns, userID)
	if err != nil {
		return nil, fmt.Errorf("store: revoke user connections: %w", err)
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var c Connection
		if err := scanConnection(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if _, err := q.Exec(ctx, `DELETE FROM connection_secrets WHERE user_id = $1`, userID); err != nil {
		return nil, fmt.Errorf("store: delete user connection secrets: %w", err)
	}
	return out, nil
}

// ListStaleConnections returns active connections whose tokens were last
// refreshed (or, never refreshed, created) before the given time, oldest
// first and at most limit rows. The keep-alive job reads it through
// WithJobs.
func ListStaleConnections(ctx context.Context, q Querier, before time.Time, limit int) ([]Connection, error) {
	rows, err := q.Query(ctx, `
		SELECT `+connectionColumns+` FROM connections c
		WHERE c.status = 'active' AND coalesce(c.last_refreshed_at, c.created_at) < $1
		ORDER BY coalesce(c.last_refreshed_at, c.created_at), c.id
		LIMIT $2`, before, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list stale connections: %w", err)
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var c Connection
		if err := scanConnection(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ConnectFlow is one in-flight /connect flow: the OAuth state, the PKCE
// verifier and what was requested, bound to the user who started it.
type ConnectFlow struct {
	State       string
	UserID      string
	VendorAppID string
	Verifier    string
	Scopes      []string
	ReturnTo    string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// CreateConnectFlow stores a flow.
func CreateConnectFlow(ctx context.Context, q Querier, f *ConnectFlow) error {
	err := q.QueryRow(ctx, `
		INSERT INTO connect_flows (state, user_id, vendor_app_id, verifier, scopes, return_to, expires_at)
		VALUES ($1, $2, $3, $4, coalesce($5::text[], '{}'), $6, $7)
		RETURNING created_at`,
		f.State, f.UserID, f.VendorAppID, f.Verifier, f.Scopes, f.ReturnTo, f.ExpiresAt,
	).Scan(&f.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create connect flow: %w", err)
	}
	return nil
}

// TakeConnectFlow deletes and returns the flow with the given state (one
// use); ErrNotFound when it does not exist, expired, or belongs to another
// user under WithUser. Expired rows are deleted on the way.
func TakeConnectFlow(ctx context.Context, q Querier, state string, now time.Time) (*ConnectFlow, error) {
	var f ConnectFlow
	err := q.QueryRow(ctx, `
		DELETE FROM connect_flows WHERE state = $1
		RETURNING state, user_id, vendor_app_id, verifier, scopes, return_to, created_at, expires_at`, state,
	).Scan(&f.State, &f.UserID, &f.VendorAppID, &f.Verifier, &f.Scopes, &f.ReturnTo, &f.CreatedAt, &f.ExpiresAt)
	if err != nil {
		return nil, notFound(err)
	}
	if !f.ExpiresAt.After(now) {
		return nil, ErrNotFound
	}
	return &f, nil
}

// PurgeConnectFlows deletes expired flows (keep-alive job, WithJobs).
func PurgeConnectFlows(ctx context.Context, q Querier, now time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM connect_flows WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, fmt.Errorf("store: purge connect flows: %w", err)
	}
	return tag.RowsAffected(), nil
}
