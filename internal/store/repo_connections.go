package store

import (
	"context"
	"fmt"
)

type vendorAppRepo struct{ q Querier }

func (r vendorAppRepo) Create(ctx context.Context, a *VendorApp) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO vendor_apps (vendor, name, client_id,
			secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext, config, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, coalesce($8::jsonb, '{}'::jsonb), $9)
		RETURNING id, config, created_at, updated_at`,
		a.Vendor, a.Name, a.ClientID,
		a.ClientSecret.KeyID, a.ClientSecret.WrappedDataKey, a.ClientSecret.Nonce, a.ClientSecret.Ciphertext,
		a.Config, a.Enabled,
	).Scan(&a.ID, &a.Config, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: create vendor app: %w", err)
	}
	return nil
}

func (r vendorAppRepo) Get(ctx context.Context, id string) (*VendorApp, error) {
	var a VendorApp
	err := r.q.QueryRow(ctx, `
		SELECT id, vendor, name, client_id,
			secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext,
			config, enabled, created_at, updated_at
		FROM vendor_apps WHERE id = $1`, id,
	).Scan(&a.ID, &a.Vendor, &a.Name, &a.ClientID,
		&a.ClientSecret.KeyID, &a.ClientSecret.WrappedDataKey, &a.ClientSecret.Nonce, &a.ClientSecret.Ciphertext,
		&a.Config, &a.Enabled, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

type connectionRepo struct{ q Querier }

func (r connectionRepo) Create(ctx context.Context, c *Connection) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO connections (user_id, vendor_app_id, external_account_id, label, display_name, scopes, status)
		VALUES ($1, $2, $3, $4, $5, coalesce($6::text[], '{}'), coalesce(nullif($7, ''), 'active'))
		RETURNING id, scopes, status, created_at, updated_at`,
		c.UserID, c.VendorAppID, c.ExternalAccountID, c.Label, c.DisplayName, c.Scopes, c.Status,
	).Scan(&c.ID, &c.Scopes, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: create connection: %w", err)
	}
	return nil
}

func (r connectionRepo) Get(ctx context.Context, id string) (*Connection, error) {
	var c Connection
	err := r.q.QueryRow(ctx, `
		SELECT id, user_id, vendor_app_id, external_account_id, label, display_name, scopes, status,
			last_refreshed_at, created_at, updated_at
		FROM connections WHERE id = $1`, id,
	).Scan(&c.ID, &c.UserID, &c.VendorAppID, &c.ExternalAccountID, &c.Label, &c.DisplayName, &c.Scopes, &c.Status,
		&c.LastRefreshedAt, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

// PutSecret inserts or replaces the connection's encrypted token bundle.
func (r connectionRepo) PutSecret(ctx context.Context, s *ConnectionSecret) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO connection_secrets (connection_id, user_id,
			secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext, token_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (connection_id) DO UPDATE SET
			secret_key_id = EXCLUDED.secret_key_id,
			secret_wrapped_key = EXCLUDED.secret_wrapped_key,
			secret_nonce = EXCLUDED.secret_nonce,
			secret_ciphertext = EXCLUDED.secret_ciphertext,
			token_expires_at = EXCLUDED.token_expires_at,
			updated_at = now()
		RETURNING updated_at`,
		s.ConnectionID, s.UserID,
		s.Secret.KeyID, s.Secret.WrappedDataKey, s.Secret.Nonce, s.Secret.Ciphertext, s.TokenExpiresAt,
	).Scan(&s.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: put connection secret: %w", err)
	}
	return nil
}

func (r connectionRepo) GetSecret(ctx context.Context, connectionID string) (*ConnectionSecret, error) {
	var s ConnectionSecret
	err := r.q.QueryRow(ctx, `
		SELECT connection_id, user_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext,
			token_expires_at, updated_at
		FROM connection_secrets WHERE connection_id = $1`, connectionID,
	).Scan(&s.ConnectionID, &s.UserID, &s.Secret.KeyID, &s.Secret.WrappedDataKey, &s.Secret.Nonce, &s.Secret.Ciphertext,
		&s.TokenExpiresAt, &s.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}
