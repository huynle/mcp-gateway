package store

import (
	"context"
	"fmt"
)

type tokenRepo struct{ q Querier }

func (r tokenRepo) Create(ctx context.Context, t *Token) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO tokens (user_id, public_id, name, token_hash, read_only, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		t.UserID, t.PublicID, t.Name, t.TokenHash, t.ReadOnly, t.Scope, t.ExpiresAt,
	).Scan(&t.ID, &t.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create token: %w", err)
	}
	return nil
}

func (r tokenRepo) Get(ctx context.Context, id string) (*Token, error) {
	var t Token
	err := r.q.QueryRow(ctx, `
		SELECT id, user_id, public_id, name, token_hash, read_only, scope, expires_at, revoked_at, last_used_at, created_at
		FROM tokens WHERE id = $1`, id,
	).Scan(&t.ID, &t.UserID, &t.PublicID, &t.Name, &t.TokenHash, &t.ReadOnly, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}

type oauthRepo struct{ q Querier }

func (r oauthRepo) CreateClient(ctx context.Context, c *OAuthClient) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, metadata)
		VALUES ($1, $2, $3, coalesce($4::text[], '{}'), coalesce($5::jsonb, '{}'::jsonb))
		RETURNING id, redirect_uris, metadata, created_at`,
		c.ClientID, c.ClientSecretHash, c.ClientName, c.RedirectURIs, c.Metadata,
	).Scan(&c.ID, &c.RedirectURIs, &c.Metadata, &c.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create oauth client: %w", err)
	}
	return nil
}

func (r oauthRepo) GetClient(ctx context.Context, id string) (*OAuthClient, error) {
	var c OAuthClient
	err := r.q.QueryRow(ctx, `
		SELECT id, client_id, client_secret_hash, client_name, redirect_uris, metadata, created_at, last_used_at
		FROM oauth_clients WHERE id = $1`, id,
	).Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.ClientName, &c.RedirectURIs, &c.Metadata, &c.CreatedAt, &c.LastUsedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

func (r oauthRepo) CreateRefreshToken(ctx context.Context, t *OAuthRefreshToken) error {
	// Delegates to the authorization server's insert so family_id (its
	// own id for a new family) and resource are always set (migration 00013).
	return CreateOAuthRefreshToken(ctx, r.q, t)
}

func (r oauthRepo) GetRefreshToken(ctx context.Context, id string) (*OAuthRefreshToken, error) {
	var t OAuthRefreshToken
	err := r.q.QueryRow(ctx, `
		SELECT id, user_id, client_id, family_id, resource, token_hash, scope, issued_at, expires_at, rotated_from, rotated_at, revoked_at, last_used_at
		FROM oauth_refresh_tokens WHERE id = $1`, id,
	).Scan(&t.ID, &t.UserID, &t.ClientID, &t.FamilyID, &t.Resource, &t.TokenHash, &t.Scope, &t.IssuedAt, &t.ExpiresAt, &t.RotatedFrom, &t.RotatedAt, &t.RevokedAt, &t.LastUsedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}
