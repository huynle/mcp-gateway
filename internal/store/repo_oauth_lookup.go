package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Authorization-server queries the minimal OAuthRepository in tx.go does not
// cover (plan 36bakiw8 section 4; decisions 3ycafouv, ysorv868). They take
// a Querier so they run under whichever scope the caller opened:
//
//   - client registration, lookup and pruning are global (oauth_clients has
//     no row-level security);
//   - codes are created under WithUser at consent and consumed by the token
//     endpoint under WithJobs, where no user is known yet;
//   - refresh tokens are found by hash under WithJobs at the token endpoint
//     and listed / revoked under WithUser on the portal, where row-level
//     security hides everyone else's harnesses;
//   - signing keys are global.

// OAuthCode is a single-use authorization code (migration 00013). The code
// itself is stored as its SHA-256 hash.
type OAuthCode struct {
	ID            string
	CodeHash      []byte
	UserID        string
	ClientID      string
	RedirectURI   string
	Resource      string
	Scope         string
	CodeChallenge string
	FamilyID      *string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}

// RefreshTokenLookup is what the token endpoint needs to decide on a
// refresh token: the row, its client's public client_id and the owner
// facts the rules depend on.
type RefreshTokenLookup struct {
	Token               OAuthRefreshToken
	ClientPublicID      string
	ClientName          string
	UserStatus          string
	LastCompanySignInAt *time.Time
}

// Harness is one connected harness as the portal lists it: a refresh-token
// family's current link, with the client's name and the family's history.
type Harness struct {
	FamilyID   string
	ClientName string
	ClientID   string
	Scope      string
	Resource   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// UserAuthFacts are the owner facts bearer authentication checks.
type UserAuthFacts struct {
	Status              string
	LastCompanySignInAt *time.Time
}

const oauthClientColumns = `id, client_id, client_secret_hash, client_name, redirect_uris, metadata, created_at, last_used_at`

// FindOAuthClientByClientID returns the client registered under the public
// client_id.
func FindOAuthClientByClientID(ctx context.Context, q Querier, clientID string) (*OAuthClient, error) {
	var c OAuthClient
	err := q.QueryRow(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients WHERE client_id = $1`, clientID).
		Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.ClientName, &c.RedirectURIs, &c.Metadata, &c.CreatedAt, &c.LastUsedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

// TouchOAuthClient records that the client completed a sign-in or token
// exchange, which is what keeps it from being pruned.
func TouchOAuthClient(ctx context.Context, q Querier, id string, at time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE oauth_clients SET last_used_at = $2 WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("store: touch oauth client: %w", err)
	}
	return nil
}

// CountUnusedOAuthClients counts registrations that never completed a
// sign-in (the registration cap).
func CountUnusedOAuthClients(ctx context.Context, q Querier) (int64, error) {
	var n int64
	if err := q.QueryRow(ctx, `SELECT count(*) FROM oauth_clients WHERE last_used_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count unused oauth clients: %w", err)
	}
	return n, nil
}

// PruneOAuthClients deletes clients that were last used (or, never used,
// registered) before idleBefore, together with their codes and refresh
// tokens (ON DELETE CASCADE), and returns how many clients went.
func PruneOAuthClients(ctx context.Context, q Querier, idleBefore time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM oauth_clients WHERE coalesce(last_used_at, created_at) < $1`, idleBefore)
	if err != nil {
		return 0, fmt.Errorf("store: prune oauth clients: %w", err)
	}
	return tag.RowsAffected(), nil
}

const oauthCodeColumns = `id, code_hash, user_id, client_id, redirect_uri, resource, scope, code_challenge, family_id, created_at, expires_at, consumed_at`

// CreateOAuthCode stores a code (hash only) for the consenting user.
func CreateOAuthCode(ctx context.Context, q Querier, c *OAuthCode) error {
	err := q.QueryRow(ctx, `
		INSERT INTO oauth_authorization_codes (code_hash, user_id, client_id, redirect_uri, resource, scope, code_challenge, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at`,
		c.CodeHash, c.UserID, c.ClientID, c.RedirectURI, c.Resource, c.Scope, c.CodeChallenge, c.ExpiresAt,
	).Scan(&c.ID, &c.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create oauth code: %w", err)
	}
	return nil
}

// ConsumeOAuthCode marks the code with the given hash consumed at the
// given time and returns it. Exactly one caller wins a race: the losers,
// and anyone presenting the code again, get the row with ConsumedAt set to
// the earlier time, which the token endpoint treats as replay. An unknown
// hash is ErrNotFound.
func ConsumeOAuthCode(ctx context.Context, q Querier, codeHash []byte, at time.Time) (*OAuthCode, error) {
	c, err := scanOAuthCode(q.QueryRow(ctx, `
		UPDATE oauth_authorization_codes SET consumed_at = $2
		WHERE code_hash = $1 AND consumed_at IS NULL
		RETURNING `+oauthCodeColumns, codeHash, at))
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("store: consume oauth code: %w", err)
	}
	c, err = scanOAuthCode(q.QueryRow(ctx, `SELECT `+oauthCodeColumns+` FROM oauth_authorization_codes WHERE code_hash = $1`, codeHash))
	if err != nil {
		return nil, err
	}
	return c, nil
}

// SetOAuthCodeFamily records which refresh-token family a consumed code
// produced, so a replay can revoke it.
func SetOAuthCodeFamily(ctx context.Context, q Querier, id, familyID string) error {
	if _, err := q.Exec(ctx, `UPDATE oauth_authorization_codes SET family_id = $2 WHERE id = $1`, id, familyID); err != nil {
		return fmt.Errorf("store: set oauth code family: %w", err)
	}
	return nil
}

// DeleteExpiredOAuthCodes removes codes past their expiry (consumed or
// not) and returns how many.
func DeleteExpiredOAuthCodes(ctx context.Context, q Querier, before time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM oauth_authorization_codes WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete expired oauth codes: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanOAuthCode(row interface{ Scan(...any) error }) (*OAuthCode, error) {
	var c OAuthCode
	err := row.Scan(&c.ID, &c.CodeHash, &c.UserID, &c.ClientID, &c.RedirectURI, &c.Resource, &c.Scope, &c.CodeChallenge, &c.FamilyID, &c.CreatedAt, &c.ExpiresAt, &c.ConsumedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

const oauthRefreshColumns = `t.id, t.user_id, t.client_id, t.family_id, t.resource, t.token_hash, t.scope, t.issued_at, t.expires_at, t.rotated_from, t.rotated_at, t.revoked_at, t.last_used_at`

// CreateOAuthRefreshToken inserts a refresh token. An empty FamilyID
// starts a new family (the row's own id).
func CreateOAuthRefreshToken(ctx context.Context, q Querier, t *OAuthRefreshToken) error {
	var family *string
	if t.FamilyID != "" {
		family = &t.FamilyID
	}
	err := q.QueryRow(ctx, `
		WITH new_id AS (SELECT gen_random_uuid() AS id)
		INSERT INTO oauth_refresh_tokens (id, user_id, client_id, family_id, resource, token_hash, scope, expires_at, rotated_from)
		SELECT id, $1, $2, coalesce($3::uuid, id), $4, $5, coalesce($6::jsonb, '{}'::jsonb), $7, $8 FROM new_id
		RETURNING id, family_id, scope, issued_at`,
		t.UserID, t.ClientID, family, t.Resource, t.TokenHash, t.Scope, t.ExpiresAt, t.RotatedFrom,
	).Scan(&t.ID, &t.FamilyID, &t.Scope, &t.IssuedAt)
	if err != nil {
		return fmt.Errorf("store: create oauth refresh token: %w", err)
	}
	return nil
}

// FindOAuthRefreshTokenByHash returns the refresh token with the given
// hash, whatever its state, joined with its client and owner facts.
func FindOAuthRefreshTokenByHash(ctx context.Context, q Querier, hash []byte) (*RefreshTokenLookup, error) {
	var l RefreshTokenLookup
	t := &l.Token
	err := q.QueryRow(ctx, `
		SELECT `+oauthRefreshColumns+`, c.client_id, c.client_name, u.status, u.last_company_sign_in_at
		FROM oauth_refresh_tokens t
		JOIN oauth_clients c ON c.id = t.client_id
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1`, hash,
	).Scan(&t.ID, &t.UserID, &t.ClientID, &t.FamilyID, &t.Resource, &t.TokenHash, &t.Scope, &t.IssuedAt, &t.ExpiresAt, &t.RotatedFrom, &t.RotatedAt, &t.RevokedAt, &t.LastUsedAt,
		&l.ClientPublicID, &l.ClientName, &l.UserStatus, &l.LastCompanySignInAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &l, nil
}

// RotateOAuthRefreshToken marks a token as exchanged for its successor.
func RotateOAuthRefreshToken(ctx context.Context, q Querier, id string, at time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE oauth_refresh_tokens SET rotated_at = $2, last_used_at = $2 WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("store: rotate oauth refresh token: %w", err)
	}
	return nil
}

// RevokeOAuthRefreshFamily revokes every live token of a family and
// returns how many. Under WithUser another user's family is hidden, so
// the count is 0.
func RevokeOAuthRefreshFamily(ctx context.Context, q Querier, familyID string, at time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`, familyID, at)
	if err != nil {
		return 0, fmt.Errorf("store: revoke oauth refresh family: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeUserOAuthRefreshTokens revokes every live refresh token of a user
// and deletes their unconsumed codes (the disable hook, WithJobs).
func RevokeUserOAuthRefreshTokens(ctx context.Context, q Querier, userID string, at time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, userID, at)
	if err != nil {
		return 0, fmt.Errorf("store: revoke user oauth refresh tokens: %w", err)
	}
	if _, err := q.Exec(ctx, `DELETE FROM oauth_authorization_codes WHERE user_id = $1 AND consumed_at IS NULL`, userID); err != nil {
		return 0, fmt.Errorf("store: delete user oauth codes: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListOAuthHarnesses returns the user's refresh-token families, newest
// first, each represented by its current (not yet rotated) link.
func ListOAuthHarnesses(ctx context.Context, q Querier, userID string) ([]Harness, error) {
	rows, err := q.Query(ctx, `
		SELECT t.family_id, c.client_name, c.client_id, t.scope, t.resource,
		       (SELECT min(f.issued_at) FROM oauth_refresh_tokens f WHERE f.family_id = t.family_id) AS created_at,
		       t.expires_at, coalesce(t.last_used_at, t.issued_at), t.revoked_at
		FROM oauth_refresh_tokens t
		JOIN oauth_clients c ON c.id = t.client_id
		WHERE t.user_id = $1 AND t.rotated_at IS NULL
		ORDER BY created_at DESC, t.family_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list oauth harnesses: %w", err)
	}
	defer rows.Close()
	var out []Harness
	for rows.Next() {
		var h Harness
		var scope []byte
		var lastUsed time.Time
		if err := rows.Scan(&h.FamilyID, &h.ClientName, &h.ClientID, &scope, &h.Resource, &h.CreatedAt, &h.ExpiresAt, &lastUsed, &h.RevokedAt); err != nil {
			return nil, err
		}
		h.Scope = string(scope)
		h.LastUsedAt = &lastUsed
		out = append(out, h)
	}
	return out, rows.Err()
}

// TouchOAuthRefreshToken records a use of the current link (an access
// token minted from it was presented), best-effort.
func TouchOAuthRefreshToken(ctx context.Context, q Querier, id string, at time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE oauth_refresh_tokens SET last_used_at = $2 WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("store: touch oauth refresh token: %w", err)
	}
	return nil
}

// FindUserAuthFacts returns the owner facts bearer authentication checks.
func FindUserAuthFacts(ctx context.Context, q Querier, userID string) (*UserAuthFacts, error) {
	var f UserAuthFacts
	err := q.QueryRow(ctx, `SELECT status, last_company_sign_in_at FROM users WHERE id = $1`, userID).Scan(&f.Status, &f.LastCompanySignInAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &f, nil
}

const signingKeyColumns = `id, kid, algorithm, public_key, private_key_id, private_wrapped_key, private_nonce, private_ciphertext, status, created_at, retired_at`

// ListSigningKeys returns every signing key, newest first.
func ListSigningKeys(ctx context.Context, q Querier) ([]SigningKey, error) {
	rows, err := q.Query(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys ORDER BY created_at DESC, kid`)
	if err != nil {
		return nil, fmt.Errorf("store: list signing keys: %w", err)
	}
	defer rows.Close()
	var out []SigningKey
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.ID, &k.KID, &k.Algorithm, &k.PublicKey,
			&k.PrivateKey.KeyID, &k.PrivateKey.WrappedDataKey, &k.PrivateKey.Nonce, &k.PrivateKey.Ciphertext,
			&k.Status, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RetireSigningKeys marks every active key other than keepKID retired at
// the given time (the rotation job, after creating the new key).
func RetireSigningKeys(ctx context.Context, q Querier, keepKID string, at time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE signing_keys SET status = $3, retired_at = $2 WHERE kid <> $1 AND status = $4`, keepKID, at, SigningKeyRetired, SigningKeyActive)
	if err != nil {
		return 0, fmt.Errorf("store: retire signing keys: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteRetiredSigningKeys removes keys retired before the given time
// (past the verification grace period; WithJobs).
func DeleteRetiredSigningKeys(ctx context.Context, q Querier, retiredBefore time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM signing_keys WHERE status = $2 AND retired_at < $1`, retiredBefore, SigningKeyRetired)
	if err != nil {
		return 0, fmt.Errorf("store: delete retired signing keys: %w", err)
	}
	return tag.RowsAffected(), nil
}
