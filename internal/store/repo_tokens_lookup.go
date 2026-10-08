package store

import (
	"context"
	"fmt"
	"time"
)

// Token-module queries that the minimal TokenRepository in tx.go does not
// cover. They take a Querier so they run under whichever scope the caller
// opened:
//
//   - FindTokenByPublicID and TouchToken are the pre-authentication path:
//     the user is not known until the token row is, so they run under
//     WithJobs (decision 9z5sdzsm, point 3) and the query is deliberately
//     narrow: one row by its unique public id plus the owner's status and
//     last company sign-in.
//   - ListTokensForUser and RevokeToken are self-service and run under
//     WithUser, where row-level security hides everyone else's tokens.
//   - RevokeUserTokens is the disable hook (WithJobs).

// TokenLookup is what authentication needs to decide on a bearer token:
// the token row and the two owner facts the rules depend on.
type TokenLookup struct {
	Token               Token
	UserStatus          string
	LastCompanySignInAt *time.Time
}

const tokenColumns = `t.id, t.user_id, t.public_id, t.name, t.token_hash, t.read_only, t.scope, t.expires_at, t.revoked_at, t.last_used_at, t.created_at`

// FindTokenByPublicID returns the token whose embedded id is publicID,
// whatever its state, joined with its owner's status and last company
// sign-in; callers compare the hash and apply expiry, revocation and
// freshness rules.
func FindTokenByPublicID(ctx context.Context, q Querier, publicID string) (*TokenLookup, error) {
	var l TokenLookup
	t := &l.Token
	err := q.QueryRow(ctx, `
		SELECT `+tokenColumns+`, u.status, u.last_company_sign_in_at
		FROM tokens t JOIN users u ON u.id = t.user_id
		WHERE t.public_id = $1`, publicID,
	).Scan(&t.ID, &t.UserID, &t.PublicID, &t.Name, &t.TokenHash, &t.ReadOnly, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedAt,
		&l.UserStatus, &l.LastCompanySignInAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &l, nil
}

// TouchToken records that the token was used at the given time.
func TouchToken(ctx context.Context, q Querier, id string, at time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE tokens SET last_used_at = $2 WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("store: touch token: %w", err)
	}
	return nil
}

// ListTokensForUser returns userID's tokens, newest first. Under WithUser
// row-level security already restricts the rows; the user_id filter keeps
// the query explicit.
func ListTokensForUser(ctx context.Context, q Querier, userID string) ([]Token, error) {
	rows, err := q.Query(ctx, `
		SELECT `+tokenColumns+`
		FROM tokens t WHERE t.user_id = $1
		ORDER BY t.created_at DESC, t.id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list tokens: %w", err)
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.UserID, &t.PublicID, &t.Name, &t.TokenHash, &t.ReadOnly, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken revokes one token. It returns ErrNotFound when no visible row
// matches, which under WithUser includes another user's token; a token
// already revoked keeps its original revocation time and is not an error.
func RevokeToken(ctx context.Context, q Querier, id string, at time.Time) error {
	var revokedAt time.Time
	err := q.QueryRow(ctx, `
		UPDATE tokens SET revoked_at = coalesce(revoked_at, $2)
		WHERE id = $1 RETURNING revoked_at`, id, at,
	).Scan(&revokedAt)
	if err != nil {
		return notFound(err)
	}
	return nil
}

// RevokeUserTokens revokes every live token of userID and returns how many
// it revoked. Used by the identity disable hook through WithJobs.
func RevokeUserTokens(ctx context.Context, q Querier, userID string, at time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, userID, at)
	if err != nil {
		return 0, fmt.Errorf("store: revoke user tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
