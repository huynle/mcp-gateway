package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Public sign-up storage (migration 00027): guarded user status
// transitions, single-use invite codes and the new-account counter behind
// the sign-up rate limit. Every function runs under WithJobs: the tables
// are invisible to gateway_app.

// SignupInvite is one signup_invites row. Only the SHA-256 of the code
// is stored.
type SignupInvite struct {
	ID        string
	CodeHash  []byte
	Label     string
	CreatedBy *string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	UsedBy    *string
	RevokedAt *time.Time
}

// TransitionUserStatus moves userID from status from to status to,
// maintaining disabled_at. ErrNotFound when the user does not exist or is
// not in status from (so a concurrent approve and reject cannot both win).
func TransitionUserStatus(ctx context.Context, q Querier, userID, from, to string, at time.Time) error {
	if !validUserStatus(from) || !validUserStatus(to) {
		return fmt.Errorf("store: transition user status: unknown status %q -> %q", from, to)
	}
	var disabledAt *time.Time
	if to == UserDisabled {
		disabledAt = &at
	}
	tag, err := q.Exec(ctx, `
		UPDATE users SET status = $3, disabled_at = $4, updated_at = now()
		WHERE id = $1 AND status = $2`,
		userID, from, to, disabledAt)
	if err != nil {
		return fmt.Errorf("store: transition user status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func validUserStatus(s string) bool {
	return s == UserActive || s == UserDisabled || s == UserPending
}

// CreateSignupInvite inserts inv, filling ID and CreatedAt.
func CreateSignupInvite(ctx context.Context, q Querier, inv *SignupInvite) error {
	err := q.QueryRow(ctx, `
		INSERT INTO signup_invites (code_hash, label, created_by, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`,
		inv.CodeHash, inv.Label, inv.CreatedBy, inv.ExpiresAt,
	).Scan(&inv.ID, &inv.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create signup invite: %w", err)
	}
	return nil
}

// ConsumeSignupInvite marks the unused, unrevoked, unexpired invite whose
// code hashes to codeHash as used by userID and returns its ID.
// ErrNotFound for any other code: unknown, used, revoked or expired are
// deliberately indistinguishable.
func ConsumeSignupInvite(ctx context.Context, q Querier, codeHash []byte, userID string, at time.Time) (string, error) {
	var id string
	err := q.QueryRow(ctx, `
		UPDATE signup_invites SET used_at = $3, used_by = $2
		WHERE code_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $3
		RETURNING id`,
		codeHash, userID, at,
	).Scan(&id)
	if err != nil {
		return "", notFound(err)
	}
	return id, nil
}

// RevokeSignupInvite revokes an unused, unrevoked invite (ErrNotFound
// otherwise).
func RevokeSignupInvite(ctx context.Context, q Querier, id string, at time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE signup_invites SET revoked_at = $2
		WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL`, id, at)
	if err != nil {
		if isInvalidUUID(err) {
			return ErrNotFound
		}
		return fmt.Errorf("store: revoke signup invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListSignupInvites returns the newest limit invites.
func ListSignupInvites(ctx context.Context, q Querier, limit int) ([]SignupInvite, error) {
	rows, err := q.Query(ctx, `
		SELECT id, code_hash, label, created_by, created_at, expires_at, used_at, used_by, revoked_at
		FROM signup_invites ORDER BY created_at DESC, id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list signup invites: %w", err)
	}
	defer rows.Close()
	var out []SignupInvite
	for rows.Next() {
		var inv SignupInvite
		if err := rows.Scan(&inv.ID, &inv.CodeHash, &inv.Label, &inv.CreatedBy, &inv.CreatedAt, &inv.ExpiresAt, &inv.UsedAt, &inv.UsedBy, &inv.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// LockSignups serialises account creation for the rest of the
// transaction, so concurrent sign-ups on any replica cannot overshoot the
// new-account limits.
func LockSignups(ctx context.Context, q Querier) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('mcp-gateway:signup'))`); err != nil {
		return fmt.Errorf("store: lock signups: %w", err)
	}
	return nil
}

// CountSignupEvents counts the accounts created since since: in total and
// for clientKey.
func CountSignupEvents(ctx context.Context, q Querier, clientKey []byte, since time.Time) (global, perKey int, err error) {
	err = q.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE client_key = $1)
		FROM signup_events WHERE created_at > $2`, clientKey, since,
	).Scan(&global, &perKey)
	if err != nil {
		return 0, 0, fmt.Errorf("store: count signup events: %w", err)
	}
	return global, perKey, nil
}

// RecordSignupEvent records one account creation for clientKey at at and
// deletes the events older than pruneBefore (none when it is zero).
func RecordSignupEvent(ctx context.Context, q Querier, clientKey []byte, at, pruneBefore time.Time) error {
	if !pruneBefore.IsZero() {
		if _, err := q.Exec(ctx, `DELETE FROM signup_events WHERE created_at < $1`, pruneBefore); err != nil {
			return fmt.Errorf("store: prune signup events: %w", err)
		}
	}
	if _, err := q.Exec(ctx, `INSERT INTO signup_events (client_key, created_at) VALUES ($1, $2)`, clientKey, at); err != nil {
		return fmt.Errorf("store: record signup event: %w", err)
	}
	return nil
}

// isInvalidUUID reports a malformed uuid parameter (SQLSTATE 22P02): an
// id from a URL path that cannot name any row.
func isInvalidUUID(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "22P02"
}
