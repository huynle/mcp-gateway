package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Harness device authorization grants (migration 00034, RFC 8628). Every
// query runs under WithJobs: no user is known before approval.

// Device grant states.
const (
	OAuthDevicePending  = "pending"
	OAuthDeviceApproved = "approved"
	OAuthDeviceDenied   = "denied"
	OAuthDeviceRedeemed = "redeemed"
)

// ErrUserCodeTaken: a device grant or machine device request already
// holds the user code (the caller draws another one).
var ErrUserCodeTaken = errors.New("store: user code taken")

// OAuthDeviceGrant is one harness device authorization. UserID is the
// user who allowed or denied it ("" while pending).
type OAuthDeviceGrant struct {
	ID             string
	DeviceCodeHash []byte
	UserCodeHash   []byte
	ClientID       string
	Scope          string
	Resource       string
	Status         string
	UserID         string
	RequestIP      string
	UserAgent      string
	Interval       int
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastPolledAt   *time.Time
	DecidedAt      *time.Time
	RedeemedAt     *time.Time
	FamilyID       *string
}

const oauthDeviceColumns = `id, device_code_hash, user_code_hash, client_id, scope, resource, status, user_id, request_ip, user_agent,
	interval_seconds, created_at, expires_at, last_polled_at, decided_at, redeemed_at, family_id`

func scanOAuthDeviceGrant(row interface{ Scan(...any) error }) (*OAuthDeviceGrant, error) {
	var g OAuthDeviceGrant
	var user *string
	if err := row.Scan(&g.ID, &g.DeviceCodeHash, &g.UserCodeHash, &g.ClientID, &g.Scope, &g.Resource, &g.Status, &user, &g.RequestIP,
		&g.UserAgent, &g.Interval, &g.CreatedAt, &g.ExpiresAt, &g.LastPolledAt, &g.DecidedAt, &g.RedeemedAt, &g.FamilyID); err != nil {
		return nil, notFound(err)
	}
	g.UserID = deref(user)
	return &g, nil
}

// CreateOAuthDeviceGrant stores a pending grant; the stored row is
// written back into g. ErrUserCodeTaken when another grant or a machine
// device request holds the user code.
func CreateOAuthDeviceGrant(ctx context.Context, q Querier, g *OAuthDeviceGrant) error {
	row, err := scanOAuthDeviceGrant(q.QueryRow(ctx, `
		INSERT INTO oauth_device_grants (device_code_hash, user_code_hash, client_id, scope, resource, request_ip, user_agent,
			interval_seconds, expires_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
		WHERE NOT EXISTS (SELECT 1 FROM machine_device_requests WHERE user_code_hash = $2)
		RETURNING `+oauthDeviceColumns,
		g.DeviceCodeHash, g.UserCodeHash, g.ClientID, g.Scope, g.Resource, g.RequestIP, g.UserAgent, g.Interval, g.ExpiresAt))
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, ErrNotFound), errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == "oauth_device_grants_user_code_hash_key":
		return ErrUserCodeTaken
	case err != nil:
		return fmt.Errorf("store: create device grant: %w", err)
	}
	*g = *row
	return nil
}

// CountPendingOAuthDeviceGrants counts a client's pending, unexpired
// grants (the per-client cap).
func CountPendingOAuthDeviceGrants(ctx context.Context, q Querier, clientID string, at time.Time) (int64, error) {
	var n int64
	if err := q.QueryRow(ctx, `SELECT count(*) FROM oauth_device_grants WHERE client_id = $1 AND status = 'pending' AND expires_at > $2`,
		clientID, at).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count device grants: %w", err)
	}
	return n, nil
}

// FindOAuthDeviceGrantByUserCode finds a grant by user code hash, in any
// state.
func FindOAuthDeviceGrantByUserCode(ctx context.Context, q Querier, hash []byte) (*OAuthDeviceGrant, error) {
	return scanOAuthDeviceGrant(q.QueryRow(ctx, `SELECT `+oauthDeviceColumns+` FROM oauth_device_grants WHERE user_code_hash = $1`, hash))
}

// LockOAuthDeviceGrant finds a grant by device code hash and locks it
// until the transaction ends (token endpoint polls).
func LockOAuthDeviceGrant(ctx context.Context, q Querier, hash []byte) (*OAuthDeviceGrant, error) {
	return scanOAuthDeviceGrant(q.QueryRow(ctx, `SELECT `+oauthDeviceColumns+` FROM oauth_device_grants
		WHERE device_code_hash = $1 FOR UPDATE`, hash))
}

// LockOAuthDeviceGrantByID locks a grant by id (the approval page).
func LockOAuthDeviceGrantByID(ctx context.Context, q Querier, id string) (*OAuthDeviceGrant, error) {
	return scanOAuthDeviceGrant(q.QueryRow(ctx, `SELECT `+oauthDeviceColumns+` FROM oauth_device_grants
		WHERE id = $1 FOR UPDATE`, id))
}

// UpdateOAuthDeviceGrant writes a grant's mutable state: status, user,
// interval, last poll, decision, redemption and family.
func UpdateOAuthDeviceGrant(ctx context.Context, q Querier, g *OAuthDeviceGrant) error {
	tag, err := q.Exec(ctx, `UPDATE oauth_device_grants SET status = $2, user_id = $3, interval_seconds = $4, last_polled_at = $5,
		decided_at = $6, redeemed_at = $7, family_id = $8 WHERE id = $1`,
		g.ID, g.Status, nullString(g.UserID), g.Interval, g.LastPolledAt, g.DecidedAt, g.RedeemedAt, g.FamilyID)
	if err != nil {
		return fmt.Errorf("store: update device grant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteExpiredOAuthDeviceGrants removes grants past their expiry (in any
// state) and returns how many.
func DeleteExpiredOAuthDeviceGrants(ctx context.Context, q Querier, before time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM oauth_device_grants WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete expired device grants: %w", err)
	}
	return tag.RowsAffected(), nil
}
