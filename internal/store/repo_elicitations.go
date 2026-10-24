package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Upstream URL elicitation queries (migration 00032,
// docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md,
// plan 2). They take a Querier so they run under whichever scope the caller
// opened: creating, reading, opening and cancelling under WithUser (row
// security limits them to the owner's rows), the expiry purge under
// WithJobs (gateway_app has no DELETE). Link ids arrive as SHA-256 hashes
// only.

// UpstreamElicitation is one upstream_elicitations row. A row is live while
// CancelledAt is nil and ExpiresAt has not passed; OpenedAt records the
// first Continue and does not end it.
type UpstreamElicitation struct {
	ID                    string
	LinkHash              []byte
	OwnerUserID           string
	ServerID              string
	HarnessID             string
	URL                   string
	UpstreamElicitationID string
	Message               string
	CreatedAt             time.Time
	ExpiresAt             time.Time
	OpenedAt              *time.Time
	CancelledAt           *time.Time
}

const upstreamElicitationColumns = `
	id, link_hash, owner_user_id, server_id, harness_id, url, upstream_elicitation_id, message,
	created_at, expires_at, opened_at, cancelled_at`

func scanUpstreamElicitation(row interface{ Scan(dest ...any) error }) (*UpstreamElicitation, error) {
	var e UpstreamElicitation
	err := row.Scan(&e.ID, &e.LinkHash, &e.OwnerUserID, &e.ServerID, &e.HarnessID, &e.URL, &e.UpstreamElicitationID, &e.Message,
		&e.CreatedAt, &e.ExpiresAt, &e.OpenedAt, &e.CancelledAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func oneUpstreamElicitation(ctx context.Context, q Querier, sql string, args ...any) (*UpstreamElicitation, error) {
	e, err := scanUpstreamElicitation(q.QueryRow(ctx, sql, args...))
	if err != nil {
		return nil, notFound(err)
	}
	return e, nil
}

// CreateUpstreamElicitation inserts e. e.ID and e.CreatedAt may be preset
// (otherwise the database chooses them; the per-owner cap counts live rows
// by expires_at, so callers with their own clock set both). The stored row
// is written back into e.
func CreateUpstreamElicitation(ctx context.Context, q Querier, e *UpstreamElicitation) error {
	if len(e.LinkHash) == 0 {
		return errors.New("store: create upstream elicitation: link hash is required")
	}
	var id, created any
	if e.ID != "" {
		id = e.ID
	}
	if !e.CreatedAt.IsZero() {
		created = e.CreatedAt
	}
	got, err := scanUpstreamElicitation(q.QueryRow(ctx, `
		INSERT INTO upstream_elicitations (id, link_hash, owner_user_id, server_id, harness_id, url,
			upstream_elicitation_id, message, created_at, expires_at)
		VALUES (coalesce($1::uuid, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, coalesce($9::timestamptz, now()), $10)
		RETURNING`+upstreamElicitationColumns,
		id, e.LinkHash, e.OwnerUserID, e.ServerID, e.HarnessID, e.URL, e.UpstreamElicitationID, e.Message, created, e.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: create upstream elicitation: %w", err)
	}
	*e = *got
	return nil
}

// liveElicitation is the predicate of a live row of owner $1 with link
// hash $2 at time $3.
const liveElicitation = `owner_user_id = $1 AND link_hash = $2 AND cancelled_at IS NULL AND expires_at > $3`

// GetUpstreamElicitationByLink reads ownerID's live elicitation whose link
// id hashes to h at at. ErrNotFound for anything else (unknown,
// someone else's, cancelled, expired).
func GetUpstreamElicitationByLink(ctx context.Context, q Querier, ownerID string, h []byte, at time.Time) (*UpstreamElicitation, error) {
	return oneUpstreamElicitation(ctx, q, `SELECT`+upstreamElicitationColumns+` FROM upstream_elicitations WHERE `+liveElicitation,
		ownerID, h, at)
}

// MarkUpstreamElicitationOpened records that ownerID pressed Continue on
// the live elicitation h (the first time is kept; the row stays live).
// ErrNotFound when it is not live.
func MarkUpstreamElicitationOpened(ctx context.Context, q Querier, ownerID string, h []byte, at time.Time) (*UpstreamElicitation, error) {
	return oneUpstreamElicitation(ctx, q, `
		UPDATE upstream_elicitations SET opened_at = coalesce(opened_at, $3)
		WHERE `+liveElicitation+` RETURNING`+upstreamElicitationColumns, ownerID, h, at)
}

// MarkUpstreamElicitationCancelled ends ownerID's live elicitation h.
// ErrNotFound when it is not live.
func MarkUpstreamElicitationCancelled(ctx context.Context, q Querier, ownerID string, h []byte, at time.Time) (*UpstreamElicitation, error) {
	return oneUpstreamElicitation(ctx, q, `
		UPDATE upstream_elicitations SET cancelled_at = $3
		WHERE `+liveElicitation+` RETURNING`+upstreamElicitationColumns, ownerID, h, at)
}

// LockUpstreamElicitations serialises ownerID's new elicitations for the
// rest of the transaction, so the live cap cannot be raced.
func LockUpstreamElicitations(ctx context.Context, q Querier, ownerID string) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('mcp-gateway:upstream-elicitations:' || $1::text))`, ownerID); err != nil {
		return fmt.Errorf("store: lock upstream elicitations: %w", err)
	}
	return nil
}

// CountLiveUpstreamElicitations counts ownerID's live elicitations at at.
func CountLiveUpstreamElicitations(ctx context.Context, q Querier, ownerID string, at time.Time) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM upstream_elicitations
		WHERE owner_user_id = $1 AND cancelled_at IS NULL AND expires_at > $2`, ownerID, at).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count upstream elicitations: %w", err)
	}
	return n, nil
}

// PurgeExpiredUpstreamElicitations deletes every elicitation that expired
// at or before before (cancelled or not). Jobs scope only.
func PurgeExpiredUpstreamElicitations(ctx context.Context, q Querier, before time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM upstream_elicitations WHERE expires_at <= $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: purge upstream elicitations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SetMCPServerElicitationOrigins replaces a server's elicitation origins
// (nil clears them). It is the only writer of the column: UpdateMCPServer
// leaves it alone, so whole-settings writers cannot wipe it. ErrNotFound
// when the caller may not change the row; ErrMCPServerLocked when the
// server is published and the caller is on the request path (migration
// 00032 extends the 00017 lock; an admin change does not supersede the
// approved snapshot).
func SetMCPServerElicitationOrigins(ctx context.Context, q Querier, serverID string, origins []string) error {
	if origins == nil {
		origins = []string{}
	}
	tag, err := q.Exec(ctx, `UPDATE mcp_servers SET elicitation_origins = $2, updated_at = now() WHERE id = $1`, serverID, origins)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == MCPServerLockedCode {
		return ErrMCPServerLocked
	}
	if err != nil {
		return fmt.Errorf("store: set mcp server elicitation origins: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
