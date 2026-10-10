package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Approvals-module queries beyond the minimal repository in tx.go
// (decision s0p05diu): insert with a caller-chosen id (the id is part of
// the payload's AEAD associated data, so it must exist before encryption),
// reads joined with the connection's label, the pending-only decision
// update, the single-use conditional consume, the digest lookup and the
// expiry sweep. They take a Querier so they run under whichever scope the
// caller opened: user-facing paths under WithUser (row-level security hides
// everyone else's approvals), the expiry job under WithJobs.

// ApprovalRecord is one approvals row together with the connection's
// label and display name (joined; empty when the connection is gone) and
// the metadata columns migration 00010 added.
type ApprovalRecord struct {
	Approval
	TokenID            *string
	Resource           json.RawMessage
	AccountLabel       string
	AccountDisplayName string
}

// ApprovalBinding is what a consume must match: the approval was granted
// for exactly this user, account, tool and policy version.
type ApprovalBinding struct {
	UserID          string
	ConnectionID    string
	Tool            string
	PolicyVersionID string
}

// ErrApprovalNotConsumable is returned by ConsumeApproval when the row
// exists but is not approved, is already consumed, has expired, or does
// not match the binding. The caller reads the row to tell which.
var ErrApprovalNotConsumable = errors.New("store: approval not consumable")

const approvalColumns = `
	a.id, a.user_id, a.connection_id, a.tool, a.digest,
	a.payload_key_id, a.payload_wrapped_key, a.payload_nonce, a.payload_ciphertext,
	a.status, a.policy_version_id, a.created_at, a.expires_at, a.decided_at, a.consumed_at,
	a.token_id, a.resource, coalesce(c.label::text, ''), coalesce(c.display_name, '')`

const approvalFrom = ` FROM approvals a LEFT JOIN connections c ON c.id = a.connection_id AND c.user_id = a.user_id`

type approvalScanner interface {
	Scan(dest ...any) error
}

func scanApproval(row approvalScanner) (*ApprovalRecord, error) {
	var a ApprovalRecord
	var keyID *string
	var wrapped, nonce, ciphertext []byte
	err := row.Scan(&a.ID, &a.UserID, &a.ConnectionID, &a.Tool, &a.Digest,
		&keyID, &wrapped, &nonce, &ciphertext,
		&a.Status, &a.PolicyVersionID, &a.CreatedAt, &a.ExpiresAt, &a.DecidedAt, &a.ConsumedAt,
		&a.TokenID, &a.Resource, &a.AccountLabel, &a.AccountDisplayName)
	if err != nil {
		return nil, err
	}
	if keyID != nil {
		a.Payload = &Encrypted{KeyID: *keyID, WrappedDataKey: wrapped, Nonce: nonce, Ciphertext: ciphertext}
	}
	return &a, nil
}

// CreateApproval inserts a pending approval under the caller-chosen a.ID
// with its encrypted payload. Status is forced to pending.
func CreateApproval(ctx context.Context, q Querier, a *ApprovalRecord) error {
	if a.Payload == nil {
		return errors.New("store: create approval: payload is required")
	}
	if a.ID == "" {
		return errors.New("store: create approval: id is required")
	}
	resource := a.Resource
	if len(resource) == 0 {
		resource = json.RawMessage(`{}`)
	}
	err := q.QueryRow(ctx, `
		INSERT INTO approvals (id, user_id, connection_id, tool, digest,
			payload_key_id, payload_wrapped_key, payload_nonce, payload_ciphertext,
			status, policy_version_id, expires_at, token_id, resource)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11, $12, $13::jsonb)
		RETURNING status, created_at, resource`,
		a.ID, a.UserID, a.ConnectionID, a.Tool, a.Digest,
		a.Payload.KeyID, a.Payload.WrappedDataKey, a.Payload.Nonce, a.Payload.Ciphertext,
		a.PolicyVersionID, a.ExpiresAt, a.TokenID, resource,
	).Scan(&a.Status, &a.CreatedAt, &a.Resource)
	if err != nil {
		return fmt.Errorf("store: create approval: %w", err)
	}
	return nil
}

// GetApproval reads one approval the scope can see.
func GetApproval(ctx context.Context, q Querier, id string) (*ApprovalRecord, error) {
	a, err := scanApproval(q.QueryRow(ctx, `SELECT`+approvalColumns+approvalFrom+` WHERE a.id = $1`, id))
	if err != nil {
		return nil, notFound(err)
	}
	return a, nil
}

// ListApprovals returns the user's approvals, newest first: only pending
// ones when pendingOnly, at most limit rows (0 means no limit).
func ListApprovals(ctx context.Context, q Querier, userID string, pendingOnly bool, limit int) ([]ApprovalRecord, error) {
	sql := `SELECT` + approvalColumns + approvalFrom + ` WHERE a.user_id = $1`
	if pendingOnly {
		sql += ` AND a.status = 'pending'`
	}
	sql += ` ORDER BY a.created_at DESC, a.id DESC`
	args := []any{userID}
	if limit > 0 {
		sql += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list approvals: %w", err)
	}
	defer rows.Close()
	var out []ApprovalRecord
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list approvals: %w", err)
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// DecideApproval moves a pending, unexpired approval of userID to status
// (approved keeps the payload for the consume; denied drops it) and
// returns the updated row. ErrNotFound when no such pending row is
// visible: it does not exist, belongs to someone else, was already
// decided, or has expired.
func DecideApproval(ctx context.Context, q Querier, id, userID, status string, at time.Time) (*ApprovalRecord, error) {
	var sql string
	switch status {
	case ApprovalApproved:
		sql = `UPDATE approvals SET status = 'approved', decided_at = $3
			WHERE id = $1 AND user_id = $2 AND status = 'pending' AND expires_at > $3`
	case ApprovalDenied:
		sql = `UPDATE approvals SET status = 'denied', decided_at = $3,
				payload_key_id = NULL, payload_wrapped_key = NULL, payload_nonce = NULL, payload_ciphertext = NULL
			WHERE id = $1 AND user_id = $2 AND status = 'pending' AND expires_at > $3`
	default:
		return nil, fmt.Errorf("store: decide approval: status %q is not a decision", status)
	}
	tag, err := q.Exec(ctx, sql, id, userID, at)
	if err != nil {
		return nil, fmt.Errorf("store: decide approval: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return GetApproval(ctx, q, id)
}

// ConsumeApproval is the single-use step: one conditional UPDATE that
// succeeds only for an approved, unconsumed, unexpired row bound exactly
// to b. Under READ COMMITTED a concurrent consumer blocks on the row lock
// and re-evaluates the WHERE on the committed version, so of two
// concurrent attempts exactly one sees RowsAffected 1. The payload
// columns are set to NULL in the same statement; callers read the
// payload before calling (it is immutable until then) and only use it
// when this returns nil.
func ConsumeApproval(ctx context.Context, q Querier, id string, b ApprovalBinding, at time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE approvals SET status = 'consumed', consumed_at = $6,
			payload_key_id = NULL, payload_wrapped_key = NULL, payload_nonce = NULL, payload_ciphertext = NULL
		WHERE id = $1 AND user_id = $2 AND connection_id = $3 AND tool = $4 AND policy_version_id = $5
			AND status = 'approved' AND consumed_at IS NULL AND expires_at > $6`,
		id, b.UserID, b.ConnectionID, b.Tool, b.PolicyVersionID, at)
	if err != nil {
		return fmt.Errorf("store: consume approval: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrApprovalNotConsumable
	}
	return nil
}

// FindApprovedApproval returns the id of the newest approved, unconsumed,
// unexpired approval bound to b with the given digest (ErrNotFound when
// none): the retry-without-approval_id path of decision s0p05diu.
func FindApprovedApproval(ctx context.Context, q Querier, b ApprovalBinding, digest []byte, at time.Time) (string, error) {
	var id string
	err := q.QueryRow(ctx, `
		SELECT id FROM approvals
		WHERE user_id = $1 AND connection_id = $2 AND tool = $3 AND policy_version_id = $4 AND digest = $5
			AND status = 'approved' AND consumed_at IS NULL AND expires_at > $6
		ORDER BY decided_at DESC, created_at DESC LIMIT 1`,
		b.UserID, b.ConnectionID, b.Tool, b.PolicyVersionID, digest, at).Scan(&id)
	if err != nil {
		return "", notFound(err)
	}
	return id, nil
}

// ExpireApprovals marks every pending or approved approval whose expiry
// has passed as expired and drops its payload, returning how many rows
// changed. The expiry job runs it under WithJobs across all users.
func ExpireApprovals(ctx context.Context, q Querier, at time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `
		UPDATE approvals SET status = 'expired',
			payload_key_id = NULL, payload_wrapped_key = NULL, payload_nonce = NULL, payload_ciphertext = NULL
		WHERE status IN ('pending', 'approved') AND expires_at <= $1`, at)
	if err != nil {
		return 0, fmt.Errorf("store: expire approvals: %w", err)
	}
	return tag.RowsAffected(), nil
}
