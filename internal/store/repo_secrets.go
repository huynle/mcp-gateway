package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Ephemeral secrets queries (migration 00031,
// docs/plans/2026-10-23-ephemeral-secrets-design.md). They take a Querier
// so they run under whichever scope the caller opened: request, entry page,
// list, revoke, consume and refund under WithUser (row-level security hides
// everyone else's secrets); the expiry job and the disable hook under
// WithJobs. Request ids and handles arrive as SHA-256 hashes only.

// Secret states (the secrets.state column).
const (
	SecretPending  = "pending"
	SecretProvided = "provided"
	SecretDenied   = "denied"
	SecretRevoked  = "revoked"
	SecretExpired  = "expired"
)

// Secret is one secrets row. Value is set only while the row is provided.
// Arg is nil for a machine action binding.
type Secret struct {
	ID            string
	OwnerUserID   string
	HarnessID     string
	Label         string
	ServerID      string
	Tool          string
	Arg           *string
	UsesTotal     int
	UsesLeft      int
	TTL           time.Duration
	LinkExpiresAt time.Time
	ExpiresAt     *time.Time
	RequestHash   []byte
	HandleHash    []byte
	State         string
	Value         *Encrypted
	ProvidedAt    *time.Time
	EndedAt       *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SecretBinding is the target a secret may be used for: a server, one of
// its tools and the argument the value goes into (nil Arg: a machine
// action, where the value is not an argument).
type SecretBinding struct {
	ServerID string
	Tool     string
	Arg      *string
}

// SecretExpiry is what ExpireSecrets did.
type SecretExpiry struct {
	// Expired counts rows moved to expired (link, TTL or uses ran out);
	// their ciphertext was wiped in the same statement.
	Expired int64
	// Deleted counts ended rows removed after the retention period.
	Deleted int64
}

// ErrSecretNotConsumable is returned by ConsumeSecret when no provided,
// unexpired secret with uses left matches the handle, owner, harness and
// binding. The caller reads the row to tell pending or denied apart.
var ErrSecretNotConsumable = errors.New("store: secret not consumable")

const secretColumns = `
	id, owner_user_id, harness_id, label, server_id, tool, arg,
	uses_total, uses_left, ttl_seconds, link_expires_at, expires_at,
	request_hash, handle_hash, state,
	value_key_id, value_wrapped_key, value_nonce, value_ciphertext,
	provided_at, ended_at, created_at, updated_at`

// secretWipe sets the value columns to NULL.
const secretWipe = `value_key_id = NULL, value_wrapped_key = NULL, value_nonce = NULL, value_ciphertext = NULL`

type secretScanner interface {
	Scan(dest ...any) error
}

func scanSecret(row secretScanner) (*Secret, error) {
	var s Secret
	var ttl int
	var keyID *string
	var wrapped, nonce, ciphertext []byte
	err := row.Scan(&s.ID, &s.OwnerUserID, &s.HarnessID, &s.Label, &s.ServerID, &s.Tool, &s.Arg,
		&s.UsesTotal, &s.UsesLeft, &ttl, &s.LinkExpiresAt, &s.ExpiresAt,
		&s.RequestHash, &s.HandleHash, &s.State,
		&keyID, &wrapped, &nonce, &ciphertext,
		&s.ProvidedAt, &s.EndedAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	s.TTL = time.Duration(ttl) * time.Second
	if keyID != nil {
		s.Value = &Encrypted{KeyID: *keyID, WrappedDataKey: wrapped, Nonce: nonce, Ciphertext: ciphertext}
	}
	return &s, nil
}

func oneSecret(ctx context.Context, q Querier, sql string, args ...any) (*Secret, error) {
	s, err := scanSecret(q.QueryRow(ctx, sql, args...))
	if err != nil {
		return nil, notFound(err)
	}
	return s, nil
}

// CreateSecret inserts a pending request. s.ID and s.CreatedAt may be
// preset (otherwise the database chooses them; the request limits count
// created_at, so callers with their own clock set it); state, value and
// the other timestamps are filled from the inserted row.
func CreateSecret(ctx context.Context, q Querier, s *Secret) error {
	if len(s.RequestHash) == 0 || len(s.HandleHash) == 0 {
		return errors.New("store: create secret: request and handle hashes are required")
	}
	var id, created any
	if s.ID != "" {
		id = s.ID
	}
	if !s.CreatedAt.IsZero() {
		created = s.CreatedAt
	}
	got, err := scanSecret(q.QueryRow(ctx, `
		INSERT INTO secrets (id, owner_user_id, harness_id, label, server_id, tool, arg,
			uses_total, uses_left, ttl_seconds, link_expires_at, request_hash, handle_hash, created_at, updated_at)
		VALUES (coalesce($1::uuid, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
			coalesce($14::timestamptz, now()), coalesce($14::timestamptz, now()))
		RETURNING`+secretColumns,
		id, s.OwnerUserID, s.HarnessID, s.Label, s.ServerID, s.Tool, s.Arg,
		s.UsesTotal, s.UsesLeft, int(s.TTL/time.Second), s.LinkExpiresAt, s.RequestHash, s.HandleHash, created))
	if err != nil {
		return fmt.Errorf("store: create secret: %w", err)
	}
	*s = *got
	return nil
}

// GetSecret reads one secret the scope can see.
func GetSecret(ctx context.Context, q Querier, id string) (*Secret, error) {
	return oneSecret(ctx, q, `SELECT`+secretColumns+` FROM secrets WHERE id = $1`, id)
}

// GetSecretByRequestHash reads the secret whose request id hashes to h.
func GetSecretByRequestHash(ctx context.Context, q Querier, h []byte) (*Secret, error) {
	return oneSecret(ctx, q, `SELECT`+secretColumns+` FROM secrets WHERE request_hash = $1`, h)
}

// GetSecretByHandleHash reads the secret whose handle hashes to h.
func GetSecretByHandleHash(ctx context.Context, q Querier, h []byte) (*Secret, error) {
	return oneSecret(ctx, q, `SELECT`+secretColumns+` FROM secrets WHERE handle_hash = $1`, h)
}

// ListSecrets returns ownerID's secrets, newest first.
func ListSecrets(ctx context.Context, q Querier, ownerID string) ([]Secret, error) {
	rows, err := q.Query(ctx, `SELECT`+secretColumns+` FROM secrets WHERE owner_user_id = $1
		ORDER BY created_at DESC, id DESC`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("store: list secrets: %w", err)
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list secrets: %w", err)
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// LockSecretRequests serialises ownerID's secret requests for the rest of
// the transaction, so the pending and hourly limits cannot be raced.
func LockSecretRequests(ctx context.Context, q Querier, ownerID string) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('mcp-gateway:secret-requests:' || $1::text))`, ownerID); err != nil {
		return fmt.Errorf("store: lock secret requests: %w", err)
	}
	return nil
}

// CountSecretRequests returns how many of ownerID's requests are pending
// with a live link at at, and how many were created since since.
func CountSecretRequests(ctx context.Context, q Querier, ownerID string, since, at time.Time) (pending, recent int, err error) {
	err = q.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE state = 'pending' AND link_expires_at > $3),
			count(*) FILTER (WHERE created_at > $2)
		FROM secrets WHERE owner_user_id = $1`, ownerID, since, at).Scan(&pending, &recent)
	if err != nil {
		return 0, 0, fmt.Errorf("store: count secret requests: %w", err)
	}
	return pending, recent, nil
}

// ProvideSecret stores the encrypted value of a pending request whose
// link is still valid at at: state provided, expires_at = at + ttl. Single
// use: ErrNotFound when no such pending row is visible (wrong id or hash,
// someone else's, already answered, link expired).
func ProvideSecret(ctx context.Context, q Querier, id string, requestHash []byte, value Encrypted, at time.Time) (*Secret, error) {
	return oneSecret(ctx, q, `
		UPDATE secrets SET state = 'provided', provided_at = $7,
			expires_at = $7 + ttl_seconds * interval '1 second', uses_left = uses_total,
			value_key_id = $3, value_wrapped_key = $4, value_nonce = $5, value_ciphertext = $6, updated_at = $7
		WHERE id = $1 AND request_hash = $2 AND state = 'pending' AND link_expires_at > $7
		RETURNING`+secretColumns,
		id, requestHash, value.KeyID, value.WrappedDataKey, value.Nonce, value.Ciphertext, at)
}

// DenySecret moves a pending request with a live link to denied.
// ErrNotFound otherwise.
func DenySecret(ctx context.Context, q Querier, requestHash []byte, at time.Time) (*Secret, error) {
	return oneSecret(ctx, q, `
		UPDATE secrets SET state = 'denied', ended_at = $2, updated_at = $2
		WHERE request_hash = $1 AND state = 'pending' AND link_expires_at > $2
		RETURNING`+secretColumns, requestHash, at)
}

// RevokeSecret revokes a pending or provided secret and wipes its value.
// ErrNotFound when no such live row is visible.
func RevokeSecret(ctx context.Context, q Querier, id string, at time.Time) (*Secret, error) {
	return oneSecret(ctx, q, `
		UPDATE secrets SET state = 'revoked', ended_at = $2, updated_at = $2, `+secretWipe+`
		WHERE id = $1 AND state IN ('pending', 'provided')
		RETURNING`+secretColumns, id, at)
}

// ConsumeSecret takes one use: a single conditional UPDATE that succeeds
// only for a provided, unexpired secret with uses left whose handle,
// owner, harness and binding all match. Under READ COMMITTED concurrent
// consumers block on the row lock and re-check the WHERE on the committed
// version, so uses_left never goes below zero and a one-use secret is
// consumed exactly once. The returned row carries the value. The value is
// never wiped here; the expiry job does that (a use may be refunded).
func ConsumeSecret(ctx context.Context, q Querier, handleHash []byte, ownerID, harnessID string, b SecretBinding, at time.Time) (*Secret, error) {
	s, err := scanSecret(q.QueryRow(ctx, `
		UPDATE secrets SET uses_left = uses_left - 1, updated_at = $7
		WHERE handle_hash = $1 AND owner_user_id = $2 AND harness_id = $3
			AND server_id = $4 AND tool = $5 AND arg IS NOT DISTINCT FROM $6
			AND state = 'provided' AND uses_left > 0 AND expires_at > $7
		RETURNING`+secretColumns,
		handleHash, ownerID, harnessID, b.ServerID, b.Tool, b.Arg, at))
	if err != nil {
		if errors.Is(notFound(err), ErrNotFound) {
			return nil, ErrSecretNotConsumable
		}
		return nil, fmt.Errorf("store: consume secret: %w", err)
	}
	return s, nil
}

// RefundSecret gives back one use of a provided, unexpired secret (the
// call failed before reaching its target), never above uses_total.
// ErrNotFound when nothing was refunded.
func RefundSecret(ctx context.Context, q Querier, id string, at time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE secrets SET uses_left = uses_left + 1, updated_at = $2
		WHERE id = $1 AND state = 'provided' AND uses_left < uses_total AND expires_at > $2`, id, at)
	if err != nil {
		return fmt.Errorf("store: refund secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpireSecrets is the expiry sweep (WithJobs): pending requests whose
// link passed and provided secrets that are used up or past their TTL
// become expired with their value wiped; ended rows (denied, revoked,
// expired) older than retention are deleted.
func ExpireSecrets(ctx context.Context, q Querier, at time.Time, retention time.Duration) (SecretExpiry, error) {
	var out SecretExpiry
	tag, err := q.Exec(ctx, `
		UPDATE secrets SET state = 'expired', ended_at = $1, updated_at = $1, `+secretWipe+`
		WHERE (state = 'pending' AND link_expires_at <= $1)
			OR (state = 'provided' AND (uses_left = 0 OR expires_at <= $1))`, at)
	if err != nil {
		return out, fmt.Errorf("store: expire secrets: %w", err)
	}
	out.Expired = tag.RowsAffected()
	tag, err = q.Exec(ctx, `
		DELETE FROM secrets WHERE state IN ('denied', 'revoked', 'expired') AND ended_at <= $1`, at.Add(-retention))
	if err != nil {
		return out, fmt.Errorf("store: delete ended secrets: %w", err)
	}
	out.Deleted = tag.RowsAffected()
	return out, nil
}

// RevokeUserSecrets revokes every pending or provided secret of ownerID
// and wipes the values (user disabled). It returns how many it revoked.
func RevokeUserSecrets(ctx context.Context, q Querier, ownerID string, at time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `
		UPDATE secrets SET state = 'revoked', ended_at = $2, updated_at = $2, `+secretWipe+`
		WHERE owner_user_id = $1 AND state IN ('pending', 'provided')`, ownerID, at)
	if err != nil {
		return 0, fmt.Errorf("store: revoke user secrets: %w", err)
	}
	return tag.RowsAffected(), nil
}
