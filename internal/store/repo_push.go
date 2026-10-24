package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Web Push queries (migration 00033, decision 0pzhidap; internal/pushnotify
// is the only caller). They take a Querier so they run under whichever
// scope the caller opened: subscribe, list, remove, delivery bookkeeping
// and the notifier's reads under WithUser (row-level security hides
// everyone else's subscriptions); the VAPID key, the endpoint handover and
// the disable hook under WithJobs. Endpoints arrive as SHA-256 hashes
// only; the endpoint and its keys are inside Sealed.

// WebPushKey is the gateway's VAPID key pair: the public key as the
// browser's base64url applicationServerKey, the private key (PKCS#8 DER)
// envelope-encrypted.
type WebPushKey struct {
	ID         string
	PublicKey  string
	PrivateKey Encrypted
	CreatedAt  time.Time
}

// PushSubscription is one push_subscriptions row. Sealed holds the
// endpoint, p256dh and auth; EndpointHost and DeviceLabel are display-only.
type PushSubscription struct {
	ID             string
	UserID         string
	EndpointSHA256 []byte
	Sealed         Encrypted
	EndpointHost   string
	DeviceLabel    string
	FailureCount   int
	LastSuccessAt  *time.Time
	LastFailureAt  *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ErrPushEndpointTaken is returned by CreatePushSubscription when the
// endpoint is already subscribed: under row-level security that is
// another user's row (the caller's own would have been visible and
// updated instead). ReleasePushEndpoint hands it over.
var ErrPushEndpointTaken = errors.New("store: push endpoint subscribed by another user")

// GetWebPushKey reads the VAPID key; ErrNotFound before the first one is
// created.
func GetWebPushKey(ctx context.Context, q Querier) (*WebPushKey, error) {
	var k WebPushKey
	err := q.QueryRow(ctx, `
		SELECT id, public_key, private_key_id, private_wrapped_key, private_nonce, private_ciphertext, created_at
		FROM webpush_keys WHERE singleton`,
	).Scan(&k.ID, &k.PublicKey, &k.PrivateKey.KeyID, &k.PrivateKey.WrappedDataKey, &k.PrivateKey.Nonce, &k.PrivateKey.Ciphertext, &k.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &k, nil
}

// CreateWebPushKey stores k (k.ID preset: it is the encryption's record
// id) unless a key already exists, and reports whether it was stored. A
// concurrent creator blocks on the unique singleton until the first one
// commits, then stores nothing; callers re-read with GetWebPushKey.
func CreateWebPushKey(ctx context.Context, q Querier, k *WebPushKey) (bool, error) {
	if k.ID == "" {
		return false, errors.New("store: create web push key: id is required")
	}
	tag, err := q.Exec(ctx, `
		INSERT INTO webpush_keys (id, public_key, private_key_id, private_wrapped_key, private_nonce, private_ciphertext)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (singleton) DO NOTHING`,
		k.ID, k.PublicKey, k.PrivateKey.KeyID, k.PrivateKey.WrappedDataKey, k.PrivateKey.Nonce, k.PrivateKey.Ciphertext)
	if err != nil {
		return false, fmt.Errorf("store: create web push key: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

const pushSubscriptionColumns = `
	id, user_id, endpoint_sha256, sub_key_id, sub_wrapped_key, sub_nonce, sub_ciphertext,
	endpoint_host, device_label, failure_count, last_success_at, last_failure_at, created_at, updated_at`

type pushScanner interface {
	Scan(dest ...any) error
}

func scanPushSubscription(row pushScanner) (*PushSubscription, error) {
	var s PushSubscription
	err := row.Scan(&s.ID, &s.UserID, &s.EndpointSHA256,
		&s.Sealed.KeyID, &s.Sealed.WrappedDataKey, &s.Sealed.Nonce, &s.Sealed.Ciphertext,
		&s.EndpointHost, &s.DeviceLabel, &s.FailureCount, &s.LastSuccessAt, &s.LastFailureAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// LockPushSubscriptions serialises userID's subscribes for the rest of
// the transaction, so the per-user cap cannot be raced.
func LockPushSubscriptions(ctx context.Context, q Querier, userID string) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('mcp-gateway:push-subscriptions:' || $1::text))`, userID); err != nil {
		return fmt.Errorf("store: lock push subscriptions: %w", err)
	}
	return nil
}

// CountPushSubscriptions counts userID's subscriptions.
func CountPushSubscriptions(ctx context.Context, q Querier, userID string) (int, error) {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM push_subscriptions WHERE user_id = $1`, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count push subscriptions: %w", err)
	}
	return n, nil
}

// GetPushSubscriptionByHash reads the visible subscription whose endpoint
// hashes to h.
func GetPushSubscriptionByHash(ctx context.Context, q Querier, h []byte) (*PushSubscription, error) {
	s, err := scanPushSubscription(q.QueryRow(ctx, `SELECT`+pushSubscriptionColumns+` FROM push_subscriptions WHERE endpoint_sha256 = $1`, h))
	if err != nil {
		return nil, notFound(err)
	}
	return s, nil
}

// CreatePushSubscription inserts s (s.ID preset: it is the encryption's
// record id) and fills the timestamps. An endpoint another user holds
// violates the unique index; ReleasePushEndpoint hands it over first.
func CreatePushSubscription(ctx context.Context, q Querier, s *PushSubscription) error {
	if s.ID == "" || len(s.EndpointSHA256) == 0 {
		return errors.New("store: create push subscription: id and endpoint hash are required")
	}
	got, err := scanPushSubscription(q.QueryRow(ctx, `
		INSERT INTO push_subscriptions (id, user_id, endpoint_sha256, sub_key_id, sub_wrapped_key, sub_nonce, sub_ciphertext,
			endpoint_host, device_label)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING`+pushSubscriptionColumns,
		s.ID, s.UserID, s.EndpointSHA256, s.Sealed.KeyID, s.Sealed.WrappedDataKey, s.Sealed.Nonce, s.Sealed.Ciphertext,
		s.EndpointHost, s.DeviceLabel))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "push_subscriptions_endpoint_sha256_key" {
		return ErrPushEndpointTaken
	}
	if err != nil {
		return fmt.Errorf("store: create push subscription: %w", err)
	}
	*s = *got
	return nil
}

// UpdatePushSubscription stores a re-subscription of the same endpoint:
// new sealed keys, host and label; the failure count starts over.
func UpdatePushSubscription(ctx context.Context, q Querier, s *PushSubscription) error {
	got, err := scanPushSubscription(q.QueryRow(ctx, `
		UPDATE push_subscriptions SET sub_key_id = $2, sub_wrapped_key = $3, sub_nonce = $4, sub_ciphertext = $5,
			endpoint_host = $6, device_label = $7, failure_count = 0, updated_at = now()
		WHERE id = $1
		RETURNING`+pushSubscriptionColumns,
		s.ID, s.Sealed.KeyID, s.Sealed.WrappedDataKey, s.Sealed.Nonce, s.Sealed.Ciphertext, s.EndpointHost, s.DeviceLabel))
	if err != nil {
		return notFound(err)
	}
	*s = *got
	return nil
}

// ListPushSubscriptions returns userID's subscriptions, oldest first.
func ListPushSubscriptions(ctx context.Context, q Querier, userID string) ([]PushSubscription, error) {
	rows, err := q.Query(ctx, `SELECT`+pushSubscriptionColumns+` FROM push_subscriptions WHERE user_id = $1
		ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list push subscriptions: %w", err)
	}
	defer rows.Close()
	var out []PushSubscription
	for rows.Next() {
		s, err := scanPushSubscription(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list push subscriptions: %w", err)
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// DeletePushSubscription deletes one visible subscription and reports
// whether it existed.
func DeletePushSubscription(ctx context.Context, q Querier, id string) (bool, error) {
	tag, err := q.Exec(ctx, `DELETE FROM push_subscriptions WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("store: delete push subscription: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeletePushSubscriptionByHash deletes the visible subscription whose
// endpoint hashes to h and reports whether it existed.
func DeletePushSubscriptionByHash(ctx context.Context, q Querier, h []byte) (bool, error) {
	tag, err := q.Exec(ctx, `DELETE FROM push_subscriptions WHERE endpoint_sha256 = $1`, h)
	if err != nil {
		return false, fmt.Errorf("store: delete push subscription: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ReleasePushEndpoint (WithJobs) deletes the subscription of endpoint
// hash h when a user other than newOwner holds it: the browser that
// presents the endpoint now belongs to newOwner's session. It returns
// how many rows it deleted (0 or 1).
func ReleasePushEndpoint(ctx context.Context, q Querier, h []byte, newOwner string) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM push_subscriptions WHERE endpoint_sha256 = $1 AND user_id <> $2`, h, newOwner)
	if err != nil {
		return 0, fmt.Errorf("store: release push endpoint: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RecordPushDelivery notes a delivery attempt: a success sets
// last_success_at and clears the failure count, a failure sets
// last_failure_at and increments it. A row that is not visible (deleted
// meanwhile) is ignored.
func RecordPushDelivery(ctx context.Context, q Querier, id string, ok bool, at time.Time) error {
	sql := `UPDATE push_subscriptions SET last_failure_at = $2, failure_count = failure_count + 1 WHERE id = $1`
	if ok {
		sql = `UPDATE push_subscriptions SET last_success_at = $2, failure_count = 0 WHERE id = $1`
	}
	if _, err := q.Exec(ctx, sql, id, at); err != nil {
		return fmt.Errorf("store: record push delivery: %w", err)
	}
	return nil
}

// DeleteUserPushSubscriptions deletes every subscription of userID (the
// disable hook and account deletion) and returns how many.
func DeleteUserPushSubscriptions(ctx context.Context, q Querier, userID string) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM push_subscriptions WHERE user_id = $1`, userID)
	if err != nil {
		return 0, fmt.Errorf("store: delete user push subscriptions: %w", err)
	}
	return tag.RowsAffected(), nil
}
