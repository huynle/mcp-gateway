package store

import (
	"context"
	"fmt"
)

type signingKeyRepo struct{ q Querier }

func (r signingKeyRepo) Create(ctx context.Context, k *SigningKey) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO signing_keys (kid, algorithm, public_key,
			private_key_id, private_wrapped_key, private_nonce, private_ciphertext, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, coalesce(nullif($8, ''), 'active'))
		RETURNING id, status, created_at`,
		k.KID, k.Algorithm, k.PublicKey,
		k.PrivateKey.KeyID, k.PrivateKey.WrappedDataKey, k.PrivateKey.Nonce, k.PrivateKey.Ciphertext, k.Status,
	).Scan(&k.ID, &k.Status, &k.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create signing key: %w", err)
	}
	return nil
}

func (r signingKeyRepo) Get(ctx context.Context, id string) (*SigningKey, error) {
	var k SigningKey
	err := r.q.QueryRow(ctx, `
		SELECT id, kid, algorithm, public_key,
			private_key_id, private_wrapped_key, private_nonce, private_ciphertext,
			status, created_at, retired_at
		FROM signing_keys WHERE id = $1`, id,
	).Scan(&k.ID, &k.KID, &k.Algorithm, &k.PublicKey,
		&k.PrivateKey.KeyID, &k.PrivateKey.WrappedDataKey, &k.PrivateKey.Nonce, &k.PrivateKey.Ciphertext,
		&k.Status, &k.CreatedAt, &k.RetiredAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &k, nil
}

type jobLockRepo struct{ q Querier }

// Upsert takes or renews the lease unconditionally; the jobs module adds the
// compare-and-set acquisition on top.
func (r jobLockRepo) Upsert(ctx context.Context, l *JobLock) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO job_locks (name, holder, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, acquired_at = now(), expires_at = EXCLUDED.expires_at
		RETURNING acquired_at`,
		l.Name, l.Holder, l.ExpiresAt,
	).Scan(&l.AcquiredAt)
	if err != nil {
		return fmt.Errorf("store: upsert job lock: %w", err)
	}
	return nil
}

func (r jobLockRepo) Get(ctx context.Context, name string) (*JobLock, error) {
	var l JobLock
	err := r.q.QueryRow(ctx, `
		SELECT name, holder, acquired_at, expires_at FROM job_locks WHERE name = $1`, name,
	).Scan(&l.Name, &l.Holder, &l.AcquiredAt, &l.ExpiresAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &l, nil
}
