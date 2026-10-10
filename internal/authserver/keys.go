package authserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Signing keys for the gateway's own access tokens: ES256 (P-256) key
// pairs in the signing_keys table, the private half envelope-encrypted
// under AAD {kind: signing_key, record: kid} so a row cannot be moved to
// another kid. One key is active (it signs); keys retired by a rotation
// keep verifying for a grace period, then the rotation job deletes them.
// Every replica reads the same table, caches what it loaded for a short
// while, and reloads on an unknown kid, so a key created on one replica
// is used by the others within the cache lifetime.
const (
	// SigningAlgorithm is the only JWS algorithm minted and accepted.
	SigningAlgorithm = jose.ES256
	// SigningKeyKind is the AAD kind of a signing key's private half.
	SigningKeyKind = "signing_key"
	// keyCacheTTL bounds how stale a replica's view of the active key and
	// the key set may be.
	keyCacheTTL = time.Minute
	// reloadBackoff bounds how often an unknown kid triggers a reload,
	// so a flood of forged tokens does not become a flood of queries.
	reloadBackoff = 10 * time.Second
)

// ErrUnknownKey reports a kid no live key matches.
var ErrUnknownKey = errors.New("authserver: unknown signing key")

// KeysOptions configures NewKeys.
type KeysOptions struct {
	// Grace is how long a retired key still verifies (DefaultKeyGrace).
	Grace time.Duration
	// Log defaults to slog.Default().
	Log *slog.Logger
}

// SigningKey is a loaded key: the row's metadata and the decoded pair
// (Private is nil for retired keys, which never sign again).
type SigningKey struct {
	KID       string
	Algorithm jose.SignatureAlgorithm
	Public    *ecdsa.PublicKey
	Private   *ecdsa.PrivateKey
	CreatedAt time.Time
	RetiredAt *time.Time
}

// Keys loads, creates, rotates and caches signing keys.
type Keys struct {
	st    Store
	kp    crypto.KeyProvider
	grace time.Duration
	log   *slog.Logger
	now   func() time.Time

	mu         sync.Mutex
	byKID      map[string]*SigningKey
	active     *SigningKey
	loadedAt   time.Time
	lastReload time.Time
}

// NewKeys builds the manager over the store and the envelope-encryption
// provider.
func NewKeys(st Store, kp crypto.KeyProvider, opts KeysOptions) *Keys {
	if opts.Grace <= 0 {
		opts.Grace = DefaultKeyGrace
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Keys{st: st, kp: kp, grace: opts.Grace, log: opts.Log, now: func() time.Time { return time.Now().UTC() }, byKID: map[string]*SigningKey{}}
}

// SetClock replaces the time source (tests).
func (k *Keys) SetClock(now func() time.Time) { k.now = now }

// Current returns the active signing key, creating the first one when the
// table is empty.
func (k *Keys) Current(ctx context.Context) (*SigningKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if k.active != nil && k.active.Private != nil && now.Sub(k.loadedAt) < keyCacheTTL {
		return k.active, nil
	}
	if err := k.reloadLocked(ctx); err != nil {
		return nil, err
	}
	if k.active != nil {
		return k.active, nil
	}
	if err := k.createLocked(ctx); err != nil {
		return nil, err
	}
	return k.active, nil
}

// Verifier returns the public key for kid, reloading the set once when the
// kid is not cached. Retired keys past the grace period are refused.
func (k *Keys) Verifier(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	key, ok := k.byKID[kid]
	if !ok && now.Sub(k.lastReload) >= reloadBackoff {
		if err := k.reloadLocked(ctx); err != nil {
			return nil, err
		}
		key, ok = k.byKID[kid]
	}
	if !ok || key.Algorithm != SigningAlgorithm {
		return nil, ErrUnknownKey
	}
	if key.RetiredAt != nil && now.Sub(*key.RetiredAt) > k.grace {
		return nil, ErrUnknownKey
	}
	return key.Public, nil
}

// JWKS returns the public keys a verifier may need: the active key and
// every retired key still inside its grace period.
func (k *Keys) JWKS(ctx context.Context) (jose.JSONWebKeySet, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.reloadLocked(ctx); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	if k.active == nil {
		if err := k.createLocked(ctx); err != nil {
			return jose.JSONWebKeySet{}, err
		}
	}
	now := k.now()
	var set jose.JSONWebKeySet
	for _, key := range k.byKID {
		if key.RetiredAt != nil && now.Sub(*key.RetiredAt) > k.grace {
			continue
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: key.Public, KeyID: key.KID, Algorithm: string(key.Algorithm), Use: "sig"})
	}
	// Active key first, then by age, so the document is stable.
	sortKeys(set.Keys, k.active.KID)
	return set, nil
}

// Rotate creates a new active key, retires the previous one (it keeps
// verifying for the grace period) and deletes keys retired longer ago.
func (k *Keys) Rotate(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.createLocked(ctx); err != nil {
		return err
	}
	now := k.now()
	err := k.st.Bypass(ctx, func(tx Tx) error {
		if _, err := tx.RetireSigningKeys(ctx, k.active.KID, now); err != nil {
			return err
		}
		deleted, err := tx.DeleteRetiredSigningKeys(ctx, now.Add(-k.grace))
		if err != nil {
			return err
		}
		if deleted > 0 {
			k.log.Info("retired signing keys deleted", "event", "authserver.keys_deleted", "count", deleted)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("authserver: retire keys: %w", err)
	}
	return k.reloadLocked(ctx)
}

// RotateIfDue rotates when the active key is older than period (or there
// is none) and always sweeps keys retired past the grace period. It
// reports whether a rotation happened.
func (k *Keys) RotateIfDue(ctx context.Context, period time.Duration) (bool, error) {
	cur, err := k.Current(ctx)
	if err != nil {
		return false, err
	}
	if k.now().Sub(cur.CreatedAt) < period {
		k.mu.Lock()
		defer k.mu.Unlock()
		now := k.now()
		err := k.st.Bypass(ctx, func(tx Tx) error {
			_, err := tx.DeleteRetiredSigningKeys(ctx, now.Add(-k.grace))
			return err
		})
		return false, err
	}
	if err := k.Rotate(ctx); err != nil {
		return false, err
	}
	k.log.Info("signing key rotated", "event", "authserver.key_rotated", "kid", k.active.KID, "previous", cur.KID)
	return true, nil
}

// reloadLocked replaces the cache with the table's contents. Called with
// the lock held.
func (k *Keys) reloadLocked(ctx context.Context) error {
	var rows []store.SigningKey
	err := k.st.Bypass(ctx, func(tx Tx) error {
		var err error
		rows, err = tx.ListSigningKeys(ctx)
		return err
	})
	if err != nil {
		return fmt.Errorf("authserver: load signing keys: %w", err)
	}
	now := k.now()
	k.lastReload = now
	byKID := make(map[string]*SigningKey, len(rows))
	var active *SigningKey
	for _, row := range rows {
		key, err := k.decode(ctx, row)
		if err != nil {
			// A key that does not decrypt (rotated master key, tampered
			// row) must not stop the others from working; it is logged
			// and skipped, and never signs.
			k.log.Error("signing key unusable", "event", "authserver.key_unusable", "kid", row.KID, "error", observability.RedactError(err))
			continue
		}
		byKID[key.KID] = key
		if row.Status == store.SigningKeyActive && key.Private != nil && (active == nil || key.CreatedAt.After(active.CreatedAt)) {
			active = key
		}
	}
	k.byKID, k.active, k.loadedAt = byKID, active, now
	return nil
}

// createLocked generates a new key pair, stores it and makes it the
// active key in the cache. Called with the lock held.
func (k *Keys) createLocked(ctx context.Context) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("authserver: generate key: %w", err)
	}
	kidBytes := make([]byte, 12)
	if _, err := rand.Read(kidBytes); err != nil {
		return fmt.Errorf("authserver: kid: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(kidBytes)
	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("authserver: encode public key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("authserver: encode private key: %w", err)
	}
	env, err := crypto.Encrypt(ctx, k.kp, crypto.AAD{Kind: SigningKeyKind, RecordID: kid}, der)
	for i := range der {
		der[i] = 0
	}
	if err != nil {
		return fmt.Errorf("authserver: encrypt private key: %w", err)
	}
	row := &store.SigningKey{KID: kid, Algorithm: string(SigningAlgorithm), PublicKey: pub, PrivateKey: store.Encrypted(env), Status: store.SigningKeyActive}
	err = k.st.Bypass(ctx, func(tx Tx) error { return tx.CreateSigningKey(ctx, row) })
	if err != nil {
		return fmt.Errorf("authserver: store signing key: %w", err)
	}
	key := &SigningKey{KID: kid, Algorithm: SigningAlgorithm, Public: &priv.PublicKey, Private: priv, CreatedAt: row.CreatedAt}
	if key.CreatedAt.IsZero() {
		key.CreatedAt = k.now()
	}
	k.byKID[kid] = key
	k.active = key
	k.loadedAt = k.now()
	k.log.Info("signing key created", "event", "authserver.key_created", "kid", kid, "algorithm", string(SigningAlgorithm))
	return nil
}

// decode turns a row into a usable key: the public half always, the
// private half (decrypted under the kid's AAD) only for active keys.
func (k *Keys) decode(ctx context.Context, row store.SigningKey) (*SigningKey, error) {
	if row.Algorithm != string(SigningAlgorithm) {
		return nil, fmt.Errorf("unsupported algorithm %q", row.Algorithm)
	}
	pubAny, err := x509.ParsePKIXPublicKey(row.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	key := &SigningKey{KID: row.KID, Algorithm: SigningAlgorithm, Public: pub, CreatedAt: row.CreatedAt, RetiredAt: row.RetiredAt}
	if row.Status != store.SigningKeyActive {
		return key, nil
	}
	der, err := crypto.Decrypt(ctx, k.kp, crypto.AAD{Kind: SigningKeyKind, RecordID: row.KID}, crypto.Envelope(row.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(der)
	for i := range der {
		der[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	priv, ok := privAny.(*ecdsa.PrivateKey)
	if !ok || !priv.PublicKey.Equal(pub) {
		return nil, errors.New("private key does not match the public key")
	}
	key.Private = priv
	return key, nil
}

// sortKeys puts activeKID first and the rest by kid.
func sortKeys(keys []jose.JSONWebKey, activeKID string) {
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0; j-- {
			a, b := keys[j-1], keys[j]
			if a.KeyID == activeKID || (b.KeyID != activeKID && a.KeyID <= b.KeyID) {
				break
			}
			keys[j-1], keys[j] = b, a
		}
	}
}
