package crypto

import (
	"context"
	"errors"
)

// DataKeySize is the length of every per-record data key (AES-256).
const DataKeySize = 32

// KeyProvider wraps and unwraps per-record data keys under a root key that
// never leaves the provider. Key IDs are opaque strings chosen by the
// provider (a file key's ID, a Vault transit key version) and are stored next
// to the ciphertext so rotation can tell old envelopes from new ones.
//
// Implementations must be safe for concurrent use and must never put key
// material into error messages or logs.
type KeyProvider interface {
	// WrapDataKey encrypts plaintextKey under the current root key and
	// returns that key's ID with the wrapped blob.
	WrapDataKey(ctx context.Context, plaintextKey []byte) (keyID string, wrapped []byte, err error)
	// UnwrapDataKey decrypts wrapped under the root key named by keyID.
	UnwrapDataKey(ctx context.Context, keyID string, wrapped []byte) ([]byte, error)
	// CurrentKeyID returns the ID WrapDataKey would use right now.
	CurrentKeyID(ctx context.Context) (string, error)
}

var (
	// ErrUnknownKeyID is returned when an envelope names a key the provider
	// does not hold (removed from the key file, below Vault's minimum
	// decryption version, ...). Such envelopes need an operator decision,
	// not a retry.
	ErrUnknownKeyID = errors.New("crypto: unknown key ID")
	// ErrDecrypt means authentication failed: wrong key, wrong associated
	// data, or tampered bytes. The cause is deliberately not distinguished.
	ErrDecrypt = errors.New("crypto: decryption failed")
	// ErrInvalidDataKey is returned when a data key is not DataKeySize bytes.
	ErrInvalidDataKey = errors.New("crypto: data key must be 32 bytes")
)
