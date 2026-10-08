package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Envelope is one encrypted record as stored in the database: the ID of the
// root key that wraps the data key, the wrapped data key, the AES-GCM nonce
// and the ciphertext (which carries the GCM tag). Fields map one-to-one onto
// the store's four columns.
type Envelope struct {
	KeyID          string
	WrappedDataKey []byte
	Nonce          []byte
	Ciphertext     []byte
}

// Encrypt seals plaintext for the record identified by aad: a fresh random
// 32-byte data key encrypts the plaintext with AES-256-GCM and a random
// nonce, then the provider wraps the data key under its current root key.
// The data key is wiped before returning.
func Encrypt(ctx context.Context, p KeyProvider, aad AAD, plaintext []byte) (Envelope, error) {
	if err := aad.Validate(); err != nil {
		return Envelope{}, err
	}
	dataKey := make([]byte, DataKeySize)
	if _, err := rand.Read(dataKey); err != nil {
		return Envelope{}, fmt.Errorf("crypto: data key: %w", err)
	}
	defer wipe(dataKey)

	aead, err := newAEAD(dataKey)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("crypto: nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad.Bytes())

	keyID, wrapped, err := p.WrapDataKey(ctx, dataKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("crypto: wrap data key: %w", err)
	}
	return Envelope{KeyID: keyID, WrappedDataKey: wrapped, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// Decrypt opens env for the record identified by aad. Any change to the AAD,
// nonce, ciphertext or wrapped key yields ErrDecrypt; a key ID the provider
// no longer holds yields ErrUnknownKeyID. The data key is wiped before
// returning.
func Decrypt(ctx context.Context, p KeyProvider, aad AAD, env Envelope) ([]byte, error) {
	if err := aad.Validate(); err != nil {
		return nil, err
	}
	dataKey, err := p.UnwrapDataKey(ctx, env.KeyID, env.WrappedDataKey)
	if err != nil {
		return nil, err
	}
	defer wipe(dataKey)
	if len(dataKey) != DataKeySize {
		return nil, ErrInvalidDataKey
	}

	aead, err := newAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	if len(env.Nonce) != aead.NonceSize() || len(env.Ciphertext) < aead.Overhead() {
		return nil, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, aad.Bytes())
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return aead, nil
}

// wipe zeroes b so key material does not linger on the heap longer than
// needed. Best effort: the runtime may have copied the slice.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
