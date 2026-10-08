package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// staticWrapVersion is the first byte of every blob produced by StaticProvider
// so the layout can evolve.
const staticWrapVersion byte = 1

// StaticProvider holds root keys in memory. It backs the dev key file
// provider and is handy in tests of other packages. Data keys are wrapped
// with AES-256-GCM under the current key, with the key ID as associated
// data so a blob cannot be presented under a different key ID.
type StaticProvider struct {
	current string
	aeads   map[string]cipher.AEAD
}

// NewStaticProvider builds a provider from 32-byte keys indexed by ID.
// currentID selects the wrapping key and must be present in keys. The key
// bytes are copied; callers may wipe their copies afterwards.
func NewStaticProvider(currentID string, keys map[string][]byte) (*StaticProvider, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("crypto: static provider needs at least one key")
	}
	p := &StaticProvider{current: currentID, aeads: make(map[string]cipher.AEAD, len(keys))}
	for id, k := range keys {
		if id == "" {
			return nil, fmt.Errorf("crypto: static provider key ID must not be empty")
		}
		if len(k) != DataKeySize {
			return nil, fmt.Errorf("crypto: key %q has %d bytes, want %d", id, len(k), DataKeySize)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("crypto: key %q: %w", id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("crypto: key %q: %w", id, err)
		}
		p.aeads[id] = aead
	}
	if _, ok := p.aeads[currentID]; !ok {
		return nil, fmt.Errorf("crypto: current key %q is not in the key set", currentID)
	}
	return p, nil
}

// KeyIDs returns the IDs of all held keys, in no particular order.
func (p *StaticProvider) KeyIDs() []string {
	ids := make([]string, 0, len(p.aeads))
	for id := range p.aeads {
		ids = append(ids, id)
	}
	return ids
}

// CurrentKeyID implements KeyProvider.
func (p *StaticProvider) CurrentKeyID(context.Context) (string, error) {
	return p.current, nil
}

// WrapDataKey implements KeyProvider. Output: version byte || nonce || sealed key.
func (p *StaticProvider) WrapDataKey(_ context.Context, plaintextKey []byte) (string, []byte, error) {
	if len(plaintextKey) != DataKeySize {
		return "", nil, ErrInvalidDataKey
	}
	aead := p.aeads[p.current]
	out := make([]byte, 1+aead.NonceSize(), 1+aead.NonceSize()+len(plaintextKey)+aead.Overhead())
	out[0] = staticWrapVersion
	if _, err := rand.Read(out[1:]); err != nil {
		return "", nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	nonce := out[1 : 1+aead.NonceSize()]
	out = aead.Seal(out, nonce, plaintextKey, []byte(p.current))
	return p.current, out, nil
}

// UnwrapDataKey implements KeyProvider.
func (p *StaticProvider) UnwrapDataKey(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	aead, ok := p.aeads[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, keyID)
	}
	if len(wrapped) < 1+aead.NonceSize()+aead.Overhead() || wrapped[0] != staticWrapVersion {
		return nil, ErrDecrypt
	}
	nonce := wrapped[1 : 1+aead.NonceSize()]
	key, err := aead.Open(nil, nonce, wrapped[1+aead.NonceSize():], []byte(keyID))
	if err != nil {
		return nil, ErrDecrypt
	}
	return key, nil
}
