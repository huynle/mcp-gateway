package crypto

import (
	"context"
	"fmt"
)

// Rewrap moves env to the provider's current root key: the data key is
// unwrapped under env.KeyID and wrapped again under the current key. Nonce
// and ciphertext are returned unchanged, so no plaintext is ever touched and
// the AAD is not needed. The data key is wiped before returning.
func Rewrap(ctx context.Context, p KeyProvider, env Envelope) (Envelope, error) {
	dataKey, err := p.UnwrapDataKey(ctx, env.KeyID, env.WrappedDataKey)
	if err != nil {
		return Envelope{}, err
	}
	defer wipe(dataKey)
	keyID, wrapped, err := p.WrapDataKey(ctx, dataKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("crypto: wrap data key: %w", err)
	}
	return Envelope{KeyID: keyID, WrappedDataKey: wrapped, Nonce: env.Nonce, Ciphertext: env.Ciphertext}, nil
}

// RewrapStats summarizes one RewrapEach call.
type RewrapStats struct {
	// Scanned counts envelopes examined, including the one whose apply failed.
	Scanned int
	// Rewrapped counts envelopes handed to apply that it accepted.
	Rewrapped int
	// Skipped counts envelopes already under the current key.
	Skipped int
}

// RewrapEach drives rotation over one batch: every envelope not already under
// the current key is rewrapped and passed to apply with its index so the
// caller can persist it (for example inside a transaction). It stops at the
// first error, from the provider, apply or ctx, and returns the stats so far.
// Callers page through their table and call RewrapEach per page.
func RewrapEach(ctx context.Context, p KeyProvider, envs []Envelope, apply func(ctx context.Context, i int, updated Envelope) error) (RewrapStats, error) {
	var stats RewrapStats
	current, err := p.CurrentKeyID(ctx)
	if err != nil {
		return stats, fmt.Errorf("crypto: current key ID: %w", err)
	}
	for i, env := range envs {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		stats.Scanned++
		if env.KeyID == current {
			stats.Skipped++
			continue
		}
		updated, err := Rewrap(ctx, p, env)
		if err != nil {
			return stats, fmt.Errorf("crypto: rewrap item %d: %w", i, err)
		}
		if err := apply(ctx, i, updated); err != nil {
			return stats, fmt.Errorf("crypto: apply item %d: %w", i, err)
		}
		stats.Rewrapped++
	}
	return stats, nil
}
