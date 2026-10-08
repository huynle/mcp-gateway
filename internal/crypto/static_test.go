package crypto_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewStaticProviderValidation(t *testing.T) {
	k := randomKey(t)
	if _, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": k}); err != nil {
		t.Fatalf("valid provider rejected: %v", err)
	}
	if _, err := crypto.NewStaticProvider("missing", map[string][]byte{"k1": k}); err == nil {
		t.Error("current key not in set must be rejected")
	}
	if _, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": k[:16]}); err == nil {
		t.Error("16-byte key must be rejected")
	}
	if _, err := crypto.NewStaticProvider("", map[string][]byte{"": k}); err == nil {
		t.Error("empty key ID must be rejected")
	}
	if _, err := crypto.NewStaticProvider("k1", nil); err == nil {
		t.Error("empty key set must be rejected")
	}
}

func TestStaticProviderWrapUnwrapRoundTrip(t *testing.T) {
	ctx := context.Background()
	p, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": randomKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	var kp crypto.KeyProvider = p // compile-time interface check

	cur, err := kp.CurrentKeyID(ctx)
	if err != nil || cur != "k1" {
		t.Fatalf("CurrentKeyID = %q, %v", cur, err)
	}
	dk := randomKey(t)
	id, wrapped, err := kp.WrapDataKey(ctx, dk)
	if err != nil {
		t.Fatal(err)
	}
	if id != "k1" {
		t.Errorf("wrap key ID = %q, want k1", id)
	}
	if bytes.Contains(wrapped, dk) {
		t.Error("wrapped blob contains the plaintext data key")
	}
	got, err := kp.UnwrapDataKey(ctx, id, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dk) {
		t.Error("unwrapped key differs from original")
	}

	// Two wraps of the same key must differ (random nonce).
	_, wrapped2, err := kp.WrapDataKey(ctx, dk)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrapped, wrapped2) {
		t.Error("wrap is deterministic; nonce reuse")
	}

	if _, err := kp.UnwrapDataKey(ctx, "nope", wrapped); !errors.Is(err, crypto.ErrUnknownKeyID) {
		t.Errorf("unknown key ID: got %v, want ErrUnknownKeyID", err)
	}
	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := kp.UnwrapDataKey(ctx, id, tampered); err == nil {
		t.Error("tampered wrapped key must fail to unwrap")
	}
	if _, err := kp.UnwrapDataKey(ctx, id, wrapped[:5]); err == nil {
		t.Error("truncated wrapped key must fail to unwrap")
	}
	if _, _, err := kp.WrapDataKey(ctx, dk[:8]); err == nil {
		t.Error("data key of wrong length must be rejected")
	}
}

func TestStaticProviderUnwrapNeedsMatchingKeyID(t *testing.T) {
	ctx := context.Background()
	keys := map[string][]byte{"k1": randomKey(t), "k2": randomKey(t)}
	p, err := crypto.NewStaticProvider("k1", keys)
	if err != nil {
		t.Fatal(err)
	}
	_, wrapped, err := p.WrapDataKey(ctx, randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UnwrapDataKey(ctx, "k2", wrapped); err == nil {
		t.Error("unwrapping under the wrong key must fail")
	}
}
