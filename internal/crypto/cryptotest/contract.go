// Package cryptotest holds the KeyProvider contract suite. Every provider
// implementation (file, Vault, and the cloud KMS providers that follow) must
// pass ProviderContract so callers can treat them interchangeably.
package cryptotest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

// Harness describes the provider under test.
type Harness struct {
	// Provider is the implementation being checked.
	Provider crypto.KeyProvider
	// Rotate makes a new root key current (edit the key file and reload,
	// `transit/keys/<name>/rotate`, ...). Optional: rotation checks are
	// skipped when nil.
	Rotate func(t *testing.T)
}

// ProviderContract runs the behavioral contract against h.Provider.
func ProviderContract(t *testing.T, h Harness) {
	t.Helper()
	if h.Provider == nil {
		t.Fatal("cryptotest: Harness.Provider is nil")
	}
	ctx := context.Background()
	p := h.Provider
	leak := &leakDetector{}

	t.Run("current key id is stable and non-empty", func(t *testing.T) {
		a, err := p.CurrentKeyID(ctx)
		if err != nil || a == "" {
			t.Fatalf("CurrentKeyID = %q, %v", a, err)
		}
		b, err := p.CurrentKeyID(ctx)
		if err != nil || b != a {
			t.Fatalf("second CurrentKeyID = %q, %v; want %q", b, err, a)
		}
	})

	t.Run("wrap and unwrap round trip", func(t *testing.T) {
		dk := randomKey(t)
		leak.track(dk)
		id, wrapped, err := p.WrapDataKey(ctx, dk)
		if err != nil {
			t.Fatal(err)
		}
		cur, _ := p.CurrentKeyID(ctx)
		if id != cur {
			t.Errorf("wrap key ID %q != current %q", id, cur)
		}
		if len(wrapped) == 0 {
			t.Fatal("empty wrapped blob")
		}
		if leak.in(string(wrapped)) {
			t.Error("wrapped blob contains the data key")
		}
		got, err := p.UnwrapDataKey(ctx, id, wrapped)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, dk) {
			t.Error("unwrap mismatch")
		}
		_, again, err := p.WrapDataKey(ctx, dk)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(again, wrapped) {
			t.Error("wrapping the same key twice produced identical blobs")
		}
	})

	t.Run("rejects wrong-length data keys", func(t *testing.T) {
		for _, n := range []int{0, 16, 31, 33, 64} {
			k := make([]byte, n)
			if _, _, err := p.WrapDataKey(ctx, k); !errors.Is(err, crypto.ErrInvalidDataKey) {
				t.Errorf("len %d: want ErrInvalidDataKey, got %v", n, err)
			}
		}
	})

	t.Run("unknown key id", func(t *testing.T) {
		dk := randomKey(t)
		leak.track(dk)
		_, wrapped, err := p.WrapDataKey(ctx, dk)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.UnwrapDataKey(ctx, "cryptotest-no-such-key", wrapped)
		if !errors.Is(err, crypto.ErrUnknownKeyID) {
			t.Errorf("want ErrUnknownKeyID, got %v", err)
		}
		if got != nil {
			t.Error("plaintext returned with error")
		}
		leak.check(t, err)
	})

	t.Run("tampered or malformed blobs fail closed", func(t *testing.T) {
		dk := randomKey(t)
		leak.track(dk)
		id, wrapped, err := p.WrapDataKey(ctx, dk)
		if err != nil {
			t.Fatal(err)
		}
		cases := map[string][]byte{
			"empty":     {},
			"garbage":   []byte("not a wrapped key"),
			"truncated": wrapped[:len(wrapped)/2],
		}
		if n := len(wrapped); n > 0 {
			flipped := bytes.Clone(wrapped)
			flipped[n-1] ^= 0x01
			cases["last byte flipped"] = flipped
		}
		for name, blob := range cases {
			got, err := p.UnwrapDataKey(ctx, id, blob)
			if err == nil {
				t.Errorf("%s: unwrap succeeded", name)
			}
			if got != nil && bytes.Equal(got, dk) {
				t.Errorf("%s: returned the real key", name)
			}
			leak.check(t, err)
		}
	})

	t.Run("envelope round trip and AAD binding", func(t *testing.T) {
		aad := crypto.AAD{UserID: "u", Kind: "contract", RecordID: "r", App: "app"}
		secret := []byte("cryptotest-plaintext-" + hex.EncodeToString(randomKey(t)[:8]))
		leak.track(secret)
		env, err := crypto.Encrypt(ctx, p, aad, secret)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crypto.Decrypt(ctx, p, aad, env)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("round trip: %v", err)
		}
		other := aad
		other.RecordID = "r2"
		if _, err := crypto.Decrypt(ctx, p, other, env); !errors.Is(err, crypto.ErrDecrypt) {
			t.Errorf("AAD mismatch: want ErrDecrypt, got %v", err)
		}
	})

	t.Run("concurrent use", func(t *testing.T) {
		const workers = 8
		var wg sync.WaitGroup
		errs := make(chan error, workers*2)
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dk := make([]byte, crypto.DataKeySize)
				if _, err := rand.Read(dk); err != nil {
					errs <- err
					return
				}
				id, wrapped, err := p.WrapDataKey(ctx, dk)
				if err != nil {
					errs <- err
					return
				}
				got, err := p.UnwrapDataKey(ctx, id, wrapped)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, dk) {
					errs <- errors.New("concurrent unwrap mismatch")
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})

	t.Run("rotation", func(t *testing.T) {
		if h.Rotate == nil {
			t.Skip("harness has no Rotate")
		}
		aad := crypto.AAD{Kind: "contract", RecordID: "rot"}
		env, err := crypto.Encrypt(ctx, p, aad, []byte("before rotation"))
		if err != nil {
			t.Fatal(err)
		}
		before := env.KeyID
		h.Rotate(t)
		after, err := p.CurrentKeyID(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if after == before {
			t.Fatalf("CurrentKeyID %q did not change after Rotate", after)
		}
		if got, err := crypto.Decrypt(ctx, p, aad, env); err != nil || string(got) != "before rotation" {
			t.Fatalf("old envelope after rotation: %q, %v", got, err)
		}
		re, err := crypto.Rewrap(ctx, p, env)
		if err != nil {
			t.Fatal(err)
		}
		if re.KeyID != after {
			t.Errorf("rewrapped KeyID = %q, want %q", re.KeyID, after)
		}
		if !bytes.Equal(re.Ciphertext, env.Ciphertext) || !bytes.Equal(re.Nonce, env.Nonce) {
			t.Error("rewrap changed nonce or ciphertext")
		}
		if got, err := crypto.Decrypt(ctx, p, aad, re); err != nil || string(got) != "before rotation" {
			t.Fatalf("rewrapped envelope: %q, %v", got, err)
		}
		if _, err := p.UnwrapDataKey(ctx, before, re.WrappedDataKey); err == nil {
			t.Error("rewrapped blob must not unwrap under the old key ID")
		}
	})
}

// leakDetector remembers secrets handed to the provider and checks that
// error strings never contain them in raw, base64 or hex form.
type leakDetector struct {
	mu      sync.Mutex
	secrets []string
}

func (l *leakDetector) track(b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secrets = append(l.secrets, string(b), base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b), base64.URLEncoding.EncodeToString(b), hex.EncodeToString(b))
}

func (l *leakDetector) in(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, sec := range l.secrets {
		if sec != "" && strings.Contains(s, sec) {
			return true
		}
	}
	return false
}

func (l *leakDetector) check(t *testing.T, err error) {
	t.Helper()
	if err != nil && l.in(err.Error()) {
		t.Errorf("error message contains key material: %v", err)
	}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, crypto.DataKeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}
