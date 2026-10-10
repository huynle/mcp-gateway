package crypto_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

// sharedKeys lets two providers hold the same key material with a different
// current key, simulating "current" moving in the key file.
func sharedKeys(t *testing.T, ids ...string) map[string][]byte {
	t.Helper()
	keys := make(map[string][]byte, len(ids))
	for _, id := range ids {
		keys[id] = randomKey(t)
	}
	return keys
}

func TestRewrapKeepsCiphertextAndMovesToCurrentKey(t *testing.T) {
	ctx := context.Background()
	keys := sharedKeys(t, "k1", "k2")
	old, err := crypto.NewStaticProvider("k1", keys)
	if err != nil {
		t.Fatal(err)
	}
	env, err := crypto.Encrypt(ctx, old, baseAAD, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Rotation: k2 becomes current, k1 is still available for unwrapping.
	rotated, err := crypto.NewStaticProvider("k2", keys)
	if err != nil {
		t.Fatal(err)
	}
	re, err := crypto.Rewrap(ctx, rotated, env)
	if err != nil {
		t.Fatal(err)
	}
	if re.KeyID != "k2" {
		t.Errorf("KeyID after rewrap = %q, want k2", re.KeyID)
	}
	if !bytes.Equal(re.Ciphertext, env.Ciphertext) || !bytes.Equal(re.Nonce, env.Nonce) {
		t.Error("rewrap must not touch nonce or ciphertext")
	}
	if bytes.Equal(re.WrappedDataKey, env.WrappedDataKey) {
		t.Error("wrapped data key must change")
	}

	// A provider that only holds k2 decrypts the rewrapped envelope but not the old one.
	onlyNew, err := crypto.NewStaticProvider("k2", map[string][]byte{"k2": keys["k2"]})
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.Decrypt(ctx, onlyNew, baseAAD, re)
	if err != nil || string(got) != "secret" {
		t.Fatalf("decrypt rewrapped under k2: %q, %v", got, err)
	}
	if _, err := crypto.Decrypt(ctx, onlyNew, baseAAD, env); !errors.Is(err, crypto.ErrUnknownKeyID) {
		t.Errorf("old envelope under k2-only provider: want ErrUnknownKeyID, got %v", err)
	}

	// Rewrap of an envelope under an unknown key fails and does not fabricate output.
	bad := env
	bad.KeyID = "gone"
	if _, err := crypto.Rewrap(ctx, rotated, bad); !errors.Is(err, crypto.ErrUnknownKeyID) {
		t.Errorf("want ErrUnknownKeyID, got %v", err)
	}
}

func TestRewrapEachSkipsCurrentAndAppliesOthers(t *testing.T) {
	ctx := context.Background()
	keys := sharedKeys(t, "k1", "k2")
	old, _ := crypto.NewStaticProvider("k1", keys)
	rotated, _ := crypto.NewStaticProvider("k2", keys)

	e1, err := crypto.Encrypt(ctx, old, baseAAD, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	e2, err := crypto.Encrypt(ctx, rotated, baseAAD, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	e3, err := crypto.Encrypt(ctx, old, baseAAD, []byte("three"))
	if err != nil {
		t.Fatal(err)
	}

	batch := []crypto.Envelope{e1, e2, e3}
	var applied []int
	stats, err := crypto.RewrapEach(ctx, rotated, batch, func(_ context.Context, i int, updated crypto.Envelope) error {
		applied = append(applied, i)
		if updated.KeyID != "k2" {
			t.Errorf("item %d rewrapped under %q", i, updated.KeyID)
		}
		if !bytes.Equal(updated.Ciphertext, batch[i].Ciphertext) {
			t.Errorf("item %d ciphertext changed", i)
		}
		batch[i] = updated
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scanned != 3 || stats.Rewrapped != 2 || stats.Skipped != 1 {
		t.Errorf("stats = %+v, want scanned 3, rewrapped 2, skipped 1", stats)
	}
	if len(applied) != 2 || applied[0] != 0 || applied[1] != 2 {
		t.Errorf("applied indexes = %v, want [0 2]", applied)
	}
	for i, want := range []string{"one", "two", "three"} {
		got, err := crypto.Decrypt(ctx, rotated, baseAAD, batch[i])
		if err != nil || string(got) != want {
			t.Errorf("item %d: %q, %v", i, got, err)
		}
	}
}

func TestRewrapEachStopsOnApplyError(t *testing.T) {
	ctx := context.Background()
	keys := sharedKeys(t, "k1", "k2")
	old, _ := crypto.NewStaticProvider("k1", keys)
	rotated, _ := crypto.NewStaticProvider("k2", keys)
	var batch []crypto.Envelope
	for range 3 {
		e, err := crypto.Encrypt(ctx, old, baseAAD, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		batch = append(batch, e)
	}
	boom := errors.New("db down")
	calls := 0
	stats, err := crypto.RewrapEach(ctx, rotated, batch, func(context.Context, int, crypto.Envelope) error {
		calls++
		if calls == 2 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want apply error, got %v", err)
	}
	if calls != 2 {
		t.Errorf("apply called %d times, want 2 (stop at first error)", calls)
	}
	if stats.Rewrapped != 1 || stats.Scanned != 2 {
		t.Errorf("stats = %+v, want rewrapped 1, scanned 2", stats)
	}
}

func TestRewrapEachHonorsContext(t *testing.T) {
	keys := sharedKeys(t, "k1", "k2")
	old, _ := crypto.NewStaticProvider("k1", keys)
	rotated, _ := crypto.NewStaticProvider("k2", keys)
	e, err := crypto.Encrypt(context.Background(), old, baseAAD, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = crypto.RewrapEach(ctx, rotated, []crypto.Envelope{e}, func(context.Context, int, crypto.Envelope) error {
		t.Error("apply must not run after cancellation")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}
