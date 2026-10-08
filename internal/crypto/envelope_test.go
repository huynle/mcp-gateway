package crypto_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

// newStatic builds a StaticProvider holding one random key per ID; the first
// ID is the current key.
func newStatic(t *testing.T, ids ...string) *crypto.StaticProvider {
	t.Helper()
	keys := make(map[string][]byte, len(ids))
	for _, id := range ids {
		keys[id] = randomKey(t)
	}
	p, err := crypto.NewStaticProvider(ids[0], keys)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var baseAAD = crypto.AAD{UserID: "user-1", Kind: "connection", RecordID: "conn-1", App: "github"}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newStatic(t, "k1")
	plaintext := []byte(`{"access_token":"gho_secret","refresh_token":"ghr_secret"}`)

	env, err := crypto.Encrypt(ctx, p, baseAAD, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if env.KeyID != "k1" {
		t.Errorf("KeyID = %q, want k1", env.KeyID)
	}
	if len(env.Nonce) != 12 {
		t.Errorf("nonce length = %d, want 12", len(env.Nonce))
	}
	if len(env.WrappedDataKey) == 0 || len(env.Ciphertext) == 0 {
		t.Fatal("wrapped data key and ciphertext must be set")
	}
	if bytes.Contains(env.Ciphertext, []byte("gho_secret")) {
		t.Error("ciphertext leaks plaintext")
	}

	got, err := crypto.Decrypt(ctx, p, baseAAD, env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip mismatch: %q", got)
	}

	// Every record gets its own data key and nonce.
	env2, err := crypto.Encrypt(ctx, p, baseAAD, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(env.WrappedDataKey, env2.WrappedDataKey) || bytes.Equal(env.Nonce, env2.Nonce) || bytes.Equal(env.Ciphertext, env2.Ciphertext) {
		t.Error("two encryptions of the same plaintext share material")
	}
}

func TestEncryptRejectsInvalidAAD(t *testing.T) {
	p := newStatic(t, "k1")
	if _, err := crypto.Encrypt(context.Background(), p, crypto.AAD{UserID: "u"}, []byte("x")); err == nil {
		t.Error("AAD without kind/record ID must be rejected")
	}
}

func TestDecryptFailsWhenAnyAADComponentChanges(t *testing.T) {
	ctx := context.Background()
	p := newStatic(t, "k1")
	env, err := crypto.Encrypt(ctx, p, baseAAD, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]crypto.AAD{
		"user":   {UserID: "user-2", Kind: "connection", RecordID: "conn-1", App: "github"},
		"kind":   {UserID: "user-1", Kind: "approval", RecordID: "conn-1", App: "github"},
		"record": {UserID: "user-1", Kind: "connection", RecordID: "conn-2", App: "github"},
		"app":    {UserID: "user-1", Kind: "connection", RecordID: "conn-1", App: "slack"},
	}
	for name, aad := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := crypto.Decrypt(ctx, p, aad, env)
			if !errors.Is(err, crypto.ErrDecrypt) {
				t.Errorf("want ErrDecrypt, got err=%v plaintext=%q", err, got)
			}
			if got != nil {
				t.Error("plaintext returned on failure")
			}
		})
	}
	// Sanity: the unchanged AAD still works.
	if _, err := crypto.Decrypt(ctx, p, baseAAD, env); err != nil {
		t.Fatalf("control decrypt failed: %v", err)
	}
}

func TestDecryptFailsOnTamperedEnvelope(t *testing.T) {
	ctx := context.Background()
	p := newStatic(t, "k1")
	env, err := crypto.Encrypt(ctx, p, baseAAD, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 0x80
		return c
	}
	cases := map[string]crypto.Envelope{
		"ciphertext":   {KeyID: env.KeyID, WrappedDataKey: env.WrappedDataKey, Nonce: env.Nonce, Ciphertext: flip(env.Ciphertext, 0)},
		"tag":          {KeyID: env.KeyID, WrappedDataKey: env.WrappedDataKey, Nonce: env.Nonce, Ciphertext: flip(env.Ciphertext, len(env.Ciphertext)-1)},
		"nonce":        {KeyID: env.KeyID, WrappedDataKey: env.WrappedDataKey, Nonce: flip(env.Nonce, 3), Ciphertext: env.Ciphertext},
		"wrapped key":  {KeyID: env.KeyID, WrappedDataKey: flip(env.WrappedDataKey, len(env.WrappedDataKey)-1), Nonce: env.Nonce, Ciphertext: env.Ciphertext},
		"short nonce":  {KeyID: env.KeyID, WrappedDataKey: env.WrappedDataKey, Nonce: env.Nonce[:4], Ciphertext: env.Ciphertext},
		"empty cipher": {KeyID: env.KeyID, WrappedDataKey: env.WrappedDataKey, Nonce: env.Nonce, Ciphertext: nil},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := crypto.Decrypt(ctx, p, baseAAD, bad); !errors.Is(err, crypto.ErrDecrypt) {
				t.Errorf("want ErrDecrypt, got %v", err)
			}
		})
	}
	t.Run("unknown key id", func(t *testing.T) {
		bad := env
		bad.KeyID = "gone"
		if _, err := crypto.Decrypt(ctx, p, baseAAD, bad); !errors.Is(err, crypto.ErrUnknownKeyID) {
			t.Errorf("want ErrUnknownKeyID, got %v", err)
		}
	})
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	ctx := context.Background()
	p := newStatic(t, "k1")
	env, err := crypto.Encrypt(ctx, p, baseAAD, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.Decrypt(ctx, p, baseAAD, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("want empty plaintext, got %q", got)
	}
}
