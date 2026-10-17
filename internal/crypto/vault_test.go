package crypto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/crypto/cryptotest"
)

// fakeVault is the shared transit test double (cryptotest.FakeVault).
type fakeVault = cryptotest.FakeVault

func newFakeVault(t *testing.T) (*fakeVault, *httptest.Server) {
	t.Helper()
	return cryptotest.NewFakeVault(t)
}

func newVaultProvider(t *testing.T, srv *httptest.Server, fv *fakeVault) *crypto.VaultProvider {
	t.Helper()
	p, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: fv.Token(), Mount: fv.Mount(), KeyName: fv.KeyName()})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewVaultProviderValidation(t *testing.T) {
	cases := map[string]crypto.VaultConfig{
		"no addr":    {Token: "t", KeyName: "k"},
		"bad scheme": {Addr: "ftp://vault", Token: "t", KeyName: "k"},
		"no token":   {Addr: "http://vault:8200", KeyName: "k"},
		"no key":     {Addr: "http://vault:8200", Token: "t"},
		"key slash":  {Addr: "http://vault:8200", Token: "t", KeyName: "a/b"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := crypto.NewVaultProvider(cfg); err == nil {
				t.Error("expected error")
			} else if strings.Contains(err.Error(), "t") && strings.Contains(err.Error(), "token: t") {
				t.Errorf("error leaks token: %v", err)
			}
		})
	}
	p, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: "http://vault:8200/", Token: "t", KeyName: "k"})
	if err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}
	var _ crypto.KeyProvider = p
}

func TestVaultProviderWrapUnwrapAndVersions(t *testing.T) {
	ctx := context.Background()
	fv, srv := newFakeVault(t)
	p := newVaultProvider(t, srv, fv)

	if id, err := p.CurrentKeyID(ctx); err != nil || id != "v1" {
		t.Fatalf("CurrentKeyID = %q, %v; want v1", id, err)
	}
	dk := randomKey(t)
	id, wrapped, err := p.WrapDataKey(ctx, dk)
	if err != nil {
		t.Fatal(err)
	}
	if id != "v1" {
		t.Errorf("wrap key ID = %q, want v1", id)
	}
	if !bytes.HasPrefix(wrapped, []byte("vault:v1:")) {
		t.Errorf("wrapped = %q, want vault:v1: prefix", wrapped)
	}
	if bytes.Contains(wrapped, []byte(base64.StdEncoding.EncodeToString(dk))) {
		t.Error("wrapped blob carries the plaintext key")
	}
	got, err := p.UnwrapDataKey(ctx, "v1", wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dk) {
		t.Error("unwrap mismatch")
	}

	// Rotation on the Vault side: new wraps use v2, old blobs still open.
	fv.Rotate()
	if id, err := p.CurrentKeyID(ctx); err != nil || id != "v2" {
		t.Fatalf("CurrentKeyID after rotate = %q, %v; want v2", id, err)
	}
	id2, wrapped2, err := p.WrapDataKey(ctx, dk)
	if err != nil || id2 != "v2" {
		t.Fatalf("wrap after rotate: id=%q err=%v", id2, err)
	}
	if got, err := p.UnwrapDataKey(ctx, "v1", wrapped); err != nil || !bytes.Equal(got, dk) {
		t.Errorf("v1 blob after rotation: %v", err)
	}
	if got, err := p.UnwrapDataKey(ctx, "v2", wrapped2); err != nil || !bytes.Equal(got, dk) {
		t.Errorf("v2 blob: %v", err)
	}

	// Key ID and ciphertext version must agree.
	if _, err := p.UnwrapDataKey(ctx, "v2", wrapped); err == nil {
		t.Error("v1 blob presented as v2 must be rejected")
	}
	if _, err := p.UnwrapDataKey(ctx, "k1", wrapped); !errors.Is(err, crypto.ErrUnknownKeyID) {
		t.Errorf("non-vault key ID: want ErrUnknownKeyID (operator action), got %v", err)
	}
	if _, err := p.UnwrapDataKey(ctx, "v2", wrapped); !errors.Is(err, crypto.ErrDecrypt) {
		t.Errorf("version mismatch: want ErrDecrypt (corruption), got %v", err)
	}
	if _, err := p.UnwrapDataKey(ctx, "v1", []byte("garbage")); err == nil {
		t.Error("malformed blob must be rejected")
	}
	if _, _, err := p.WrapDataKey(ctx, dk[:8]); !errors.Is(err, crypto.ErrInvalidDataKey) {
		t.Errorf("short data key: want ErrInvalidDataKey, got %v", err)
	}

	// Operator raised min_decryption_version: v1 is gone for good.
	fv.SetMinDecryptionVersion(2)
	if _, err := p.UnwrapDataKey(ctx, "v1", wrapped); !errors.Is(err, crypto.ErrUnknownKeyID) {
		t.Errorf("version below min_decryption_version: want ErrUnknownKeyID, got %v", err)
	}
}

func TestVaultProviderEnvelopeRoundTripAndRewrap(t *testing.T) {
	ctx := context.Background()
	fv, srv := newFakeVault(t)
	p := newVaultProvider(t, srv, fv)
	env, err := crypto.Encrypt(ctx, p, baseAAD, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	fv.Rotate()
	re, err := crypto.Rewrap(ctx, p, env)
	if err != nil {
		t.Fatal(err)
	}
	if re.KeyID != "v2" || !bytes.Equal(re.Ciphertext, env.Ciphertext) {
		t.Errorf("rewrap: KeyID=%q", re.KeyID)
	}
	got, err := crypto.Decrypt(ctx, p, baseAAD, re)
	if err != nil || string(got) != "secret" {
		t.Fatalf("decrypt after rewrap: %q, %v", got, err)
	}
}

func TestVaultProviderErrorsDoNotLeakTokenOrKeys(t *testing.T) {
	ctx := context.Background()
	fv, srv := newFakeVault(t)
	bad, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: "s.wrong-token", KeyName: fv.KeyName()})
	if err != nil {
		t.Fatal(err)
	}
	dk := randomKey(t)
	_, _, err = bad.WrapDataKey(ctx, dk)
	if err == nil {
		t.Fatal("expected permission error")
	}
	msg := err.Error()
	for _, secret := range []string{"s.wrong-token", base64.StdEncoding.EncodeToString(dk)} {
		if strings.Contains(msg, secret) {
			t.Errorf("error leaks secret: %v", err)
		}
	}
	if !strings.Contains(msg, "403") {
		t.Errorf("error should carry the HTTP status for operators: %v", err)
	}

	// Unreachable server: the error names the operation, not the token.
	srv.Close()
	if _, err := bad.CurrentKeyID(ctx); err == nil || strings.Contains(err.Error(), "s.wrong-token") {
		t.Errorf("unreachable: %v", err)
	}
}

func TestVaultProviderHonorsContextAndMount(t *testing.T) {
	fv, srv := newFakeVault(t)
	fv.SetMount("kms")
	p, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: fv.Token(), Mount: "kms", KeyName: fv.KeyName()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.CurrentKeyID(context.Background()); err != nil {
		t.Fatalf("custom mount: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.CurrentKeyID(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}

func TestVaultProviderReady(t *testing.T) {
	fv, srv := newFakeVault(t)
	p := newVaultProvider(t, srv, fv)
	if err := p.Ready(context.Background()); err != nil {
		t.Fatalf("ready: %v", err)
	}
	fv.SetKeyName("other") // key no longer exists under the configured name
	if err := p.Ready(context.Background()); err == nil {
		t.Error("missing key must fail readiness")
	}
}
