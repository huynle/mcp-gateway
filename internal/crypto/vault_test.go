package crypto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

// fakeVault imitates the transit endpoints the provider uses. Ciphertexts are
// "vault:v<N>:<base64>" where the payload is the plaintext XORed with a
// per-version pad, so a ciphertext only opens under the version that made it.
type fakeVault struct {
	t       *testing.T
	token   string
	mount   string
	keyName string

	mu      sync.Mutex
	latest  int
	minDecr int
	pads    map[int]byte
	calls   []string
}

func newFakeVault(t *testing.T) (*fakeVault, *httptest.Server) {
	t.Helper()
	fv := &fakeVault{t: t, token: "s.test-token", mount: "transit", keyName: "gateway", latest: 1, minDecr: 1, pads: map[int]byte{1: 0x5a}}
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	return fv, srv
}

func (f *fakeVault) rotate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.latest++
	f.pads[f.latest] = byte(0x10 * f.latest)
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if r.Header.Get("X-Vault-Token") != f.token {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	prefix := "/v1/" + f.mount + "/"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == prefix+"keys/"+f.keyName:
		f.mu.Lock()
		defer f.mu.Unlock()
		writeVaultJSON(w, map[string]any{"data": map[string]any{"latest_version": f.latest, "min_decryption_version": f.minDecr, "type": "aes256-gcm96", "name": f.keyName}})
	case r.Method == http.MethodPost && r.URL.Path == prefix+"encrypt/"+f.keyName:
		var body struct {
			Plaintext string `json:"plaintext"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeVaultError(w, http.StatusBadRequest, "bad json")
			return
		}
		pt, err := base64.StdEncoding.DecodeString(body.Plaintext)
		if err != nil {
			writeVaultError(w, http.StatusBadRequest, "plaintext must be base64")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		writeVaultJSON(w, map[string]any{"data": map[string]any{"ciphertext": f.seal(f.latest, pt), "key_version": f.latest}})
	case r.Method == http.MethodPost && r.URL.Path == prefix+"decrypt/"+f.keyName:
		var body struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeVaultError(w, http.StatusBadRequest, "bad json")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		ver, payload, ok := strings.Cut(strings.TrimPrefix(body.Ciphertext, "vault:v"), ":")
		v, convErr := strconv.Atoi(ver)
		if !ok || convErr != nil || v < 1 || v > f.latest {
			writeVaultError(w, http.StatusBadRequest, "invalid ciphertext: no prefix")
			return
		}
		if v < f.minDecr {
			writeVaultError(w, http.StatusBadRequest, "ciphertext or signature version is disallowed by policy (too old)")
			return
		}
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			writeVaultError(w, http.StatusBadRequest, "invalid ciphertext")
			return
		}
		writeVaultJSON(w, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(f.xor(v, raw))}})
	default:
		writeVaultError(w, http.StatusNotFound, "unsupported path")
	}
}

func (f *fakeVault) seal(v int, pt []byte) string {
	return fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(f.xor(v, pt)))
}

func (f *fakeVault) xor(v int, b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ f.pads[v]
	}
	return out
}

func writeVaultJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeVaultError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}

func newVaultProvider(t *testing.T, srv *httptest.Server, fv *fakeVault) *crypto.VaultProvider {
	t.Helper()
	p, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: fv.token, Mount: fv.mount, KeyName: fv.keyName})
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
	fv.rotate()
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
	if _, err := p.UnwrapDataKey(ctx, "k1", wrapped); err == nil {
		t.Error("non-vault key ID must be rejected")
	}
	if _, err := p.UnwrapDataKey(ctx, "v1", []byte("garbage")); err == nil {
		t.Error("malformed blob must be rejected")
	}
	if _, _, err := p.WrapDataKey(ctx, dk[:8]); !errors.Is(err, crypto.ErrInvalidDataKey) {
		t.Errorf("short data key: want ErrInvalidDataKey, got %v", err)
	}

	// Operator raised min_decryption_version: v1 is gone for good.
	fv.mu.Lock()
	fv.minDecr = 2
	fv.mu.Unlock()
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
	fv.rotate()
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
	bad, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: "s.wrong-token", KeyName: fv.keyName})
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
	fv.mount = "kms"
	p, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: fv.token, Mount: "kms", KeyName: fv.keyName})
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
	fv.keyName = "other" // key no longer exists under the configured name
	if err := p.Ready(context.Background()); err == nil {
		t.Error("missing key must fail readiness")
	}
}
