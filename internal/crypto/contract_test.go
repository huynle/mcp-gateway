package crypto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/crypto/cryptotest"
)

// switchingProvider stands in for "edit the key file and restart": Rotate
// loads a new file with a different current key into the same handle.
type switchingProvider struct {
	inner atomic.Pointer[crypto.StaticProvider]
}

func (s *switchingProvider) WrapDataKey(ctx context.Context, k []byte) (string, []byte, error) {
	return s.inner.Load().WrapDataKey(ctx, k)
}

func (s *switchingProvider) UnwrapDataKey(ctx context.Context, id string, w []byte) ([]byte, error) {
	return s.inner.Load().UnwrapDataKey(ctx, id, w)
}

func (s *switchingProvider) CurrentKeyID(ctx context.Context) (string, error) {
	return s.inner.Load().CurrentKeyID(ctx)
}

func TestFileProviderContract(t *testing.T) {
	keys := sharedKeys(t, "2026-01", "2026-07")
	first, err := crypto.LoadKeyFile(writeKeyFile(t, "2026-01", keys))
	if err != nil {
		t.Fatal(err)
	}
	sp := &switchingProvider{}
	sp.inner.Store(first)
	cryptotest.ProviderContract(t, cryptotest.Harness{
		Provider: sp,
		Rotate: func(t *testing.T) {
			second, err := crypto.LoadKeyFile(writeKeyFile(t, "2026-07", keys))
			if err != nil {
				t.Fatal(err)
			}
			sp.inner.Store(second)
		},
	})
}

func TestStaticProviderContract(t *testing.T) {
	cryptotest.ProviderContract(t, cryptotest.Harness{Provider: newStatic(t, "only")})
}

// TestVaultProviderContract runs the contract against a real Vault transit
// engine. It is skipped unless GATEWAY_VAULT_ADDR is set. It creates (if
// missing) and rotates the key named by GATEWAY_VAULT_TRANSIT_KEY, default
// "mcp-gateway-contract-test", under GATEWAY_VAULT_MOUNT (default transit),
// so point it at a dev Vault, never a production key.
func TestVaultProviderContract(t *testing.T) {
	addr := os.Getenv("GATEWAY_VAULT_ADDR")
	if addr == "" {
		t.Skip("GATEWAY_VAULT_ADDR is unset; skipping Vault contract test")
	}
	token := os.Getenv("GATEWAY_VAULT_TOKEN")
	keyName := os.Getenv("GATEWAY_VAULT_TRANSIT_KEY")
	if keyName == "" {
		keyName = "mcp-gateway-contract-test"
	}
	mount := os.Getenv("GATEWAY_VAULT_MOUNT")
	if mount == "" {
		mount = "transit"
	}
	admin := func(t *testing.T, path string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		u := strings.TrimSuffix(addr, "/") + "/v1/" + mount + "/" + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("vault %s: %v", path, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			t.Fatalf("vault %s: HTTP %d: %s", path, resp.StatusCode, body)
		}
	}
	admin(t, "keys/"+keyName) // idempotent create

	p, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: addr, Token: token, Mount: mount, KeyName: keyName})
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.ReadinessCheck(p)(context.Background()); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	cryptotest.ProviderContract(t, cryptotest.Harness{
		Provider: p,
		Rotate:   func(t *testing.T) { admin(t, "keys/"+keyName+"/rotate") },
	})
}

// captureHandler records every slog record, fully rendered, so tests can
// grep for secrets.
type captureHandler struct {
	mu    sync.Mutex
	lines []string
	attrs []slog.Attr
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	for _, a := range h.attrs {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
	}
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, b.String())
	return nil
}

func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &captureHandler{lines: h.lines, attrs: append(append([]slog.Attr{}, h.attrs...), attrs...)}
}

func (h *captureHandler) WithGroup(string) slog.Handler { return h }

func TestNoKeyMaterialInLogsOrErrors(t *testing.T) {
	ctx := context.Background()
	fv, srv := newFakeVault(t)
	cap := &captureHandler{}
	p, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: fv.token, KeyName: fv.keyName, Logger: slog.New(cap)})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("super-secret-refresh-token-" + hex.EncodeToString(randomKey(t)[:6]))
	env, err := crypto.Encrypt(ctx, p, baseAAD, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := p.UnwrapDataKey(ctx, env.KeyID, env.WrappedDataKey) // the data key, for the leak list
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Decrypt(ctx, p, baseAAD, env); err != nil {
		t.Fatal(err)
	}
	fv.rotate()
	if _, err := crypto.Rewrap(ctx, p, env); err != nil {
		t.Fatal(err)
	}
	// Provoke errors too: they must not carry secrets either.
	var errs []error
	bad := env
	bad.KeyID = "v9"
	_, e1 := crypto.Decrypt(ctx, p, baseAAD, bad)
	bad = env
	bad.WrappedDataKey = bytes.Clone(env.WrappedDataKey)
	bad.WrappedDataKey[len(bad.WrappedDataKey)-1] ^= 1
	_, e2 := crypto.Decrypt(ctx, p, baseAAD, bad)
	wrongAAD := baseAAD
	wrongAAD.App = "x"
	_, e3 := crypto.Decrypt(ctx, p, wrongAAD, env)
	fv.mu.Lock()
	fv.token = "rotated-token"
	fv.mu.Unlock()
	_, _, e4 := p.WrapDataKey(ctx, dk)
	errs = append(errs, e1, e2, e3, e4)

	if len(cap.lines) == 0 {
		t.Fatal("expected the provider to log something at debug level")
	}
	secrets := map[string][]byte{"data key": dk, "plaintext": plaintext, "token": []byte(fv.token), "old token": []byte("s.test-token"), "wrapped": env.WrappedDataKey}
	forms := func(b []byte) []string {
		return []string{string(b), base64.StdEncoding.EncodeToString(b), hex.EncodeToString(b)}
	}
	for name, sec := range secrets {
		for _, form := range forms(sec) {
			for _, line := range cap.lines {
				if strings.Contains(line, form) {
					t.Errorf("log line leaks %s: %q", name, line)
				}
			}
			for _, err := range errs {
				if err != nil && strings.Contains(err.Error(), form) {
					t.Errorf("error leaks %s: %v", name, err)
				}
			}
		}
	}
	for i, err := range errs {
		if err == nil {
			t.Errorf("provoked error %d did not fail", i)
		}
	}
}
