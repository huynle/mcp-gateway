package crypto_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestNewProviderFromEnvFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := crypto.GenerateKeyFile(path, "dev-1"); err != nil {
		t.Fatal(err)
	}
	p, err := crypto.NewProviderFromEnv(envFrom(map[string]string{"GATEWAY_KEY_PROVIDER": "file", "GATEWAY_KEY_FILE": path}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(*crypto.StaticProvider); !ok {
		t.Fatalf("got %T, want *StaticProvider", p)
	}
	if id, _ := p.CurrentKeyID(ctx); id != "dev-1" {
		t.Errorf("current = %q", id)
	}

	// Unset provider defaults to file so local runs need only the file path.
	p, err = crypto.NewProviderFromEnv(envFrom(map[string]string{"GATEWAY_KEY_FILE": path}))
	if err != nil {
		t.Fatalf("default provider: %v", err)
	}
	if _, ok := p.(*crypto.StaticProvider); !ok {
		t.Fatalf("default: got %T, want *StaticProvider", p)
	}

	if _, err := crypto.NewProviderFromEnv(envFrom(map[string]string{"GATEWAY_KEY_PROVIDER": "file"})); err == nil || !strings.Contains(err.Error(), "GATEWAY_KEY_FILE") {
		t.Errorf("missing GATEWAY_KEY_FILE must be named in the error, got %v", err)
	}
	if _, err := crypto.NewProviderFromEnv(envFrom(map[string]string{"GATEWAY_KEY_PROVIDER": "file", "GATEWAY_KEY_FILE": filepath.Join(t.TempDir(), "nope.json")})); err == nil {
		t.Error("unloadable key file must error")
	}
	if _, err := crypto.NewProviderFromEnv(envFrom(map[string]string{"GATEWAY_KEY_PROVIDER": "kms"})); err == nil || !strings.Contains(err.Error(), "GATEWAY_KEY_PROVIDER") {
		t.Errorf("unknown provider must be named in the error, got %v", err)
	}
}

func TestNewProviderFromEnvVault(t *testing.T) {
	fv, srv := newFakeVault(t)
	fv.mount = "kms"
	env := map[string]string{
		"GATEWAY_KEY_PROVIDER":      "vault",
		"GATEWAY_VAULT_ADDR":        srv.URL,
		"GATEWAY_VAULT_TOKEN":       fv.token,
		"GATEWAY_VAULT_TRANSIT_KEY": fv.keyName,
		"GATEWAY_VAULT_MOUNT":       "kms",
	}
	p, err := crypto.NewProviderFromEnv(envFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(*crypto.VaultProvider); !ok {
		t.Fatalf("got %T, want *VaultProvider", p)
	}
	if id, err := p.CurrentKeyID(context.Background()); err != nil || id != "v1" {
		t.Errorf("CurrentKeyID = %q, %v", id, err)
	}

	for _, missing := range []string{"GATEWAY_VAULT_ADDR", "GATEWAY_VAULT_TOKEN", "GATEWAY_VAULT_TRANSIT_KEY"} {
		t.Run("missing "+missing, func(t *testing.T) {
			e := map[string]string{}
			for k, v := range env {
				e[k] = v
			}
			delete(e, missing)
			_, err := crypto.NewProviderFromEnv(envFrom(e))
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Errorf("want error naming %s, got %v", missing, err)
			}
			if strings.Contains(err.Error(), fv.token) {
				t.Errorf("error leaks token: %v", err)
			}
		})
	}

	// Mount is optional: default transit.
	fv.mount = "transit"
	e := map[string]string{}
	for k, v := range env {
		e[k] = v
	}
	delete(e, "GATEWAY_VAULT_MOUNT")
	p, err = crypto.NewProviderFromEnv(envFrom(e))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.CurrentKeyID(context.Background()); err != nil {
		t.Errorf("default mount: %v", err)
	}
}

type plainProvider struct {
	crypto.KeyProvider
	err error
}

func (p plainProvider) CurrentKeyID(context.Context) (string, error) { return "x", p.err }

func TestReadinessCheck(t *testing.T) {
	ctx := context.Background()

	// File provider: keys are loaded, so it is ready.
	var check observability.Check = crypto.ReadinessCheck(newStatic(t, "k1"))
	if err := check(ctx); err != nil {
		t.Errorf("static: %v", err)
	}

	// Vault: ready when the key is readable, failing otherwise.
	fv, srv := newFakeVault(t)
	vp := newVaultProvider(t, srv, fv)
	if err := crypto.ReadinessCheck(vp)(ctx); err != nil {
		t.Errorf("vault: %v", err)
	}
	fv.keyName = "renamed"
	if err := crypto.ReadinessCheck(vp)(ctx); err == nil {
		t.Error("vault with unreadable key must not be ready")
	}

	// Providers without a Ready method fall back to CurrentKeyID.
	boom := errors.New("backend down")
	if err := crypto.ReadinessCheck(plainProvider{err: boom})(ctx); !errors.Is(err, boom) {
		t.Errorf("fallback: want %v, got %v", boom, err)
	}
	if err := crypto.ReadinessCheck(plainProvider{})(ctx); err != nil {
		t.Errorf("fallback ok: %v", err)
	}
}
