package crypto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/crypto/cryptotest"
)

// migrationSetup is a file provider holding the legacy keys and a Vault
// provider for the target, as an operator moving off the key file has them.
type migrationSetup struct {
	fv     *fakeVault
	srv    *httptest.Server
	legacy *crypto.StaticProvider
	vault  *crypto.VaultProvider
	keys   map[string][]byte
	file   string
}

func newMigrationSetup(t *testing.T) migrationSetup {
	t.Helper()
	fv, srv := newFakeVault(t)
	keys := sharedKeys(t, "2025-07", "2026-01")
	path := writeKeyFile(t, "2026-01", keys)
	legacy, err := crypto.LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return migrationSetup{fv: fv, srv: srv, legacy: legacy, vault: newVaultProvider(t, srv, fv), keys: keys, file: path}
}

func (s migrationSetup) provider(t *testing.T) *crypto.MigratingProvider {
	t.Helper()
	p, err := crypto.NewMigratingProvider(s.legacy, s.vault)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMigratingProviderContract(t *testing.T) {
	s := newMigrationSetup(t)
	cryptotest.ProviderContract(t, cryptotest.Harness{
		Provider: s.provider(t),
		Rotate:   func(*testing.T) { s.fv.Rotate() },
	})
}

func TestMigratingProviderReadsLegacyAndWritesTarget(t *testing.T) {
	ctx := context.Background()
	s := newMigrationSetup(t)
	old, err := crypto.Encrypt(ctx, s.legacy, baseAAD, []byte("refresh-token"))
	if err != nil {
		t.Fatal(err)
	}
	if old.KeyID != "2026-01" {
		t.Fatalf("legacy envelope key ID = %q", old.KeyID)
	}
	p := s.provider(t)

	// Existing envelopes keep decrypting: no reconnects at cutover.
	if got, err := crypto.Decrypt(ctx, p, baseAAD, old); err != nil || string(got) != "refresh-token" {
		t.Fatalf("legacy envelope through migrating provider: %q, %v", got, err)
	}
	// New data goes to the target.
	if id, err := p.CurrentKeyID(ctx); err != nil || id != "v1" {
		t.Fatalf("CurrentKeyID = %q, %v; want the vault version", id, err)
	}
	fresh, err := crypto.Encrypt(ctx, p, baseAAD, []byte("new-token"))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.KeyID != "v1" || !bytes.HasPrefix(fresh.WrappedDataKey, []byte("vault:v1:")) {
		t.Errorf("new envelope key ID = %q; want a vault transit wrap", fresh.KeyID)
	}

	// Re-wrap moves the legacy envelope to the target; afterwards a
	// vault-only provider (the post-cutover configuration) opens both.
	stats, err := crypto.RewrapEach(ctx, p, []crypto.Envelope{old, fresh}, func(_ context.Context, i int, updated crypto.Envelope) error {
		if i != 0 {
			t.Errorf("rewrapped item %d; only the legacy one needs it", i)
		}
		old = updated
		return nil
	})
	if err != nil || stats.Rewrapped != 1 || stats.Skipped != 1 {
		t.Fatalf("RewrapEach = %+v, %v", stats, err)
	}
	if old.KeyID != "v1" {
		t.Errorf("rewrapped key ID = %q, want v1", old.KeyID)
	}
	for name, env := range map[string]crypto.Envelope{"rewrapped": old, "fresh": fresh} {
		if _, err := crypto.Decrypt(ctx, s.vault, baseAAD, env); err != nil {
			t.Errorf("%s envelope under vault only: %v", name, err)
		}
	}

	// The older file key is still honored for envelopes under it.
	older := writeKeyFile(t, "2025-07", s.keys)
	olderProvider, err := crypto.LoadKeyFile(older)
	if err != nil {
		t.Fatal(err)
	}
	ancient, err := crypto.Encrypt(ctx, olderProvider, baseAAD, []byte("ancient"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := crypto.Decrypt(ctx, p, baseAAD, ancient); err != nil || string(got) != "ancient" {
		t.Errorf("non-current file key: %q, %v", got, err)
	}
}

func TestMigratingProviderRoutesByKeyIDWithoutFallback(t *testing.T) {
	ctx := context.Background()
	s := newMigrationSetup(t)
	p := s.provider(t)
	legacyEnv, err := crypto.Encrypt(ctx, s.legacy, baseAAD, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	vaultEnv, err := crypto.Encrypt(ctx, p, baseAAD, []byte("y"))
	if err != nil {
		t.Fatal(err)
	}

	// A file key ID the file does not hold is an operator problem.
	bad := legacyEnv
	bad.KeyID = "2024-01"
	if _, err := crypto.Decrypt(ctx, p, baseAAD, bad); !errors.Is(err, crypto.ErrUnknownKeyID) {
		t.Errorf("unknown file key: want ErrUnknownKeyID, got %v", err)
	}
	// Vault IDs never fall back to the file, and file IDs never reach Vault.
	s.fv.SetToken("revoked")
	if _, err := crypto.Decrypt(ctx, p, baseAAD, vaultEnv); err == nil {
		t.Error("vault envelope must fail when vault refuses, not fall back to the file")
	}
	calls := len(s.fv.Calls())
	if _, err := crypto.Decrypt(ctx, p, baseAAD, legacyEnv); err != nil {
		t.Errorf("legacy envelope must not depend on vault: %v", err)
	}
	if n := len(s.fv.Calls()); n != calls {
		t.Errorf("legacy unwrap called vault (%d new calls)", n-calls)
	}
	// A legacy blob presented under a vault-shaped ID is rejected.
	swapped := legacyEnv
	swapped.KeyID = "v1"
	s.fv.SetToken("s.test-token")
	if _, err := crypto.Decrypt(ctx, p, baseAAD, swapped); err == nil {
		t.Error("legacy blob under a vault key ID must not decrypt")
	}
}

func TestNewMigratingProviderRefusesCollidingKeyIDs(t *testing.T) {
	_, srv := newFakeVault(t)
	vp, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: "t", KeyName: "gateway"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"v1", "v2", "v10", "v0", "v01", "V3"} {
		t.Run(id, func(t *testing.T) {
			legacy := newStatic(t, "2026-01", id)
			_, err := crypto.NewMigratingProvider(legacy, vp)
			if err == nil {
				t.Fatalf("file key ID %q collides with vault versions; want an error", id)
			}
			if !strings.Contains(err.Error(), id) {
				t.Errorf("error should name the offending key ID: %v", err)
			}
		})
	}
	for _, id := range []string{"2026-01", "compose-1", "vault", "v1a", "dev-v1"} {
		if _, err := crypto.NewMigratingProvider(newStatic(t, id), vp); err != nil {
			t.Errorf("file key ID %q is not vault-shaped; got %v", id, err)
		}
	}
	if _, err := crypto.NewMigratingProvider(nil, vp); err == nil {
		t.Error("nil legacy provider must be rejected")
	}
	if _, err := crypto.NewMigratingProvider(newStatic(t, "k"), nil); err == nil {
		t.Error("nil target provider must be rejected")
	}
}

func TestMigratingProviderReadyFollowsTarget(t *testing.T) {
	s := newMigrationSetup(t)
	p := s.provider(t)
	if err := crypto.ReadinessCheck(p)(context.Background()); err != nil {
		t.Fatalf("ready: %v", err)
	}
	s.fv.SetKeyName("other")
	if err := crypto.ReadinessCheck(p)(context.Background()); err == nil {
		t.Error("unreadable vault key must fail readiness: new data could not be written")
	}
}

func TestNewProviderFromEnvMigrate(t *testing.T) {
	s := newMigrationSetup(t)
	env := map[string]string{
		"GATEWAY_KEY_PROVIDER":      "migrate",
		"GATEWAY_KEY_FILE":          s.file,
		"GATEWAY_VAULT_ADDR":        s.srv.URL,
		"GATEWAY_VAULT_TOKEN":       s.fv.Token(),
		"GATEWAY_VAULT_TRANSIT_KEY": s.fv.KeyName(),
	}
	p, err := crypto.NewProviderFromEnv(envFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(*crypto.MigratingProvider); !ok {
		t.Fatalf("got %T, want *MigratingProvider", p)
	}
	if id, err := p.CurrentKeyID(context.Background()); err != nil || id != "v1" {
		t.Errorf("CurrentKeyID = %q, %v", id, err)
	}
	for _, missing := range []string{"GATEWAY_KEY_FILE", "GATEWAY_VAULT_ADDR", "GATEWAY_VAULT_TOKEN", "GATEWAY_VAULT_TRANSIT_KEY"} {
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
			if err != nil && strings.Contains(err.Error(), s.fv.Token()) {
				t.Errorf("error leaks token: %v", err)
			}
		})
	}
	if _, err := crypto.NewProviderFromEnv(envFrom(map[string]string{"GATEWAY_KEY_PROVIDER": "kms"})); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Errorf("unknown provider error should list migrate, got %v", err)
	}
}

func TestMigratingProviderNoKeyMaterialInLogsOrErrors(t *testing.T) {
	ctx := context.Background()
	fv, srv := newFakeVault(t)
	keys := sharedKeys(t, "2026-01")
	legacy, err := crypto.NewStaticProvider("2026-01", keys)
	if err != nil {
		t.Fatal(err)
	}
	cap := &captureHandler{}
	vp, err := crypto.NewVaultProvider(crypto.VaultConfig{Addr: srv.URL, Token: fv.Token(), KeyName: fv.KeyName(), Logger: slog.New(cap)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := crypto.NewMigratingProvider(legacy, vp)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("super-secret-token-" + hex.EncodeToString(randomKey(t)[:6]))
	old, err := crypto.Encrypt(ctx, legacy, baseAAD, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := legacy.UnwrapDataKey(ctx, old.KeyID, old.WrappedDataKey)
	if err != nil {
		t.Fatal(err)
	}
	re, err := crypto.Rewrap(ctx, p, old)
	if err != nil {
		t.Fatal(err)
	}
	var errs []error
	bad := old
	bad.KeyID = "gone"
	_, e1 := crypto.Decrypt(ctx, p, baseAAD, bad)
	bad = old
	bad.WrappedDataKey = bytes.Clone(old.WrappedDataKey)
	bad.WrappedDataKey[len(bad.WrappedDataKey)-1] ^= 1
	_, e2 := crypto.Decrypt(ctx, p, baseAAD, bad)
	fv.SetToken("rotated-token")
	_, e3 := crypto.Decrypt(ctx, p, baseAAD, re)
	_, _, e4 := p.WrapDataKey(ctx, dk)
	errs = append(errs, e1, e2, e3, e4)

	secrets := map[string][]byte{"data key": dk, "plaintext": plaintext, "file key": keys["2026-01"], "token": []byte("s.test-token"), "wrapped": old.WrappedDataKey, "rewrapped": re.WrappedDataKey}
	for name, sec := range secrets {
		for _, form := range []string{string(sec), base64.StdEncoding.EncodeToString(sec), hex.EncodeToString(sec)} {
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
