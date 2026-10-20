//go:build darwin

package machineclient

import (
	"context"
	"errors"
	"os"
	"testing"
)

// TestKeychainReal exercises the real login keychain through
// /usr/bin/security (opt-in: it writes and deletes a keychain item).
//
//	MCP_GATEWAY_TEST_KEYCHAIN=1 go test -run TestKeychainReal ./internal/machineclient/
func TestKeychainReal(t *testing.T) {
	if os.Getenv("MCP_GATEWAY_TEST_KEYCHAIN") != "1" {
		t.Skip("set MCP_GATEWAY_TEST_KEYCHAIN=1 to use the real keychain")
	}
	ks, err := NewKeyStore(KeyStoreKeychain, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id := "00000000-0000-4000-8000-00000000test"
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ks.Delete(ctx, id) })
	if err := ks.Save(ctx, id, k); err != nil {
		t.Fatal(err)
	}
	got, err := ks.Load(ctx, id)
	if err != nil || !got.Equal(k) {
		t.Fatalf("load: %v", err)
	}
	if err := ks.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(ctx, id); !errors.Is(err, ErrNoKey) {
		t.Fatalf("after delete: %v", err)
	}
}
