//go:build !windows

package machineclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const storedTestSecret = "gwr_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

func TestFileSecretStoreRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proxy")
	ss, err := NewSecretStore(KeyStoreFile, dir, "mcp-gateway-proxy")
	if err != nil || ss.Name() != KeyStoreFile {
		t.Fatalf("%v %v", err, ss)
	}
	ctx := context.Background()
	if _, err := ss.Load(ctx, "abc.token"); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("missing: %v", err)
	}
	if err := ss.Save(ctx, "abc.token", storedTestSecret); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "abc.token")
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi, err)
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode())
	}
	got, err := ss.Load(ctx, "abc.token")
	if err != nil || got != storedTestSecret {
		t.Fatalf("load %q %v", got, err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Load(ctx, "abc.token"); err == nil {
		t.Fatal("a world-readable secret file was accepted")
	}
	if err := ss.Delete(ctx, "abc.token"); err != nil {
		t.Fatal(err)
	}
	if err := ss.Delete(ctx, "abc.token"); err != nil {
		t.Fatalf("delete twice: %v", err)
	}
	if _, err := ss.Load(ctx, "abc.token"); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestSecretStoreRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	ss, _ := NewSecretStore(KeyStoreFile, t.TempDir(), "svc")
	for _, acct := range []string{"", "../x", "a/b", ".hidden"} {
		if err := ss.Save(ctx, acct, storedTestSecret); err == nil {
			t.Errorf("account %q accepted by the file store", acct)
		}
	}
	for _, s := range []string{"", "two\nlines", "tab\there"} {
		if err := ss.Save(ctx, "ok", s); err == nil {
			t.Errorf("secret %q accepted", s)
		}
	}
	if _, err := NewSecretStore("vault", t.TempDir(), "svc"); err == nil {
		t.Fatal("unknown store accepted")
	}
}

func TestKeychainSecretStore(t *testing.T) {
	fs := &fakeSecurity{items: map[string]string{}}
	ss := &KeychainSecretStore{Service: "mcp-gateway-proxy", run: fs.run}
	if ss.Name() != KeyStoreKeychain {
		t.Fatal(ss.Name())
	}
	ctx := context.Background()
	acct := "https://gw.example.com"
	if _, err := ss.Load(ctx, acct); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("missing: %v", err)
	}
	if err := ss.Save(ctx, acct, storedTestSecret); err != nil {
		t.Fatal(err)
	}
	got, err := ss.Load(ctx, acct)
	if err != nil || got != storedTestSecret {
		t.Fatalf("load %q %v", got, err)
	}
	if err := ss.Delete(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if err := ss.Delete(ctx, acct); err != nil {
		t.Fatalf("delete twice: %v", err)
	}
	for _, c := range fs.calls {
		for _, a := range c {
			if strings.Contains(a, storedTestSecret) {
				t.Fatalf("secret in argv: %v", c)
			}
		}
		if !contains(c, "mcp-gateway-proxy") || contains(c, KeychainService) {
			t.Fatalf("wrong keychain service (must not share the machine key's): %v", c)
		}
	}
	add := fs.calls[1]
	if add[len(add)-1] != "-w" || !strings.Contains(fs.stdins[1], storedTestSecret) {
		t.Fatalf("the secret must go through stdin with -w last: %v", add)
	}
	fs.fail = errors.New("boom " + storedTestSecret)
	if err := ss.Save(ctx, acct, storedTestSecret); err == nil || strings.Contains(err.Error(), storedTestSecret) {
		t.Fatalf("error leaks the secret: %v", err)
	}
}

func TestPrivateFileHelpers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "state.json")
	if _, err := ReadPrivateFile(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if err := WritePrivateFile(p, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	b, err := ReadPrivateFile(p)
	if err != nil || string(b) != "{}" {
		t.Fatalf("%q %v", b, err)
	}
}
