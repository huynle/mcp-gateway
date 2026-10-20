//go:build !windows

package machineclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RFC 8037 appendix A: the Ed25519 example key and its RFC 7638 thumbprint.
const (
	rfcSeedB64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfcX       = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfcThumb   = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
)

func rfcKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(rfcSeedB64)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestJWKAndThumbprint(t *testing.T) {
	k := rfcKey(t)
	pub := k.Public().(ed25519.PublicKey)
	jwk := PublicJWK(pub)
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X != rfcX {
		t.Fatalf("jwk %+v", jwk)
	}
	b, _ := json.Marshal(jwk)
	if string(b) != `{"kty":"OKP","crv":"Ed25519","x":"`+rfcX+`"}` {
		t.Fatalf("json %s", b)
	}
	if got := Thumbprint(pub); got != rfcThumb {
		t.Fatalf("thumbprint %q, want %q", got, rfcThumb)
	}
	if got := FormatFingerprint(rfcThumb); got != "kPrK _qmx VWaY VA9w" {
		t.Fatalf("fingerprint %q", got)
	}
}

func TestGenerateKey(t *testing.T) {
	k1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := GenerateKey()
	if len(k1) != ed25519.PrivateKeySize || bytes.Equal(k1, k2) {
		t.Fatal("keys must be random Ed25519 keys")
	}
}

func TestFileKeyStoreRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	ks := &FileKeyStore{Path: filepath.Join(dir, "machine.key")}
	if ks.Name() != KeyStoreFile {
		t.Fatal(ks.Name())
	}
	k := rfcKey(t)
	if err := ks.Save(context.Background(), "m1", k); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(ks.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode().Perm())
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	pem, _ := os.ReadFile(ks.Path)
	if !strings.Contains(string(pem), "BEGIN PRIVATE KEY") {
		t.Fatalf("not PKCS#8 PEM:\n%s", pem)
	}
	got, err := ks.Load(context.Background(), "m1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(k) {
		t.Fatal("loaded a different key")
	}
	if err := ks.Delete(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ks.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("key not deleted")
	}
	if err := ks.Delete(context.Background(), "m1"); err != nil {
		t.Fatalf("deleting a missing key: %v", err)
	}
	if _, err := ks.Load(context.Background(), "m1"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("missing key: %v", err)
	}
}

func TestFileKeyStoreRefusesLoosePermissions(t *testing.T) {
	ks := &FileKeyStore{Path: filepath.Join(t.TempDir(), "machine.key")}
	if err := ks.Save(context.Background(), "m1", rfcKey(t)); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644, 0o620} {
		if err := os.Chmod(ks.Path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := ks.Load(context.Background(), "m1")
		if err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %v: want a refusal mentioning chmod 600, got %v", mode, err)
		}
	}
	_ = os.Chmod(ks.Path, 0o400)
	if _, err := ks.Load(context.Background(), "m1"); err != nil {
		t.Errorf("0400 must be accepted: %v", err)
	}
}

func TestFileKeyStoreRefusesOtherOwner(t *testing.T) {
	ks := &FileKeyStore{Path: filepath.Join(t.TempDir(), "machine.key"), uid: func() int { return os.Getuid() + 1 }}
	if err := ks.Save(context.Background(), "m1", rfcKey(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(context.Background(), "m1"); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("want an ownership refusal, got %v", err)
	}
}

func TestFileKeyStoreRefusesGarbage(t *testing.T) {
	ks := &FileKeyStore{Path: filepath.Join(t.TempDir(), "machine.key")}
	if err := os.WriteFile(ks.Path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ks.Load(context.Background(), "m1")
	if err == nil || strings.Contains(err.Error(), "not a key") {
		t.Fatalf("err %v", err)
	}
}

// fakeSecurity records /usr/bin/security invocations and plays a keychain.
type fakeSecurity struct {
	calls  [][]string
	stdins []string
	items  map[string]string // account -> password
	fail   error
}

func (f *fakeSecurity) run(_ context.Context, path string, args []string, stdin []byte) ([]byte, error) {
	f.calls = append(f.calls, append([]string{path}, args...))
	f.stdins = append(f.stdins, string(stdin))
	if f.fail != nil {
		return nil, f.fail
	}
	acct := ""
	for i, a := range args {
		if a == "-a" && i+1 < len(args) {
			acct = args[i+1]
		}
	}
	switch args[0] {
	case "add-generic-password":
		lines := strings.Split(string(stdin), "\n")
		if len(lines) < 2 || lines[0] != lines[1] {
			return nil, errors.New("passwords do not match")
		}
		f.items[acct] = lines[0]
		return nil, nil
	case "find-generic-password":
		v, ok := f.items[acct]
		if !ok {
			return nil, &exitError{code: 44}
		}
		return []byte(v + "\n"), nil
	case "delete-generic-password":
		if _, ok := f.items[acct]; !ok {
			return nil, &exitError{code: 44}
		}
		delete(f.items, acct)
		return nil, nil
	}
	return nil, errors.New("unexpected command")
}

type exitError struct{ code int }

func (e *exitError) Error() string { return "exit status" }
func (e *exitError) ExitCode() int { return e.code }

func TestKeychainKeyStore(t *testing.T) {
	fs := &fakeSecurity{items: map[string]string{}}
	ks := &KeychainKeyStore{run: fs.run}
	if ks.Name() != KeyStoreKeychain {
		t.Fatal(ks.Name())
	}
	k := rfcKey(t)
	ctx := context.Background()
	if err := ks.Save(ctx, "mid-1", k); err != nil {
		t.Fatal(err)
	}
	got, err := ks.Load(ctx, "mid-1")
	if err != nil || !got.Equal(k) {
		t.Fatalf("load: %v", err)
	}
	if err := ks.Delete(ctx, "mid-1"); err != nil {
		t.Fatal(err)
	}
	if err := ks.Delete(ctx, "mid-1"); err != nil {
		t.Fatalf("deleting a missing item: %v", err)
	}
	if _, err := ks.Load(ctx, "mid-1"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("missing item: %v", err)
	}
	// The secret never appears in argv: only on stdin.
	secret := rfcSeedB64
	for _, c := range fs.calls {
		if c[0] != "/usr/bin/security" {
			t.Errorf("must run /usr/bin/security by absolute path: %v", c)
		}
		for _, a := range c {
			if strings.Contains(a, secret) {
				t.Fatalf("secret in argv: %v", c)
			}
		}
	}
	add := fs.calls[0]
	if add[len(add)-1] != "-w" {
		t.Fatalf("-w must be last so security prompts (reads stdin): %v", add)
	}
	for _, want := range []string{"-s", KeychainService, "-a", "mid-1", "-U"} {
		if !contains(add, want) {
			t.Errorf("add args %v miss %q", add, want)
		}
	}
	if !strings.Contains(fs.stdins[0], secret) {
		t.Fatal("secret must go through stdin")
	}
}

func TestKeychainErrorsHideOutput(t *testing.T) {
	fs := &fakeSecurity{items: map[string]string{}, fail: errors.New("boom " + rfcSeedB64)}
	ks := &KeychainKeyStore{run: fs.run}
	err := ks.Save(context.Background(), "m", rfcKey(t))
	if err == nil || strings.Contains(err.Error(), rfcSeedB64) {
		t.Fatalf("err %v", err)
	}
	fs.fail = nil
	fs.items["m"] = "garbage!!"
	if _, err := ks.Load(context.Background(), "m"); err == nil || strings.Contains(err.Error(), "garbage") {
		t.Fatalf("err %v", err)
	}
}

func TestNewKeyStore(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(KeyStoreFile, dir)
	if err != nil || ks.Name() != KeyStoreFile || ks.(*FileKeyStore).Path != filepath.Join(dir, "machine.key") {
		t.Fatalf("%v %#v", err, ks)
	}
	if _, err := NewKeyStore("vault", dir); err == nil {
		t.Fatal("unknown store accepted")
	}
	if d := DefaultKeyStore(); d != KeyStoreKeychain && d != KeyStoreFile {
		t.Fatal(d)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
