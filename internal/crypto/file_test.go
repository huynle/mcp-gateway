package crypto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

func writeKeyFile(t *testing.T, current string, keys map[string][]byte) string {
	t.Helper()
	doc := map[string]any{"current": current, "keys": []map[string]string{}}
	var list []map[string]string
	for id, k := range keys {
		list = append(list, map[string]string{"id": id, "key": base64.StdEncoding.EncodeToString(k)})
	}
	doc["keys"] = list
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadKeyFileCurrentMovesBetweenTwoKeys(t *testing.T) {
	ctx := context.Background()
	keys := sharedKeys(t, "2026-01", "2026-07")

	first, err := crypto.LoadKeyFile(writeKeyFile(t, "2026-01", keys))
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := first.CurrentKeyID(ctx); id != "2026-01" {
		t.Fatalf("current = %q, want 2026-01", id)
	}
	env, err := crypto.Encrypt(ctx, first, baseAAD, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Operator edits the file: same keys, "current" moves to 2026-07.
	second, err := crypto.LoadKeyFile(writeKeyFile(t, "2026-07", keys))
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := second.CurrentKeyID(ctx); id != "2026-07" {
		t.Fatalf("current = %q, want 2026-07", id)
	}
	got, err := crypto.Decrypt(ctx, second, baseAAD, env)
	if err != nil || string(got) != "secret" {
		t.Fatalf("old envelope must still decrypt after current moves: %q, %v", got, err)
	}
	re, err := crypto.Rewrap(ctx, second, env)
	if err != nil {
		t.Fatal(err)
	}
	if re.KeyID != "2026-07" || !bytes.Equal(re.Ciphertext, env.Ciphertext) {
		t.Errorf("rewrap: KeyID=%q ciphertext-equal=%v", re.KeyID, bytes.Equal(re.Ciphertext, env.Ciphertext))
	}

	// Operator removes the retired key after rotation completed.
	third, err := crypto.LoadKeyFile(writeKeyFile(t, "2026-07", map[string][]byte{"2026-07": keys["2026-07"]}))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := crypto.Decrypt(ctx, third, baseAAD, re); err != nil || string(got) != "secret" {
		t.Errorf("rewrapped envelope under new-only file: %q, %v", got, err)
	}
	if _, err := crypto.Decrypt(ctx, third, baseAAD, env); !errors.Is(err, crypto.ErrUnknownKeyID) {
		t.Errorf("old envelope under new-only file: want ErrUnknownKeyID, got %v", err)
	}
}

func TestLoadKeyFileRejectsBadFiles(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "keys.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	k := base64.StdEncoding.EncodeToString(randomKey(t))
	short := base64.StdEncoding.EncodeToString(randomKey(t)[:31])
	cases := map[string]string{
		"not json":          `{`,
		"no keys":           `{"current":"a","keys":[]}`,
		"current missing":   `{"current":"b","keys":[{"id":"a","key":"` + k + `"}]}`,
		"short key":         `{"current":"a","keys":[{"id":"a","key":"` + short + `"}]}`,
		"bad base64":        `{"current":"a","keys":[{"id":"a","key":"not*base64"}]}`,
		"duplicate id":      `{"current":"a","keys":[{"id":"a","key":"` + k + `"},{"id":"a","key":"` + k + `"}]}`,
		"empty id":          `{"current":"","keys":[{"id":"","key":"` + k + `"}]}`,
		"unknown field":     `{"current":"a","keys":[{"id":"a","key":"` + k + `"}],"extra":1}`,
		"duplicate key mat": `{"current":"a","keys":[{"id":"a","key":"` + k + `"},{"id":"b","key":"` + k + `"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := crypto.LoadKeyFile(write(t, body))
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), k) || strings.Contains(err.Error(), short) {
				t.Errorf("error leaks key material: %v", err)
			}
		})
	}
	if _, err := crypto.LoadKeyFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file must error")
	}
}

func TestLoadKeyFileRejectsGroupOrWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	path := writeKeyFile(t, "a", sharedKeys(t, "a"))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadKeyFile(path); err == nil {
		t.Error("world-readable key file must be rejected")
	}
}

func TestGenerateKeyFileProducesLoadableFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sub", "keys.json")
	if err := crypto.GenerateKeyFile(path, "dev-1"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
	p, err := crypto.LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := p.CurrentKeyID(ctx); id != "dev-1" {
		t.Errorf("current = %q, want dev-1", id)
	}
	env, err := crypto.Encrypt(ctx, p, baseAAD, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Decrypt(ctx, p, baseAAD, env); err != nil {
		t.Fatal(err)
	}
	// Never overwrite an existing key file: that would orphan every envelope.
	if err := crypto.GenerateKeyFile(path, "dev-2"); err == nil {
		t.Error("GenerateKeyFile must refuse to overwrite")
	}
}
