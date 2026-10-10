package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// keyFile is the on-disk layout of the dev key file:
//
//	{
//	  "current": "2026-01",
//	  "keys": [
//	    {"id": "2026-01", "key": "<base64 of 32 random bytes>"},
//	    {"id": "2025-07", "key": "..."}
//	  ]
//	}
//
// Rotation: add a key, point "current" at it, restart, run the re-wrap job,
// then remove the retired key once no envelope references it.
type keyFile struct {
	Current string         `json:"current"`
	Keys    []keyFileEntry `json:"keys"`
}

type keyFileEntry struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// LoadKeyFile reads a dev key file and returns a StaticProvider holding its
// keys. On POSIX systems the file must not be group- or world-accessible.
// Error messages name key IDs but never key bytes.
func LoadKeyFile(path string) (*StaticProvider, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: key file: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("crypto: key file %s has mode %04o; must not be group- or world-accessible (chmod 600)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: key file: %w", err)
	}
	defer wipe(raw)

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc keyFile
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("crypto: key file %s: invalid JSON: %w", path, err)
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("crypto: key file %s: no keys", path)
	}
	keys := make(map[string][]byte, len(doc.Keys))
	defer func() {
		for _, k := range keys {
			wipe(k)
		}
	}()
	for _, e := range doc.Keys {
		if e.ID == "" {
			return nil, fmt.Errorf("crypto: key file %s: key with empty id", path)
		}
		if _, dup := keys[e.ID]; dup {
			return nil, fmt.Errorf("crypto: key file %s: duplicate key id %q", path, e.ID)
		}
		k, err := base64.StdEncoding.DecodeString(e.Key)
		if err != nil {
			return nil, fmt.Errorf("crypto: key file %s: key %q is not valid base64", path, e.ID)
		}
		if len(k) != DataKeySize {
			return nil, fmt.Errorf("crypto: key file %s: key %q has %d bytes, want %d", path, e.ID, len(k), DataKeySize)
		}
		for otherID, other := range keys {
			if bytes.Equal(other, k) {
				return nil, fmt.Errorf("crypto: key file %s: keys %q and %q have identical material", path, otherID, e.ID)
			}
		}
		keys[e.ID] = k
	}
	if _, ok := keys[doc.Current]; !ok {
		return nil, fmt.Errorf("crypto: key file %s: current key %q is not in keys", path, doc.Current)
	}
	return NewStaticProvider(doc.Current, keys)
}

// GenerateKeyFile writes a new dev key file with one random key under keyID,
// creating parent directories, with mode 0600. It refuses to overwrite an
// existing file because that would orphan every envelope wrapped under the
// old key.
func GenerateKeyFile(path, keyID string) error {
	if keyID == "" {
		return errors.New("crypto: key ID must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("crypto: key file: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("crypto: key file: %w", err)
	}
	k := make([]byte, DataKeySize)
	if _, err := rand.Read(k); err != nil {
		_ = f.Close()
		return fmt.Errorf("crypto: key file: %w", err)
	}
	defer wipe(k)
	doc := keyFile{Current: keyID, Keys: []keyFileEntry{{ID: keyID, Key: base64.StdEncoding.EncodeToString(k)}}}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		_ = f.Close()
		return fmt.Errorf("crypto: key file: %w", err)
	}
	return f.Close()
}
