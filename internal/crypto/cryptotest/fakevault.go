package cryptotest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// FakeVault imitates the Vault / OpenBao transit endpoints that
// crypto.VaultProvider uses: GET <mount>/keys/<key>, POST
// <mount>/encrypt/<key> and POST <mount>/decrypt/<key>. Ciphertexts are
// "vault:v<N>:<base64(nonce || AES-256-GCM sealed plaintext)>" under a
// random per-version key, like real transit: wrapping is randomized, a
// ciphertext only opens under the version that made it, and tampering fails
// authentication. Keys live only in memory for the test's lifetime.
//
// The defaults are token "s.test-token", mount "transit" and key "gateway"
// at version 1. All methods are safe for concurrent use with requests.
type FakeVault struct {
	mu      sync.Mutex
	token   string
	mount   string
	keyName string
	latest  int
	minDecr int
	keys    map[int]cipher.AEAD
	calls   []string
}

// NewFakeVault starts a FakeVault on an httptest server that is closed when
// the test ends.
func NewFakeVault(t testing.TB) (*FakeVault, *httptest.Server) {
	t.Helper()
	fv := &FakeVault{token: "s.test-token", mount: "transit", keyName: "gateway", minDecr: 1, keys: map[int]cipher.AEAD{}}
	fv.Rotate()
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	return fv, srv
}

// Token returns the token requests must carry.
func (f *FakeVault) Token() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.token
}

// SetToken changes the accepted token (simulates a revoked token).
func (f *FakeVault) SetToken(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = tok
}

// Mount returns the transit mount path.
func (f *FakeVault) Mount() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mount
}

// SetMount changes the transit mount path.
func (f *FakeVault) SetMount(m string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mount = m
}

// KeyName returns the transit key name.
func (f *FakeVault) KeyName() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keyName
}

// SetKeyName renames the transit key (requests for the old name then 404).
func (f *FakeVault) SetKeyName(k string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keyName = k
}

// Rotate adds a key version and makes it the latest, like
// `vault write -f transit/keys/<key>/rotate`.
func (f *FakeVault) Rotate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.latest++
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	f.keys[f.latest] = aead
}

// SetMinDecryptionVersion refuses decryption below version n, like raising
// the key's min_decryption_version.
func (f *FakeVault) SetMinDecryptionVersion(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.minDecr = n
}

// Calls returns "METHOD /path" for every request served so far.
func (f *FakeVault) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// ServeHTTP implements the transit endpoints.
func (f *FakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	token, prefix, keyName := f.token, "/v1/"+f.mount+"/", f.keyName
	f.mu.Unlock()
	if r.Header.Get("X-Vault-Token") != token {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == prefix+"keys/"+keyName:
		f.mu.Lock()
		defer f.mu.Unlock()
		writeVaultJSON(w, map[string]any{"data": map[string]any{"latest_version": f.latest, "min_decryption_version": f.minDecr, "type": "aes256-gcm96", "name": keyName}})
	case r.Method == http.MethodPost && r.URL.Path == prefix+"encrypt/"+keyName:
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
	case r.Method == http.MethodPost && r.URL.Path == prefix+"decrypt/"+keyName:
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
			writeVaultError(w, http.StatusBadRequest, "invalid ciphertext: could not decode")
			return
		}
		aead := f.keys[v]
		if len(raw) < aead.NonceSize() {
			writeVaultError(w, http.StatusBadRequest, "invalid ciphertext: too short")
			return
		}
		pt, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
		if err != nil {
			writeVaultError(w, http.StatusBadRequest, "cipher: message authentication failed")
			return
		}
		writeVaultJSON(w, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
	default:
		writeVaultError(w, http.StatusNotFound, "unsupported path")
	}
}

// seal encrypts pt under version v; f.mu must be held.
func (f *FakeVault) seal(v int, pt []byte) string {
	aead := f.keys[v]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, pt, nil)))
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
