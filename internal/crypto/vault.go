package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// VaultConfig configures the HashiCorp Vault transit provider.
type VaultConfig struct {
	// Addr is the Vault base URL, e.g. https://vault.internal:8200.
	Addr string
	// Token authenticates every request (X-Vault-Token). It needs
	// `update` on <mount>/encrypt/<key> and <mount>/decrypt/<key> and `read`
	// on <mount>/keys/<key>.
	Token string
	// Mount is the transit engine mount path. Default "transit".
	Mount string
	// KeyName is the transit key. Its versions become envelope key IDs.
	KeyName string
	// Namespace sets X-Vault-Namespace (Vault Enterprise). Optional.
	Namespace string
	// HTTPClient overrides the client; the default has a 10 s timeout.
	HTTPClient *http.Client
	// Logger receives debug records (operation, status, duration). Never
	// request or response bodies. Optional.
	Logger *slog.Logger
}

// VaultProvider wraps data keys with the Vault transit secrets engine over
// its HTTP API. The transit key version is the envelope key ID ("v1", "v2",
// ...), so `vault write -f transit/keys/<name>/rotate` is root key rotation:
// new envelopes use the new version, old ones still decrypt until the
// operator raises min_decryption_version, and RewrapEach moves them over.
type VaultProvider struct {
	base      *url.URL
	token     string
	namespace string
	keyName   string
	mount     string
	client    *http.Client
	log       *slog.Logger
}

const (
	vaultDefaultMount   = "transit"
	vaultDefaultTimeout = 10 * time.Second
	vaultPrefix         = "vault:v"
	vaultMaxErrorBody   = 4 << 10
)

// NewVaultProvider validates cfg and returns a provider. It does not contact
// Vault; use Ready or ReadinessCheck for that.
func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error) {
	if cfg.Addr == "" {
		return nil, errors.New("crypto: vault: address must not be empty")
	}
	base, err := url.Parse(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("crypto: vault: address: %w", err)
	}
	if (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("crypto: vault: address %q must be an http(s) URL", cfg.Addr)
	}
	if cfg.Token == "" {
		return nil, errors.New("crypto: vault: token must not be empty")
	}
	if cfg.KeyName == "" || strings.ContainsAny(cfg.KeyName, "/?#") {
		return nil, fmt.Errorf("crypto: vault: key name %q must be a single non-empty path segment", cfg.KeyName)
	}
	mount := strings.Trim(cfg.Mount, "/")
	if mount == "" {
		mount = vaultDefaultMount
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: vaultDefaultTimeout}
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &VaultProvider{
		base:      base,
		token:     cfg.Token,
		namespace: cfg.Namespace,
		keyName:   cfg.KeyName,
		mount:     mount,
		client:    client,
		log:       log,
	}, nil
}

// CurrentKeyID implements KeyProvider by reading the key's latest_version.
func (p *VaultProvider) CurrentKeyID(ctx context.Context) (string, error) {
	var resp struct {
		Data struct {
			LatestVersion int `json:"latest_version"`
		} `json:"data"`
	}
	if err := p.do(ctx, http.MethodGet, "keys", nil, &resp); err != nil {
		return "", err
	}
	if resp.Data.LatestVersion < 1 {
		return "", errors.New("crypto: vault: key has no versions")
	}
	return vaultKeyID(resp.Data.LatestVersion), nil
}

// Ready reports whether the transit key is readable with the configured
// token. It satisfies the optional readiness interface used by ReadinessCheck.
func (p *VaultProvider) Ready(ctx context.Context) error {
	_, err := p.CurrentKeyID(ctx)
	return err
}

// WrapDataKey implements KeyProvider via transit encrypt. The wrapped blob is
// Vault's ciphertext string ("vault:v<N>:<base64>") as bytes.
func (p *VaultProvider) WrapDataKey(ctx context.Context, plaintextKey []byte) (string, []byte, error) {
	if len(plaintextKey) != DataKeySize {
		return "", nil, ErrInvalidDataKey
	}
	req := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintextKey)}
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}
	if err := p.do(ctx, http.MethodPost, "encrypt", req, &resp); err != nil {
		return "", nil, err
	}
	version, ok := parseVaultCiphertext(resp.Data.Ciphertext)
	if !ok {
		return "", nil, errors.New("crypto: vault: encrypt returned malformed ciphertext")
	}
	if resp.Data.KeyVersion != 0 && resp.Data.KeyVersion != version {
		return "", nil, errors.New("crypto: vault: encrypt key_version disagrees with ciphertext")
	}
	return vaultKeyID(version), []byte(resp.Data.Ciphertext), nil
}

// UnwrapDataKey implements KeyProvider via transit decrypt. A keyID that is
// not a transit version ("v<N>"), or one Vault refuses as too old, maps to
// ErrUnknownKeyID (operator action); a keyID that disagrees with the version
// embedded in the blob maps to ErrDecrypt (corruption).
func (p *VaultProvider) UnwrapDataKey(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	if !isVaultKeyID(keyID) {
		return nil, fmt.Errorf("%w: %q is not a vault transit key version", ErrUnknownKeyID, keyID)
	}
	version, ok := parseVaultCiphertext(string(wrapped))
	if !ok {
		return nil, fmt.Errorf("%w: wrapped data key is not a vault transit ciphertext", ErrDecrypt)
	}
	if keyID != vaultKeyID(version) {
		return nil, fmt.Errorf("%w: key ID %q does not match ciphertext version v%d", ErrDecrypt, keyID, version)
	}
	req := map[string]string{"ciphertext": string(wrapped)}
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := p.do(ctx, http.MethodPost, "decrypt", req, &resp); err != nil {
		var ve *vaultError
		if errors.As(err, &ve) && ve.tooOld() {
			return nil, fmt.Errorf("%w: %q is below the key's min_decryption_version", ErrUnknownKeyID, keyID)
		}
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, errors.New("crypto: vault: decrypt returned malformed plaintext")
	}
	if len(key) != DataKeySize {
		wipe(key)
		return nil, ErrInvalidDataKey
	}
	return key, nil
}

// vaultError is a non-2xx response. It carries status and Vault's error
// strings, which describe policy and request shape, never secrets.
type vaultError struct {
	op     string
	status int
	errors []string
}

func (e *vaultError) Error() string {
	return fmt.Sprintf("crypto: vault: %s: HTTP %d: %s", e.op, e.status, strings.Join(e.errors, "; "))
}

func (e *vaultError) tooOld() bool {
	for _, m := range e.errors {
		if strings.Contains(m, "disallowed by policy") || strings.Contains(m, "too old") {
			return true
		}
	}
	return false
}

func vaultKeyID(version int) string { return "v" + strconv.Itoa(version) }

// isVaultKeyID reports whether id has the shape vaultKeyID produces
// ("v" and a positive integer).
func isVaultKeyID(id string) bool {
	rest, found := strings.CutPrefix(id, "v")
	if !found {
		return false
	}
	v, err := strconv.Atoi(rest)
	return err == nil && v >= 1
}

// parseVaultCiphertext extracts N from "vault:v<N>:<payload>".
func parseVaultCiphertext(s string) (version int, ok bool) {
	rest, found := strings.CutPrefix(s, vaultPrefix)
	if !found {
		return 0, false
	}
	ver, payload, found := strings.Cut(rest, ":")
	if !found || payload == "" {
		return 0, false
	}
	v, err := strconv.Atoi(ver)
	if err != nil || v < 1 {
		return 0, false
	}
	return v, true
}

// do performs one transit request against <mount>/<op>/<key>.
func (p *VaultProvider) do(ctx context.Context, method, op string, body, out any) error {
	u := *p.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/v1/" + p.mount + "/" + op + "/" + url.PathEscape(p.keyName)

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("crypto: vault: %s: encode request: %w", op, err)
		}
		defer wipe(raw)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return fmt.Errorf("crypto: vault: %s: build request: %w", op, err)
	}
	req.Header.Set("X-Vault-Token", p.token)
	req.Header.Set("X-Vault-Request", "true")
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		p.log.DebugContext(ctx, "vault transit request failed", "op", op, "key", p.keyName, "duration", time.Since(start))
		// url.Error wraps the token-free request URL; keep the cause chain
		// (context.Canceled, net errors) for callers.
		return fmt.Errorf("crypto: vault: %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	p.log.DebugContext(ctx, "vault transit request", "op", op, "key", p.keyName, "status", resp.StatusCode, "duration", time.Since(start))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ve := &vaultError{op: op, status: resp.StatusCode}
		var payload struct {
			Errors []string `json:"errors"`
		}
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, vaultMaxErrorBody))
		if json.Unmarshal(limited, &payload) == nil {
			ve.errors = payload.Errors
		}
		return ve
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("crypto: vault: %s: decode response: %w", op, err)
	}
	return nil
}
