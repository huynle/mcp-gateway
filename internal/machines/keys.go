package machines

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/huynle/mcp-gateway/internal/tokens"
)

// ErrInvalidKey: the public key is not an Ed25519 public JWK.
var ErrInvalidKey = errors.New("machines: public_key must be an Ed25519 public JWK")

// maxJWK bounds the public key document.
const maxJWK = 1 << 10

// ParsePublicKey reads a machine's public key: exactly an OKP / Ed25519
// JWK with a 32-byte x and no private part.
func ParsePublicKey(raw json.RawMessage) (ed25519.PublicKey, error) {
	if len(raw) == 0 || len(raw) > maxJWK {
		return nil, ErrInvalidKey
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil || jwk == nil {
		return nil, ErrInvalidKey
	}
	if _, private := jwk["d"]; private {
		return nil, ErrInvalidKey
	}
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	if kty != "OKP" || crv != "Ed25519" || x == "" {
		return nil, ErrInvalidKey
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(x)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	return ed25519.PublicKey(b), nil
}

// PublicJWK is the JWK of a public key (what the CLI sends).
func PublicJWK(pub ed25519.PublicKey) json.RawMessage {
	return json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`)
}

// Thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 public key
// (RFC 8037 §2): SHA-256 over the required members in lexicographic order,
// base64url without padding. It is the machine's fingerprint.
func Thumbprint(pub ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DisplayFingerprint is how pages show a fingerprint: its first 16
// characters in groups of four (the CLI prints the same).
func DisplayFingerprint(fp string) string {
	if len(fp) > 16 {
		fp = fp[:16]
	}
	var parts []string
	for len(fp) > 4 {
		parts = append(parts, fp[:4])
		fp = fp[4:]
	}
	return strings.Join(append(parts, fp), " ")
}

// UserCodeAlphabet is the device flow's user code alphabet (shared with
// the harness device grant, tokens.UserCodeAlphabet).
const UserCodeAlphabet = tokens.UserCodeAlphabet

// NewUserCode returns a random user code formatted "ABCD-EFGH".
func NewUserCode() (string, error) { return tokens.NewUserCode() }

// NormalizeUserCode accepts a user code as typed (any case, spaces and
// dashes) and returns its eight letters, or false when it cannot be one.
func NormalizeUserCode(s string) (string, bool) { return tokens.NormalizeUserCode(s) }

// FormatUserCode formats eight normalized letters as "ABCD-EFGH".
func FormatUserCode(n string) string { return tokens.FormatUserCode(n) }

// Secret prefixes. Every secret has the gateway token shape
// <prefix><8 base62>_<43 base62> (decision uamxx6ba) and is stored as its
// SHA-256 only.
const (
	// AccessTokenPrefix starts machine access tokens (10 minutes).
	AccessTokenPrefix = "mgm_"
	// EnrollmentCodePrefix starts one-time enrollment codes.
	EnrollmentCodePrefix = "mge_"
	// DeviceCodePrefix starts device codes (device authorization flow).
	DeviceCodePrefix = "mgd_"
)

// NewSecret mints a secret with prefix from the OS CSPRNG.
func NewSecret(prefix string) (string, error) {
	g, err := tokens.Generate()
	if err != nil {
		return "", fmt.Errorf("machines: generate secret: %w", err)
	}
	return prefix + g.PublicID + "_" + g.Secret, nil
}

// ValidSecret reports whether raw has exactly NewSecret(prefix)'s shape.
func ValidSecret(prefix, raw string) bool {
	rest, ok := strings.CutPrefix(raw, prefix)
	if !ok || len(rest) != tokens.PublicIDLen+1+tokens.SecretLen || rest[tokens.PublicIDLen] != '_' {
		return false
	}
	return base62(rest[:tokens.PublicIDLen]) && base62(rest[tokens.PublicIDLen+1:])
}

// HashSecret is a secret's stored form (and a user code's): SHA-256.
func HashSecret(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func base62(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
