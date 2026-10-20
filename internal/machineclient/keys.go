package machineclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// JWK is an Ed25519 public key as a JSON Web Key (RFC 8037).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// GenerateKey creates a new machine key.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	return k, err
}

// PublicJWK is the public key as sent to the gateway.
func PublicJWK(pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
}

// Thumbprint is the RFC 7638 JWK thumbprint (SHA-256, base64url without
// padding) of the public key: the machine's fingerprint.
func Thumbprint(pub ed25519.PublicKey) string {
	// The required members in lexicographic order, no whitespace.
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// FormatFingerprint is how a fingerprint is shown to people: the first 16
// characters of the thumbprint in groups of 4, as the portal shows it.
func FormatFingerprint(thumbprint string) string {
	if len(thumbprint) > 16 {
		thumbprint = thumbprint[:16]
	}
	var groups []string
	for len(thumbprint) > 4 {
		groups = append(groups, thumbprint[:4])
		thumbprint = thumbprint[4:]
	}
	groups = append(groups, thumbprint)
	return strings.Join(groups, " ")
}
