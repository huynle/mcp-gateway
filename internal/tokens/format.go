package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Token string format (decision uamxx6ba): Prefix + public id + "_" + secret.
//
//	mgw_<8 base62 chars>_<43 base62 chars>
//
// The public id is random and independent of the row's uuid; it is the only
// part the gateway logs or shows after creation. The secret is 32 random
// bytes, base62-encoded and zero-padded to a fixed width so the shape is
// regular enough for a secret scanner; only its SHA-256 hash is stored.
const (
	// Prefix starts every generated token.
	Prefix = "mgw_"
	// PublicIDLen is the length of the public id in characters.
	PublicIDLen = 8
	// SecretBytes is the entropy of the secret.
	SecretBytes = 32
	// SecretLen is the encoded secret's length: ceil(256 / log2(62)) = 43.
	SecretLen = 43
	// ScanPattern is the regular expression for a custom secret-scanning
	// rule (GitHub, gitleaks, ...). It matches exactly one whole token.
	ScanPattern = `mgw_[A-Za-z0-9]{8}_[A-Za-z0-9]{43}`
)

// ErrMalformed reports a bearer string that is not shaped like a token.
var ErrMalformed = errors.New("tokens: malformed token")

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Generated is a freshly minted token: Raw is shown to the user exactly
// once, PublicID and Hash are what gets stored.
type Generated struct {
	Raw      string
	PublicID string
	Secret   string
	Hash     []byte
}

// Generate mints a new token from the operating system's CSPRNG.
func Generate() (*Generated, error) {
	publicID, err := randomBase62(PublicIDLen)
	if err != nil {
		return nil, fmt.Errorf("tokens: generate public id: %w", err)
	}
	raw := make([]byte, SecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("tokens: generate secret: %w", err)
	}
	secret := encodeBase62(raw, SecretLen)
	return &Generated{
		Raw:      Prefix + publicID + "_" + secret,
		PublicID: publicID,
		Secret:   secret,
		Hash:     HashSecret(secret),
	}, nil
}

// Parse splits a bearer string into its public id and secret, or returns
// ErrMalformed. It accepts exactly the shape Generate produces: no
// surrounding whitespace, no other prefix, fixed lengths, base62 only.
func Parse(raw string) (publicID, secret string, err error) {
	rest, ok := strings.CutPrefix(raw, Prefix)
	if !ok || len(rest) != PublicIDLen+1+SecretLen || rest[PublicIDLen] != '_' {
		return "", "", ErrMalformed
	}
	publicID, secret = rest[:PublicIDLen], rest[PublicIDLen+1:]
	if !isBase62(publicID) || !isBase62(secret) {
		return "", "", ErrMalformed
	}
	return publicID, secret, nil
}

// HashSecret is the stored form of a secret: SHA-256 of the encoded secret
// string. 256 random bits need no slow hash (decision uamxx6ba).
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// randomBase62 returns n uniformly random base62 characters (rejection
// sampling on bytes keeps the distribution unbiased).
func randomBase62(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			// 248 = 4*62: the largest multiple of 62 below 256.
			if b < 248 {
				out = append(out, alphabet[b%62])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out), nil
}

// encodeBase62 renders b as a big-endian base62 number, left-padded with
// '0' to width characters.
func encodeBase62(b []byte, width int) string {
	n := new(big.Int).SetBytes(b)
	base, rem := big.NewInt(62), new(big.Int)
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		n.DivMod(n, base, rem)
		out[i] = alphabet[rem.Int64()]
	}
	return string(out)
}

func isBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(alphabet, rune(s[i])) {
			return false
		}
	}
	return true
}
