package tunnel

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Tunnel token format, modelled on the gateway's API tokens (decision
// uamxx6ba) with its own prefix so secret scanners and humans can tell
// them apart:
//
//	mgt_<8 base62 chars>_<43 base62 chars>
//
// The token is shown to its owner exactly once; only HashToken(raw), the
// SHA-256 of the whole token string, is stored (mcp_tunnels.token_hash).
// The tunnel is found by that hash, so no part of the token is a database
// key and nothing but the hash ever reaches the store or the logs.
const (
	// TokenPrefix starts every tunnel token.
	TokenPrefix = "mgt_"
	// TokenScanPattern matches exactly one whole tunnel token (for a custom
	// secret-scanning rule).
	TokenScanPattern = `mgt_[A-Za-z0-9]{8}_[A-Za-z0-9]{43}`
)

// ErrMalformedToken reports a string that is not shaped like a tunnel token.
var ErrMalformedToken = errors.New("tunnel: malformed token")

// GenerateToken mints a tunnel token from the OS CSPRNG and returns it
// with its stored hash.
func GenerateToken() (raw string, hash []byte, err error) {
	g, err := tokens.Generate()
	if err != nil {
		return "", nil, fmt.Errorf("tunnel: generate token: %w", err)
	}
	raw = TokenPrefix + g.PublicID + "_" + g.Secret
	return raw, HashToken(raw), nil
}

// ParseToken checks raw has exactly the shape GenerateToken produces.
func ParseToken(raw string) error {
	rest, ok := strings.CutPrefix(raw, TokenPrefix)
	if !ok || len(rest) != tokens.PublicIDLen+1+tokens.SecretLen || rest[tokens.PublicIDLen] != '_' {
		return ErrMalformedToken
	}
	if !base62(rest[:tokens.PublicIDLen]) || !base62(rest[tokens.PublicIDLen+1:]) {
		return ErrMalformedToken
	}
	return nil
}

// HashToken is the stored form of a token: SHA-256 of the whole token
// string. 256 random bits need no slow hash.
func HashToken(raw string) []byte {
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
