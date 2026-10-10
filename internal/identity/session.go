package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// SessionCookie is the browser session cookie. Its value is a random
// secret; only the SHA-256 hash is stored (sessions.token_hash).
const SessionCookie = "mcpgw_session"

// newSessionSecret returns a fresh session secret and its stored hash.
func newSessionSecret() (secret string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("identity: session secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	return secret, hashSecret(secret), nil
}

func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// csrfToken derives the per-session CSRF token from the session secret.
// The browser already holds the secret (in the HttpOnly cookie), the server
// recomputes the token from it on every request, and a cross-site attacker
// knows neither, so no extra state is stored (synchronizer token pattern).
func csrfToken(secret string) string {
	sum := sha256.Sum256([]byte("mcp-gateway/csrf:" + secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// sessionCookie builds the session cookie: HttpOnly, SameSite=Lax, Secure
// as configured, bounded by the absolute timeout (idle expiry is enforced
// server-side).
func (s *Service) sessionCookie(secret string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookie,
		Value:    secret,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}
