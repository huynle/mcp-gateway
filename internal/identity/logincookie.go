package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// LoginCookie carries the in-flight sign-in state between /start and
// /callback: state, nonce, PKCE verifier and the return path. The gateway
// runs several replicas without sticky sessions, so the state lives in the
// browser, HMAC-signed with a key derived from the provider's client secret
// (shared by every replica; no extra secret to configure). Ten-minute
// lifetime; deleted by the callback.
const LoginCookie = "mcpgw_login"

const loginTTL = 10 * time.Minute

// maxReturnTo bounds the return path copied into the cookie.
const maxReturnTo = 2048

// maxInviteParam bounds the invite code copied into the cookie (a real
// code is 48 bytes).
const maxInviteParam = 128

type loginState struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	ReturnTo string `json:"r"`
	// Invite is the sign-up invite code the browser brought (invite
	// mode); it never leaves the gateway.
	Invite  string    `json:"i,omitempty"`
	Expires time.Time `json:"e"`
}

var errLoginState = errors.New("identity: invalid login state")

func loginKey(clientSecret string) []byte {
	sum := sha256.Sum256([]byte("mcp-gateway/login-state:" + clientSecret))
	return sum[:]
}

func (s *Service) newLoginState(p *provider, returnTo string, now time.Time) (*loginState, error) {
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}
	verifier, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &loginState{
		Provider: p.cfg.Name,
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		ReturnTo: returnTo,
		Expires:  now.Add(loginTTL),
	}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// codeChallenge is the S256 PKCE challenge for the verifier.
func (l *loginState) codeChallenge() string { return oidc.NewSHACodeChallenge(l.Verifier) }

// encode signs the state for the cookie.
func (l *loginState) encode(key []byte) (string, error) {
	payload, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(payload)
	return enc + "." + sign(key, enc), nil
}

func sign(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// decodeLoginState verifies and parses a cookie value for provider p.
func decodeLoginState(value string, key []byte, now time.Time) (*loginState, error) {
	enc, mac, ok := strings.Cut(value, ".")
	if !ok || !hmac.Equal([]byte(mac), []byte(sign(key, enc))) {
		return nil, errLoginState
	}
	payload, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, errLoginState
	}
	var l loginState
	if err := json.Unmarshal(payload, &l); err != nil {
		return nil, errLoginState
	}
	if !now.Before(l.Expires) {
		return nil, errLoginState
	}
	return &l, nil
}

func (s *Service) loginCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     LoginCookie,
		Value:    value,
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

func (s *Service) clearLoginCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: LoginCookie, Value: "", Path: "/auth/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// SafeReturnTo reduces a user-supplied return path to a same-origin
// absolute path ("/..."), or "/" when it is anything else: another origin,
// a protocol-relative URL, a backslash trick, a fragment, a path that
// re-enters the sign-in routes, or an unnormalised path.
func SafeReturnTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxReturnTo {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "/"
	}
	p := u.EscapedPath()
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	// Reject encoded slashes and dot segments: normalise the decoded path
	// and require it to round-trip unchanged.
	if strings.Contains(strings.ToLower(p), "%2f") || strings.Contains(strings.ToLower(p), "%5c") {
		return "/"
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "/"
		}
	}
	if strings.HasPrefix(u.Path, "/auth/") {
		return "/"
	}
	out := p
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}
