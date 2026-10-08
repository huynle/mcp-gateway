package identity_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// fakeIDP is a minimal OpenID Connect provider for tests: discovery, an
// authorization endpoint that issues a code without a login page, a token
// endpoint that enforces client authentication and PKCE S256, and a JWKS.
type fakeIDP struct {
	srv          *httptest.Server
	key          *rsa.PrivateKey
	clientID     string
	clientSecret string

	mu       sync.Mutex
	codes    map[string]authRequest
	lastAuth authRequest
	// claims are merged into every ID token (sub, email, name, hd, tid...).
	claims map[string]any
	// nonceOverride, when set, replaces the nonce echoed in the ID token.
	nonceOverride string
	// breakPKCE makes the provider record a bogus challenge so the
	// gateway's verifier can never match.
	breakPKCE  bool
	tokenCalls int
}

type authRequest struct {
	clientID, redirectURI, state, nonce, challenge, method, scope string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{
		key:          key,
		clientID:     "gateway",
		clientSecret: "gateway-dev-secret",
		codes:        map[string]authRequest{},
		claims: map[string]any{
			"sub":            "08a8684b-db88-4b73-90a9-3cd1661f5466",
			"email":          "dev@example.com",
			"email_verified": true,
			"name":           "dev",
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("GET /keys", f.jwks)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) issuer() string { return f.srv.URL }

func (f *fakeIDP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                f.issuer(),
		"authorization_endpoint":                f.issuer() + "/authorize",
		"token_endpoint":                        f.issuer() + "/token",
		"jwks_uri":                              f.issuer() + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (f *fakeIDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := authRequest{
		clientID:    q.Get("client_id"),
		redirectURI: q.Get("redirect_uri"),
		state:       q.Get("state"),
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
		method:      q.Get("code_challenge_method"),
		scope:       q.Get("scope"),
	}
	f.mu.Lock()
	f.lastAuth = req
	f.mu.Unlock()
	switch {
	case req.clientID != f.clientID:
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	case q.Get("response_type") != "code":
		http.Error(w, "response_type must be code", http.StatusBadRequest)
		return
	case req.method != "S256" || req.challenge == "":
		http.Error(w, "PKCE S256 required", http.StatusBadRequest)
		return
	case req.nonce == "" || req.state == "":
		http.Error(w, "nonce and state required", http.StatusBadRequest)
		return
	}
	if f.breakPKCE {
		req.challenge = "bogus-challenge"
	}
	code := randomString()
	f.mu.Lock()
	f.codes[code] = req
	f.mu.Unlock()
	u, err := url.Parse(req.redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	v := u.Query()
	v.Set("code", code)
	v.Set("state", req.state)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (f *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.tokenCalls++
	f.mu.Unlock()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != f.clientID || secret != f.clientSecret {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	f.mu.Lock()
	req, found := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code"))
	f.mu.Unlock()
	if !found || req.redirectURI != r.PostForm.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != req.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	nonce := req.nonce
	if f.nonceOverride != "" {
		nonce = f.nonceOverride
	}
	now := time.Now()
	payload := map[string]any{
		"iss":   f.issuer(),
		"aud":   f.clientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
	}
	f.mu.Lock()
	for k, v := range f.claims {
		payload[k] = v
	}
	f.mu.Unlock()
	writeJSON(w, map[string]any{
		"access_token": "at-" + randomString(),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     f.sign(payload),
	})
}

func (f *fakeIDP) sign(payload map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	body, _ := json.Marshal(payload)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIDP) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := f.key.PublicKey
	writeJSON(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (f *fakeIDP) lastAuthRequest() authRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuth
}

func (f *fakeIDP) setClaim(k string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims[k] = v
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func randomString() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}
