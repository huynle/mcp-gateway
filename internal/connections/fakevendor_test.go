package connections_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeVendor is an httptest OAuth 2.0 provider with authorize, token,
// userinfo and revoke endpoints. It verifies PKCE (S256), client
// credentials and the redirect URI, issues rotating refresh tokens, and
// can be told to answer invalid_grant on refresh.
type fakeVendor struct {
	srv *httptest.Server

	mu          sync.Mutex
	clientID    string
	secret      string
	codes       map[string]issuedCode // code -> challenge etc.
	refreshes   map[string]string     // refresh token -> account id
	accessOwner map[string]string     // access token -> account id
	users       map[string]userInfo   // account id -> info
	revoked     []string
	authorize   []url.Values
	ever        []string // every access and refresh token ever issued

	tokenCalls   atomic.Int32
	refreshCalls atomic.Int32
	invalidGrant atomic.Bool
	refreshDelay time.Duration
	expiresIn    int
	issued       atomic.Int32
}

type issuedCode struct {
	account   string
	challenge string
	redirect  string
	scope     string
}

type userInfo struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

func newFakeVendor(t *testing.T) *fakeVendor {
	t.Helper()
	v := &fakeVendor{
		clientID: "client-1", secret: "client-secret-xyz",
		codes: map[string]issuedCode{}, refreshes: map[string]string{}, accessOwner: map[string]string{},
		users: map[string]userInfo{
			"acct-company":  {ID: "acct-company", Login: "alice", Email: "alice@acme.test"},
			"acct-personal": {ID: "acct-personal", Login: "alice-home", Email: "alice@gmail.test"},
		},
		expiresIn: 3600,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", v.authorizeHandler)
	mux.HandleFunc("POST /token", v.tokenHandler)
	mux.HandleFunc("GET /userinfo", v.userInfoHandler)
	mux.HandleFunc("POST /revoke", v.revokeHandler)
	v.srv = httptest.NewServer(mux)
	t.Cleanup(v.srv.Close)
	return v
}

func (v *fakeVendor) URL() string { return v.srv.URL }

// authorizeHandler records the request and redirects back with a code for
// the account named by the "login_as" query parameter (the test's stand-in
// for the vendor's login screen; default acct-company).
func (v *fakeVendor) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v.mu.Lock()
	v.authorize = append(v.authorize, q)
	account := q.Get("login_as")
	if account == "" {
		account = "acct-company"
	}
	code := fmt.Sprintf("code-%d", len(v.codes)+1)
	v.codes[code] = issuedCode{account: account, challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), scope: q.Get("scope")}
	v.mu.Unlock()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != v.clientID || q.Get("response_type") != "code" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	u, _ := url.Parse(q.Get("redirect_uri"))
	qq := u.Query()
	qq.Set("code", code)
	qq.Set("state", q.Get("state"))
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// issueCode mints a code directly (tests that skip the authorize hop).
func (v *fakeVendor) issueCode(account, challenge, redirect string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	code := fmt.Sprintf("code-%d", len(v.codes)+1)
	v.codes[code] = issuedCode{account: account, challenge: challenge, redirect: redirect}
	return code
}

func (v *fakeVendor) tokenHandler(w http.ResponseWriter, r *http.Request) {
	v.tokenCalls.Add(1)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != v.clientID || secret != v.secret {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "bad client credentials")
		return
	}
	var account, scope string
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		v.mu.Lock()
		c, ok := v.codes[r.PostForm.Get("code")]
		delete(v.codes, r.PostForm.Get("code"))
		v.mu.Unlock()
		if !ok {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown code")
			return
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if c.challenge != "" && base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "pkce verification failed")
			return
		}
		if c.redirect != "" && r.PostForm.Get("redirect_uri") != c.redirect {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		}
		account, scope = c.account, c.scope
	case "refresh_token":
		v.refreshCalls.Add(1)
		if v.refreshDelay > 0 {
			time.Sleep(v.refreshDelay)
		}
		if v.invalidGrant.Load() {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "Token has been expired or revoked.")
			return
		}
		v.mu.Lock()
		account, ok = v.refreshes[r.PostForm.Get("refresh_token")]
		if ok {
			delete(v.refreshes, r.PostForm.Get("refresh_token")) // rotation: old one dies
		}
		v.mu.Unlock()
		if !ok {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
			return
		}
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	n := v.issued.Add(1)
	access, refresh := fmt.Sprintf("access-%d-%s", n, account), fmt.Sprintf("refresh-%d-%s", n, account)
	v.mu.Lock()
	v.accessOwner[access] = account
	v.refreshes[refresh] = account
	v.ever = append(v.ever, access, refresh)
	v.mu.Unlock()
	body := map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": v.expiresIn}
	if scope != "" {
		body["scope"] = scope // echo what was granted, like a real vendor
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (v *fakeVendor) userInfoHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	v.mu.Lock()
	account, ok := v.accessOwner[token]
	info := v.users[account]
	v.mu.Unlock()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (v *fakeVendor) revokeHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	v.mu.Lock()
	v.revoked = append(v.revoked, r.PostForm.Get("token"))
	v.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (v *fakeVendor) revokedTokens() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.revoked...)
}

// allTokens lists every access and refresh token the vendor ever issued,
// for scanning stores and logs for plaintext.
func (v *fakeVendor) allTokens() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.ever...)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
