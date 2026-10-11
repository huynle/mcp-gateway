//go:build integration || e2e

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- Brain-shaped OAuth upstream ---------------------------------------------------

type recallIn struct {
	Q string `json:"q"`
}

type recallInV2 struct {
	Q     string `json:"q"`
	Limit int    `json:"limit"`
}

type titleIn struct {
	Title string `json:"title"`
}

type asCode struct{ clientID, challenge, redirectURI, resource string }

// brainUpstream is shaped like brain.huynle.com: MCP at /mcp answering
// 401 `Bearer realm="brain-api"` (no resource_metadata) without a valid
// token, RFC 9728 metadata at the path-aware and root well-known URLs
// naming the origin as resource and authorization server, RFC 8414
// metadata at the root with dynamic client registration and PKCE S256
// only. Its tools: recall (read) and save (write); version 2 adds a
// limit to recall's schema and a new tool, forget.
type brainUpstream struct {
	srv    *httptest.Server
	issuer string
	forbid func(value, what string)
	v2     atomic.Bool

	mu            sync.Mutex
	registrations int
	clients       map[string]bool
	codes         map[string]asCode
	access        map[string]bool
	saved         []string
	bearers       []string // Authorization headers /mcp accepted
}

func newBrainUpstream(t *testing.T, forbid func(value, what string)) *brainUpstream {
	t.Helper()
	u := &brainUpstream{forbid: forbid, clients: map[string]bool{}, codes: map[string]asCode{}, access: map[string]bool{}}
	build := func(v2 bool) *sdk.Server {
		s := sdk.NewServer(&sdk.Implementation{Name: "brain", Version: "1"}, nil)
		read := &sdk.ToolAnnotations{ReadOnlyHint: true}
		if v2 {
			sdk.AddTool(s, &sdk.Tool{Name: "recall", Description: "Recall memories.", Annotations: read},
				func(_ context.Context, _ *sdk.CallToolRequest, in recallInV2) (*sdk.CallToolResult, any, error) {
					return textResult("recall v2: " + in.Q), nil, nil
				})
			sdk.AddTool(s, &sdk.Tool{Name: "forget", Description: "Forget a memory."},
				func(_ context.Context, _ *sdk.CallToolRequest, in titleIn) (*sdk.CallToolResult, any, error) {
					return textResult("forgot " + in.Title), nil, nil
				})
		} else {
			sdk.AddTool(s, &sdk.Tool{Name: "recall", Description: "Recall memories.", Annotations: read},
				func(_ context.Context, _ *sdk.CallToolRequest, in recallIn) (*sdk.CallToolResult, any, error) {
					return textResult("recall: " + in.Q), nil, nil
				})
		}
		sdk.AddTool(s, &sdk.Tool{Name: "save", Description: "Save a memory."},
			func(_ context.Context, _ *sdk.CallToolRequest, in titleIn) (*sdk.CallToolResult, any, error) {
				u.mu.Lock()
				u.saved = append(u.saved, in.Title)
				u.mu.Unlock()
				return textResult("saved"), nil, nil
			})
		return s
	}
	v1, v2 := statelessMCP(build(false)), statelessMCP(build(true))

	mux := http.NewServeMux()
	prm := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"resource": u.issuer, "authorization_servers": []string{u.issuer},
			"bearer_methods_supported": []string{"header"}, "scopes_supported": []string{"mcp"},
		})
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", prm)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", prm)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer": u.issuer, "authorization_endpoint": u.issuer + "/authorize", "token_endpoint": u.issuer + "/token",
			"registration_endpoint": u.issuer + "/register", "response_types_supported": []string{"code"},
			"grant_types_supported":            []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"mcp"},
			"token_endpoint_auth_methods_supported": []string{"none"},
		})
	})
	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		u.mu.Lock()
		u.registrations++
		id := "dcr-" + randHex(4)
		u.clients[id] = true
		u.mu.Unlock()
		writeJSON(w, 201, map[string]any{"client_id": id, "redirect_uris": req["redirect_uris"], "token_endpoint_auth_method": "none"})
	})
	mux.HandleFunc("POST /token", u.token)
	mux.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		tok, ok := strings.CutPrefix(authz, "Bearer ")
		u.mu.Lock()
		ok = ok && u.access[tok]
		if ok {
			u.bearers = append(u.bearers, authz)
		}
		u.mu.Unlock()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="brain-api"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			return
		}
		if u.v2.Load() {
			v2.ServeHTTP(w, r)
			return
		}
		v1.ServeHTTP(w, r)
	}))
	u.srv = httptest.NewTLSServer(mux)
	u.issuer = u.srv.URL
	t.Cleanup(u.srv.Close)
	return u
}

func (u *brainUpstream) mcpURL() string { return u.srv.URL + "/mcp" }

// authorize plays the user consenting at the authorization server: it
// checks the request (DCR client, PKCE S256, RFC 8707 resource) and
// returns the redirect back to the gateway's callback.
func (u *brainUpstream) authorize(t *testing.T, authURL string) *url.URL {
	t.Helper()
	a, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Scheme + "://" + a.Host + a.Path; got != u.issuer+"/authorize" {
		t.Fatalf("connect redirected to %s, want the server's authorization endpoint", got)
	}
	q := a.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorization request without PKCE S256: %v", q)
	}
	if q.Get("resource") == "" {
		t.Fatalf("authorization request without an RFC 8707 resource: %v", q)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.clients[q.Get("client_id")] {
		t.Fatalf("authorization request from an unregistered client %q", q.Get("client_id"))
	}
	code := "code-" + randHex(8)
	u.forbid(code, "authorization code")
	u.codes[code] = asCode{clientID: q.Get("client_id"), challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri"), resource: q.Get("resource")}
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	return back
}

func (u *brainUpstream) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	u.mu.Lock()
	defer u.mu.Unlock()
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	c, found := u.codes[r.PostForm.Get("code")]
	delete(u.codes, r.PostForm.Get("code"))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || c.clientID != r.PostForm.Get("client_id") || c.redirectURI != r.PostForm.Get("redirect_uri") ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || c.resource != r.PostForm.Get("resource") {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	at, rt := "brain-at-"+randHex(12), "brain-rt-"+randHex(12)
	u.forbid(at, "upstream access token")
	u.forbid(rt, "upstream refresh token")
	u.access[at] = true
	writeJSON(w, 200, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "refresh_token": rt})
}

func (u *brainUpstream) savedTitles() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.saved...)
}

// --- API key and no-auth upstreams ---------------------------------------------------

// keyUpstream answers 401 without any OAuth metadata unless the request
// carries one of keys (value -> whose key) in header; its tools report
// whose key they saw. It also has a resource, a template and a prompt.
type keyUpstream struct {
	srv    *httptest.Server
	header string
	keys   map[string]string
	mu     sync.Mutex
	seen   []http.Header
}

func newKeyUpstream(t *testing.T, name, header string, keys map[string]string) *keyUpstream {
	t.Helper()
	u := &keyUpstream{header: header, keys: keys}
	s := sdk.NewServer(&sdk.Implementation{Name: name, Version: "1"}, nil)
	who := func(h http.Header) string { return keys[h.Get(header)] }
	sdk.AddTool(s, &sdk.Tool{Name: "lookup", Description: "Look a record up.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, req *sdk.CallToolRequest, in recallIn) (*sdk.CallToolResult, any, error) {
			return textResult("lookup " + in.Q + " with " + who(req.Extra.Header)), nil, nil
		})
	h := statelessMCP(s)
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.Header.Clone())
		u.mu.Unlock()
		if _, ok := keys[r.Header.Get(header)]; !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *keyUpstream) headers() []http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]http.Header(nil), u.seen...)
}

// newOpenUpstream is a server without authentication, serving s.
func newOpenUpstream(t *testing.T, s *sdk.Server) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(statelessMCP(s))
	t.Cleanup(srv.Close)
	return srv
}
