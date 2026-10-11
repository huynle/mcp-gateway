package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/netguard"
)

// fakeNet gives httptest servers public-looking host names: the netguard
// resolver maps each name to a public documentation-free address
// (93.184.216.N) and the dialer routes that address to the server's
// loopback listener. Everything still goes through the real netguard
// checks, so a metadata document pointing at 127.0.0.1 or 169.254.169.254
// is refused exactly as in production. Names unknown to fakeNet do not
// resolve, so any request that bypassed the injected client would fail.
type fakeNet struct {
	t       *testing.T
	mu      sync.Mutex
	names   map[string]netip.Addr
	targets map[netip.Addr]string
	next    byte
	allow   netguard.AllowList
	guard   *netguard.Guard
}

func newFakeNet(t *testing.T, allow ...string) *fakeNet {
	t.Helper()
	n := &fakeNet{t: t, names: map[string]netip.Addr{}, targets: map[netip.Addr]string{}, next: 10}
	if len(allow) > 0 {
		al, err := netguard.NewStaticAllowList(allow...)
		if err != nil {
			t.Fatal(err)
		}
		n.allow = al
	}
	n.guard = netguard.New(netguard.Options{
		AllowList: n.allow,
		AllowHTTP: true,
		Resolver:  n,
		Dial:      n.dial,
		Timeout:   10 * time.Second,
	})
	return n
}

// add serves h under http://name and returns that base URL.
func (n *fakeNet) add(name string, h http.Handler) string {
	n.t.Helper()
	ts := httptest.NewServer(h)
	n.t.Cleanup(ts.Close)
	n.mu.Lock()
	defer n.mu.Unlock()
	ip := netip.AddrFrom4([4]byte{93, 184, 216, n.next})
	n.next++
	n.names[name] = ip
	n.targets[ip] = ts.Listener.Addr().String()
	return "http://" + name
}

func (n *fakeNet) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ip, ok := n.names[host]; ok {
		return []netip.Addr{ip}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (n *fakeNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	target, ok := n.targets[ip]
	n.mu.Unlock()
	if !ok {
		// An allow-listed internal address: dial it for real (loopback test
		// servers only).
		target = addr
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

func (n *fakeNet) client() *http.Client { return n.guard.Client() }

// --- upstream MCP servers ------------------------------------------------------

// mcpHandler is a go-sdk Streamable HTTP server with one "whoami" tool
// that reports the credential headers it saw.
func mcpHandler() http.Handler {
	s := mcp.NewServer(&mcp.Implementation{Name: "upstream", Version: "1.0.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "whoami"},
		func(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]string, error) {
			out := map[string]string{}
			if req.Extra != nil && req.Extra.Header != nil {
				for _, k := range []string{"Authorization", "X-Api-Key", "X-Brain-Project"} {
					out[k] = req.Extra.Header.Get(k)
				}
			}
			return nil, out, nil
		})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
}

// gate wraps an MCP handler: requests without an accepted credential get a
// 401 with challenge.
func gate(next http.Handler, challenge string, ok func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok(r) {
			if challenge != "" {
				w.Header().Set("WWW-Authenticate", challenge)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Unauthorized","message":"Missing authentication token"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- in-process authorization server ----------------------------------------------

// testAS is an OAuth 2.1 authorization server shaped like Brain's
// (brain.huynle.com): RFC 8414 metadata at the root, DCR, S256 only.
// Knobs switch on CIMD, the RFC 9207 iss parameter, scopes, and make
// refreshes fail.
type testAS struct {
	t      *testing.T
	issuer string // set after add

	cimd           bool
	issParam       bool
	noS256         bool
	noRegistration bool
	scopes         []string
	tokenEndpoint  string // override (e.g. an internal address)

	mu            sync.Mutex
	registrations int
	clients       map[string]string // client_id -> secret ("" public)
	codes         map[string]asCode
	access        map[string]bool // live access tokens
	refresh       map[string]bool // live refresh tokens
	refreshCalls  int
	failRefresh   string // OAuth error code to answer refreshes with
	denyAll       bool   // the protected server rejects every token
	lastAuthorize url.Values
	lastToken     url.Values
	lastTokenAuth string
	issued        int
}

type asCode struct {
	clientID, challenge, redirectURI, resource, scope string
}

func newTestAS(t *testing.T) *testAS {
	return &testAS{t: t, clients: map[string]string{}, codes: map[string]asCode{}, access: map[string]bool{}, refresh: map[string]bool{},
		scopes: []string{"mcp", "mcp:read", "mcp:write", "control"}}
}

func (a *testAS) metadata() map[string]any {
	m := map[string]any{
		"issuer":                                a.issuer,
		"authorization_endpoint":                a.issuer + "/authorize",
		"token_endpoint":                        a.issuer + "/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      a.scopes,
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
	}
	if a.tokenEndpoint != "" {
		m["token_endpoint"] = a.tokenEndpoint
	}
	if !a.noRegistration {
		m["registration_endpoint"] = a.issuer + "/register"
	}
	if a.noS256 {
		m["code_challenge_methods_supported"] = []string{"plain"}
	}
	if a.cimd {
		m["client_id_metadata_document_supported"] = true
	}
	if a.issParam {
		m["authorization_response_iss_parameter_supported"] = true
	}
	return m
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *testAS) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, a.metadata())
	})
	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.registrations++
		id := "dcr-" + randHex(4)
		secret := ""
		if m, _ := req["token_endpoint_auth_method"].(string); m != "none" {
			secret = "dcr-secret-" + randHex(8)
		}
		a.clients[id] = secret
		resp := map[string]any{"client_id": id, "redirect_uris": req["redirect_uris"], "token_endpoint_auth_method": req["token_endpoint_auth_method"]}
		if secret != "" {
			resp["client_secret"] = secret
		}
		writeJSON(w, 201, resp)
	})
	mux.HandleFunc("POST /token", a.token)
}

// authorize plays the user consenting at the AS: it validates the request
// like the AS would and returns the redirect back to the client.
func (a *testAS) authorize(t *testing.T, authURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != a.issuer+"/authorize" {
		t.Fatalf("authorize endpoint = %s, want %s/authorize", got, a.issuer)
	}
	q := u.Query()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastAuthorize = q
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize request without PKCE S256: %v", q)
	}
	cid := q.Get("client_id")
	if _, ok := a.clients[cid]; !ok && (!a.cimd || !strings.HasPrefix(cid, "http")) {
		t.Fatalf("authorize with unknown client %q", cid)
	}
	code := "code-" + randHex(8)
	a.codes[code] = asCode{clientID: cid, challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri"), resource: q.Get("resource"), scope: q.Get("scope")}
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	if a.issParam {
		bq.Set("iss", a.issuer)
	}
	back.RawQuery = bq.Encode()
	return back
}

func (a *testAS) clientAuth(r *http.Request) (string, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		a.lastTokenAuth = "basic"
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		a.lastTokenAuth = "post"
	}
	if a.cimd && strings.HasPrefix(id, "http") {
		return id, secret == ""
	}
	want, ok := a.clients[id]
	return id, ok && want == secret
}

func (a *testAS) issue(w http.ResponseWriter, scope string) {
	a.issued++
	at := fmt.Sprintf("at-%d-%s", a.issued, randHex(6))
	rt := fmt.Sprintf("rt-%d-%s", a.issued, randHex(6))
	a.access[at] = true
	a.refresh[rt] = true
	writeJSON(w, 200, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "refresh_token": rt, "scope": scope})
}

func (a *testAS) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastToken = r.PostForm
	id, ok := a.clientAuth(r)
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		c, found := a.codes[r.PostForm.Get("code")]
		delete(a.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case !found, c.clientID != id, c.redirectURI != r.PostForm.Get("redirect_uri"),
			base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge,
			r.PostForm.Get("resource") != c.resource:
			writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "secret detail at-should-not-leak"})
			return
		}
		a.issue(w, c.scope)
	case "refresh_token":
		a.refreshCalls++
		rt := r.PostForm.Get("refresh_token")
		if a.failRefresh != "" {
			writeJSON(w, 400, map[string]string{"error": a.failRefresh})
			return
		}
		if !a.refresh[rt] {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		delete(a.refresh, rt) // rotation: a refresh token works once
		a.issue(w, "")
	default:
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (a *testAS) validAccess(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.access[tok] && !a.denyAll
}

// revokeAll invalidates every access token (forces a 401 upstream).
func (a *testAS) revokeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.access = map[string]bool{}
}

// brainServer builds a server shaped exactly like brain.huynle.com: MCP
// at /mcp answering 401 `Bearer realm="brain-api"` without
// resource_metadata, the RFC 9728 document at both the path-aware and the
// root well-known URL naming the root as resource and itself as AS, and
// the AS metadata at the root. It returns the MCP URL and the AS.
func brainServer(t *testing.T, n *fakeNet, name string, configure func(*testAS)) (string, *testAS) {
	t.Helper()
	as := newTestAS(t)
	if configure != nil {
		configure(as)
	}
	mux := http.NewServeMux()
	as.routes(mux)
	var base string
	prm := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"authorization_servers":    []string{base},
			"bearer_methods_supported": []string{"header"},
			"resource":                 base,
			"scopes_supported":         as.scopes,
		})
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", prm)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", prm)
	mux.Handle("/mcp", gate(mcpHandler(), `Bearer realm="brain-api"`, func(r *http.Request) bool {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		return ok && as.validAccess(tok)
	}))
	base = n.add(name, mux)
	as.issuer = base
	return base + "/mcp", as
}

// logBuffer captures every log line of a test.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logBuffer) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
