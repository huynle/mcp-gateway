//go:build integration || e2e || security

package security

// SSRF attacks on user-added MCP servers (decision yd6qrbqc: netguard is
// the only way to reach a user-supplied URL; resolve once, check every
// answer, dial the checked IP; ambiguous numeric hosts refused; redirects
// re-checked, https->http never). The netguard-level tests need no
// database; the world-level ones drive the portal, the admin pages and
// /mcp.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/netguard"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ssrfRig is a netguard Guard over a fake DNS (names -> answers, which
// may change between lookups) and a dial recorder: loopback dials go to
// the real test servers, anything else fails without touching the
// network. Every dial is recorded with its literal ip:port.
type ssrfRig struct {
	guard *netguard.Guard
	mu    sync.Mutex
	dns   map[string][][]netip.Addr // name -> successive answers (the last repeats)
	asked map[string]int
	dials []string
}

func newSSRFRig(t *testing.T, allow ...string) *ssrfRig {
	t.Helper()
	r := &ssrfRig{dns: map[string][][]netip.Addr{}, asked: map[string]int{}}
	al, err := netguard.NewStaticAllowList(allow...)
	if err != nil {
		t.Fatal(err)
	}
	r.guard = netguard.New(netguard.Options{AllowList: al, Resolver: r, Dial: r.dial})
	return r
}

func (r *ssrfRig) answer(name string, answers ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var set []netip.Addr
	for _, a := range answers {
		set = append(set, netip.MustParseAddr(a))
	}
	r.dns[name] = append(r.dns[name], set)
}

func (r *ssrfRig) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq, ok := r.dns[strings.ToLower(host)]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	i := r.asked[host]
	r.asked[host]++
	if i >= len(seq) {
		i = len(seq) - 1
	}
	return seq[i], nil
}

func (r *ssrfRig) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.dials = append(r.dials, addr)
	r.mu.Unlock()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("rig: dial of a non-literal address %q", addr)
	}
	if !ap.Addr().IsLoopback() {
		return nil, errors.New("rig: no network beyond loopback")
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (r *ssrfRig) dialed() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.dials...)
}

func blockedReason(err error) (netguard.Reason, bool) {
	var be *netguard.BlockedError
	if errors.As(err, &be) {
		return be.Reason, true
	}
	return "", false
}

// TestSecurityFedSSRFBlockedHostForms: every spelling of an internal
// destination is refused before any dial: loopback, private, link-local
// and metadata, CGNAT, unspecified; IPv4-mapped/compatible, NAT64 and
// 6to4 IPv6 forms; decimal, hex, octal and short numeric hosts; zone
// identifiers; localhost names; userinfo; names resolving to internal
// addresses, or to a mix of public and internal ones.
func TestSecurityFedSSRFBlockedHostForms(t *testing.T) {
	rig := newSSRFRig(t)
	rig.answer("metadata.google.internal", "169.254.169.254")
	rig.answer("mixed.example", "93.184.216.34", "10.1.2.3")
	rig.answer("mapped.example", "::ffff:10.0.0.1")
	rig.answer("nat64.example", "64:ff9b::a9fe:a9fe")
	rig.answer("cgnat.example", "100.64.1.1")
	for _, raw := range []string{
		"https://127.0.0.1/mcp", "https://127.0.0.2:8443/mcp", "https://[::1]/mcp", "https://0.0.0.0/mcp", "https://[::]/mcp",
		"https://10.0.0.1/mcp", "https://172.16.0.1/mcp", "https://192.168.1.1/mcp", "https://[fd00::1]/mcp",
		"https://169.254.169.254/latest/meta-data/", "https://[fe80::1]/mcp", "https://100.64.0.1/mcp",
		"https://[::ffff:127.0.0.1]/mcp", "https://[::ffff:7f00:1]/mcp", "https://[::127.0.0.1]/mcp",
		"https://[64:ff9b::7f00:1]/mcp", "https://[2002:7f00:1::]/mcp", "https://[2002:a9fe:a9fe::1]/mcp",
		"https://2130706433/mcp", "https://0x7f000001/mcp", "https://0x7f.0.0.1/mcp", "https://017700000001/mcp",
		"https://0177.0.0.1/mcp", "https://127.1/mcp", "https://010.8.8.8/mcp", "https://8.8.8.8.:443.evil/mcp",
		"https://[fe80::1%25en0]/mcp", "https://localhost/mcp", "https://LOCALHOST./mcp", "https://api.localhost/mcp",
		"https://user:pass@example.com/mcp", "https://metadata.google.internal/computeMetadata/v1/",
		"https://mixed.example/mcp", "https://mapped.example/mcp", "https://nat64.example/mcp", "https://cgnat.example/mcp",
		"ftp://example.com/mcp", "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
	} {
		t.Run(raw, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, raw, nil)
			if err != nil {
				return // not even a request: nothing can be dialled
			}
			before := len(rig.dialed())
			resp, err := rig.guard.Client().Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("GET %s succeeded", raw)
			}
			if _, ok := blockedReason(err); !ok && !strings.Contains(err.Error(), "no such host") {
				t.Errorf("GET %s: %v, want a netguard refusal", raw, err)
			}
			if got := rig.dialed()[before:]; len(got) != 0 {
				t.Errorf("GET %s dialled %v", raw, got)
			}
		})
	}
}

// TestSecurityFedSSRFDNSRebinding: the address checked is the address
// dialled. A name that answered a public address once and a loopback
// address the next time is refused the second time, and the dial always
// targets the literal checked IP (never the name, so the OS resolver gets
// no second chance).
func TestSecurityFedSSRFDNSRebinding(t *testing.T) {
	rig := newSSRFRig(t)
	rig.answer("flip.example", "93.184.216.34")
	rig.answer("flip.example", "127.0.0.1")
	get := func() error {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://flip.example/mcp", nil)
		resp, err := rig.guard.Client().Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(); err == nil {
		t.Fatal("the rig has no network beyond loopback: the first request should fail at dial")
	}
	if d := rig.dialed(); len(d) != 1 || d[0] != "93.184.216.34:443" {
		t.Fatalf("first dial = %v, want exactly the checked public address", d)
	}
	err := get()
	if r, ok := blockedReason(err); !ok || r != netguard.ReasonLoopback {
		t.Fatalf("rebound request: %v, want loopback refusal", err)
	}
	if d := rig.dialed(); len(d) != 1 {
		t.Fatalf("the rebound name was dialled: %v", d)
	}
}

// TestSecurityFedSSRFRedirects: an allowed (allow-listed by name) server
// redirecting to an internal address, a metadata address, a mapped IPv6
// form or a name resolving inside is refused at the redirect; a redirect
// loop stops at the bound. Only the allowed origin is ever dialled.
func TestSecurityFedSSRFRedirects(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		port := r.Host[strings.LastIndex(r.Host, ":")+1:]
		targets := map[string]string{
			"/ip":      "http://127.0.0.1:" + port + "/landed",
			"/meta":    "http://169.254.169.254/latest/meta-data/iam/",
			"/mapped":  "http://[::ffff:127.0.0.1]:" + port + "/landed",
			"/decimal": "http://2130706433:" + port + "/landed",
			"/inside":  "http://inside.example:" + port + "/landed",
			"/loop":    "/loop",
		}
		if to, ok := targets[r.URL.Path]; ok {
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("landed"))
	}))
	t.Cleanup(srv.Close)
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	rig := newSSRFRig(t, "public.example") // allowed by name only: http allowed, its IP is not
	rig.answer("public.example", "127.0.0.1")
	rig.answer("inside.example", "10.20.30.40")
	for _, path := range []string{"/ip", "/meta", "/mapped", "/decimal", "/inside", "/loop"} {
		t.Run(path, func(t *testing.T) {
			before := hits.Load()
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://public.example:"+port+path, nil)
			resp, err := rig.guard.Client().Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("redirect %s was followed (status %d)", path, resp.StatusCode)
			}
			if _, ok := blockedReason(err); !ok {
				t.Errorf("redirect %s: %v, want a netguard refusal", path, err)
			}
			if path != "/loop" && hits.Load()-before != 1 {
				t.Errorf("redirect %s: %d requests reached the test server, want only the first", path, hits.Load()-before)
			}
		})
	}
	for _, d := range rig.dialed() {
		if d != "127.0.0.1:"+port {
			t.Errorf("dialled %s (only the allowed origin may be dialled)", d)
		}
	}
}

// TestSecurityFedRedirectNeverCarriesCredentials: the federation client
// refuses a redirect (or a legacy SSE endpoint event) to another origin
// before the Authorizer runs, so an upstream cannot bounce the user's
// credential to a second (also reachable) host.
func TestSecurityFedRedirectNeverCarriesCredentials(t *testing.T) {
	var otherSaw atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherSaw.Store(r.Header.Get("Authorization") + "|" + r.Header.Get("X-Notes-Key"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(other.Close)
	otherPort := other.URL[strings.LastIndex(other.URL, ":")+1:]
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example:"+otherPort+"/mcp", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(first.Close)
	firstPort := first.URL[strings.LastIndex(first.URL, ":")+1:]
	rig := newSSRFRig(t, "first.example", "other.example")
	rig.answer("first.example", "127.0.0.1")
	rig.answer("other.example", "127.0.0.1")
	var authorized atomic.Int64
	az := authorizerFunc(func(_ context.Context, r *http.Request) error {
		authorized.Add(1)
		r.Header.Set("Authorization", "Bearer user-upstream-token-redirect")
		r.Header.Set("X-Notes-Key", "user-key-redirect")
		return nil
	})
	c, err := client.New(client.Options{HTTPClient: rig.guard.Client(), Authorizer: az})
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range []client.Transport{client.TransportStreamableHTTP, client.TransportSSE} {
		_, err := c.Connect(t.Context(), client.Endpoint{URL: "http://first.example:" + firstPort + "/mcp", Transport: tr})
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Class != client.ClassBlocked {
			t.Errorf("%s: connect through a cross-origin redirect = %v, want class blocked", tr, err)
		}
	}
	if v, _ := otherSaw.Load().(string); v != "" && v != "|" {
		t.Errorf("the redirect target received credentials: %q", v)
	}
	if otherSaw.Load() != nil {
		t.Error("the redirect target was contacted at all")
	}
}

type authorizerFunc func(ctx context.Context, r *http.Request) error

func (f authorizerFunc) Authorize(ctx context.Context, r *http.Request) error { return f(ctx, r) }

// TestSecurityFedSSRFOAuthDiscovery: a hostile server's 401 challenge and
// protected-resource metadata point discovery at internal addresses
// (resource_metadata, authorization_servers); each is refused by netguard
// (reported in Blocked, never dialled), and authorization-server metadata
// naming another issuer (mix-up) is ignored.
func TestSecurityFedSSRFOAuthDiscovery(t *testing.T) {
	var port string
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="http://169.254.169.254/latest/meta-data/prm"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, map[string]any{
			"resource": "http://mcp.example:" + port + "/mcp",
			"authorization_servers": []string{
				"http://10.9.9.9/", "http://[::ffff:127.0.0.1]:" + port + "/", "http://mixup.example:" + port + "/",
			},
		})
	})
	// mixup.example's metadata claims to be another issuer.
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, map[string]any{
			"issuer": "https://accounts.example.com", "authorization_endpoint": "https://accounts.example.com/authorize",
			"token_endpoint": "https://accounts.example.com/token", "code_challenge_methods_supported": []string{"S256"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	port = srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	rig := newSSRFRig(t, "mcp.example", "mixup.example")
	rig.answer("mcp.example", "127.0.0.1")
	rig.answer("mixup.example", "127.0.0.1")
	d, err := auth.NewDiscoverer(auth.DiscoveryOptions{HTTPClient: rig.guard.Client()})
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Detect(t.Context(), "http://mcp.example:"+port+"/mcp")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.AuthServerMetadata != nil {
		t.Errorf("an authorization server was accepted: %+v", res.AuthServerMetadata)
	}
	blocked := strings.Join(res.Blocked, ",")
	for _, want := range []string{"169.254.169.254", "10.9.9.9", "::ffff:127.0.0.1"} {
		if !strings.Contains(blocked, want) {
			t.Errorf("Blocked = %q, want %s reported", blocked, want)
		}
	}
	for _, dl := range rig.dialed() {
		if dl != "127.0.0.1:"+port {
			t.Errorf("discovery dialled %s", dl)
		}
	}
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// hostileAS is an OAuth upstream on the allow-listed loopback origin
// whose authorization server metadata names internal registration and
// token endpoints.
func hostileAS(t *testing.T, cimd bool) *httptest.Server {
	t.Helper()
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, map[string]any{
			"issuer": base, "authorization_endpoint": base + "/authorize",
			"token_endpoint":                        "http://10.0.0.1/token",
			"registration_endpoint":                 "http://169.254.169.254/register",
			"code_challenge_methods_supported":      []string{"S256"},
			"client_id_metadata_document_supported": cimd,
		})
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

// TestSecurityFedSSRFOAuthEndpoints: the authorization server's
// registration endpoint (DCR) and token endpoint (code exchange) are
// fetched through netguard: internal ones are refused, the connect flow
// fails cleanly and the log records the refusal (host + reason only).
func TestSecurityFedSSRFOAuthEndpoints(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	dcr := hostileAS(t, false)
	s1 := w.addServer(w.alice, "oauthdcr", dcr.URL+"/mcp", func(s *store.MCPServer) { s.AuthKind = store.MCPAuthOAuth })
	code, _, body := w.get(w.alice, "/servers/"+s1.ID+"/connect")
	if code < 400 {
		t.Fatalf("connect with an internal registration endpoint = %d %s", code, body)
	}
	if !strings.Contains(w.logs.String(), `host=169.254.169.254`) {
		t.Error("the registration endpoint refusal is not in the log")
	}

	cimd := hostileAS(t, true)
	s2 := w.addServer(w.alice, "oauthcimd", cimd.URL+"/mcp", func(s *store.MCPServer) { s.AuthKind = store.MCPAuthOAuth })
	code, hdr, body := w.get(w.alice, "/servers/"+s2.ID+"/connect")
	if code != http.StatusFound {
		t.Fatalf("connect (CIMD) = %d %s", code, body)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil || loc.Query().Get("state") == "" {
		t.Fatalf("no state in %q", hdr.Get("Location"))
	}
	code, _, body = w.get(w.alice, "/servers/oauth/callback?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=stolen-code")
	if code != http.StatusBadRequest || !strings.Contains(body, "connect flow invalid") {
		t.Fatalf("callback with an internal token endpoint = %d %q", code, body)
	}
	if !strings.Contains(w.logs.String(), `host=10.0.0.1`) {
		t.Error("the token endpoint refusal is not in the log")
	}
	if strings.Contains(w.logs.String(), "stolen-code") {
		t.Error("the authorization code reached the log")
	}
}

// TestSecurityFedSSRFPortalAdminAndMCPPaths: every path that contacts an
// upstream on someone's behalf goes through netguard: portal detection,
// owner refresh, admin refresh, portal resource read, /mcp tools/call and
// resources/read. A server on a loopback address (not allow-listed, or
// after the allow-list entry is removed) is never contacted.
func TestSecurityFedSSRFPortalAdminAndMCPPaths(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	up := newUpstream(t, notesServer)
	// Detection of internal addresses through the portal.
	for _, target := range []string{
		strings.Replace(up.URL(), "http://", "https://", 1) + "/mcp",
		"https://169.254.169.254/latest/meta-data/",
		"https://[::ffff:127.0.0.1]/mcp", "https://2130706433/mcp", "https://localhost/mcp",
	} {
		code, _, body := w.post(w.alice, "/servers/new", url.Values{"action": {"detect"}, "name": {"probe"}, "url_mode": {"https"}, "url": {target}})
		if code != http.StatusOK || !strings.Contains(body, "blocked by the gateway") {
			t.Errorf("detect %s = %d, want the blocked message; body has %q", target, code, excerpt(body, "address"))
		}
	}

	// A reachable (allow-listed) server is reviewed, then the allow-list
	// entry is removed: every later contact must be refused.
	w.allowLoopback()
	s := w.addServer(w.alice, "ssrfnotes", up.URL(), nil)
	w.review(w.alice, s, "search")
	alice := w.client(w.alice)
	if res, err := w.call(alice, "ssrfnotes.search", map[string]any{"q": "x"}); err != nil || res.IsError {
		t.Fatalf("reachable call: %v %+v", err, res)
	}
	w.exec(`DELETE FROM netguard_allow_hosts`)
	w.fed.AllowList.Invalidate()
	up.reset()

	res, err := w.call(alice, "ssrfnotes.search", map[string]any{"q": "x"})
	if err == nil && !res.IsError {
		t.Fatal("tools/call succeeded against a loopback server after the allow-list entry was removed")
	}
	if err == nil && !strings.Contains(text(t, res), "not allowed") {
		t.Errorf("tools/call refusal = %q, want the class-level blocked text", text(t, res))
	}
	_, err = alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://ssrfnotes/notes://readme"})
	if err == nil {
		t.Error("resources/read reached a loopback server")
	}
	for _, probe := range []struct {
		who  user
		path string
		form url.Values
	}{
		{w.alice, "/servers/" + s.ID + "/refresh", nil},
		{w.alice, "/servers/" + s.ID + "/resources/read", url.Values{"uri": {"notes://readme"}}},
		{w.admin, "/admin/servers/" + s.ID + "/refresh", nil},
	} {
		code, _, body := w.post(probe.who, probe.path, probe.form)
		if code != http.StatusBadGateway || !strings.Contains(body, "blocked") || strings.Contains(body, "readme text") {
			t.Errorf("POST %s = %d, want 502 with the blocked message; %q", probe.path, code, excerpt(body, "blocked"))
		}
	}
	if n := len(up.requests()); n != 0 {
		t.Errorf("the loopback upstream received %d requests after the allow-list entry was removed", n)
	}
}

// excerpt returns a short window of body around the first match of key
// (for failure messages).
func excerpt(body, key string) string {
	i := strings.Index(body, key)
	if i < 0 {
		if len(body) > 200 {
			return body[:200]
		}
		return body
	}
	end := i + 200
	if end > len(body) {
		end = len(body)
	}
	return body[i:end]
}
