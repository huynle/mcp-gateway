//go:build !windows

package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"
	fakeUser    = "BCDF-GHJK"
)

// fakeGateway plays the gateway's authorization server and /mcp.
type fakeGateway struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// devicePolls scripts the answers to successive device_code polls of
	// one device code: an OAuth error code, or "" for success.
	devicePolls []string
	pollIndex   map[string]int
	nextID      int
	clients     map[string]bool
	access      map[string]bool   // valid access tokens
	refresh     map[string]string // live refresh token -> client
	used        map[string]bool   // rotated refresh tokens
	expiresIn   int
	// rejectAccess makes /mcp answer 401 to every token (set) once
	// (rejectOnce) or always.
	rejectOnce bool
	rejectAll  bool
	// foreign makes the AS metadata point registration and token
	// endpoints at another server.
	foreign string
	// sessionID is sent on the initialize answer when set.
	sessionID string
	// noRevoke leaves revocation_endpoint out of the AS metadata;
	// revokeStatus, when set, is the revocation endpoint's answer.
	noRevoke     bool
	revokeStatus int
	revokeReqs   []url.Values

	registrations []map[string]any
	deviceReqs    []url.Values
	tokenReqs     []url.Values
	mcpReqs       []mcpReq

	// slow holds tools/call "slow" until closed.
	slow chan struct{}
}

type mcpReq struct {
	header http.Header
	body   string
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{
		t: t, devicePolls: []string{""}, pollIndex: map[string]int{}, clients: map[string]bool{},
		access: map[string]bool{}, refresh: map[string]string{}, used: map[string]bool{},
		expiresIn: 3600, slow: make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", g.prm)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", g.prm)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", g.asm)
	mux.HandleFunc("POST /oauth/register", g.register)
	mux.HandleFunc("POST /oauth/device_authorization", g.device)
	mux.HandleFunc("POST /oauth/token", g.token)
	mux.HandleFunc("POST /oauth/revoke", g.revoke)
	mux.HandleFunc("POST /mcp", g.mcp)
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) URL() string { return g.srv.URL }

func (g *fakeGateway) prm(w http.ResponseWriter, _ *http.Request) {
	writeJSONT(w, 200, map[string]any{
		"resource": g.URL() + "/mcp", "authorization_servers": []string{g.URL()},
		"bearer_methods_supported": []string{"header"}, "scopes_supported": []string{"mcp", "mcp:read"},
	})
}

func (g *fakeGateway) asm(w http.ResponseWriter, _ *http.Request) {
	b := g.URL()
	g.mu.Lock()
	other := g.foreign
	noRevoke := g.noRevoke
	g.mu.Unlock()
	if other == "" {
		other = b
	}
	doc := map[string]any{
		"issuer": b, "authorization_endpoint": b + "/oauth/authorize", "token_endpoint": other + "/oauth/token",
		"registration_endpoint": other + "/oauth/register", "device_authorization_endpoint": b + "/oauth/device_authorization",
		"grant_types_supported": []string{"authorization_code", "refresh_token", deviceGrant},
	}
	if !noRevoke {
		doc["revocation_endpoint"] = other + "/oauth/revoke"
	}
	writeJSONT(w, 200, doc)
}

// revoke is RFC 7009: the refresh token's family ends (here: the token).
func (g *fakeGateway) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.revokeReqs = append(g.revokeReqs, r.PostForm)
	if g.revokeStatus != 0 {
		writeJSONT(w, g.revokeStatus, map[string]string{"error": "server_error"})
		return
	}
	if g.refresh[r.PostForm.Get("token")] == r.PostForm.Get("client_id") {
		delete(g.refresh, r.PostForm.Get("token"))
	}
	w.WriteHeader(http.StatusOK)
}

func (g *fakeGateway) revocations() []url.Values {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]url.Values(nil), g.revokeReqs...)
}

func (g *fakeGateway) register(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONT(w, 400, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.registrations = append(g.registrations, req)
	g.nextID++
	id := fmt.Sprintf("gwc_client%d", g.nextID)
	g.clients[id] = true
	writeJSONT(w, 201, map[string]any{"client_id": id, "token_endpoint_auth_method": "none", "grant_types": req["grant_types"]})
}

func (g *fakeGateway) device(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.deviceReqs = append(g.deviceReqs, r.PostForm)
	if !g.clients[r.PostForm.Get("client_id")] {
		writeJSONT(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	g.nextID++
	code := fmt.Sprintf("gwd_device%d", g.nextID)
	writeJSONT(w, 200, map[string]any{
		"device_code": code, "user_code": fakeUser, "verification_uri": g.URL() + "/activate",
		"verification_uri_complete": g.URL() + "/activate?code=" + fakeUser, "expires_in": 600, "interval": 5,
	})
}

func (g *fakeGateway) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.PostForm
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tokenReqs = append(g.tokenReqs, f)
	client := f.Get("client_id")
	if !g.clients[client] {
		writeJSONT(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	switch f.Get("grant_type") {
	case deviceGrant:
		code := f.Get("device_code")
		i := g.pollIndex[code]
		g.pollIndex[code] = i + 1
		answer := g.devicePolls[min(i, len(g.devicePolls)-1)]
		if answer != "" {
			writeJSONT(w, 400, map[string]string{"error": answer})
			return
		}
		g.issue(w, client)
	case "refresh_token":
		rt := f.Get("refresh_token")
		owner, ok := g.refresh[rt]
		switch {
		case g.used[rt]:
			// Reuse revokes the family: every live token of the client.
			for k, c := range g.refresh {
				if c == owner || c == client {
					delete(g.refresh, k)
				}
			}
			writeJSONT(w, 400, map[string]string{"error": "invalid_grant", "error_description": "the refresh token was already used"})
			return
		case !ok || owner != client:
			writeJSONT(w, 400, map[string]string{"error": "invalid_grant", "error_description": "the refresh token is invalid"})
			return
		}
		delete(g.refresh, rt)
		g.used[rt] = true
		g.issue(w, client)
	default:
		writeJSONT(w, 400, map[string]string{"error": "unsupported_grant_type"})
	}
}

// issue answers a token response; g.mu is held.
func (g *fakeGateway) issue(w http.ResponseWriter, client string) {
	g.nextID++
	at := fmt.Sprintf("at-%d", g.nextID)
	rt := fmt.Sprintf("gwr_rt%d_%s", g.nextID, g.srv.Listener.Addr().String())
	g.access[at] = true
	g.refresh[rt] = client
	writeJSONT(w, 200, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": g.expiresIn, "refresh_token": rt, "scope": "mcp"})
}

// seedRT is the refresh token a previous run of the proxy left.
const seedRT = "gwr_rtseed"

// seedOldClient registers "gwc_old" with the live refresh token seedRT,
// as a previous run of the proxy left them.
func (g *fakeGateway) seedOldClient() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.clients["gwc_old"] = true
	g.refresh[seedRT] = "gwc_old"
}

func (g *fakeGateway) revokeAllRefresh() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refresh = map[string]string{}
}

func (g *fakeGateway) snapshot() (regs []map[string]any, dev, tok []url.Values, mcp []mcpReq) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]map[string]any(nil), g.registrations...), append([]url.Values(nil), g.deviceReqs...),
		append([]url.Values(nil), g.tokenReqs...), append([]mcpReq(nil), g.mcpReqs...)
}

func (g *fakeGateway) grantTypes() []string {
	_, _, tok, _ := g.snapshot()
	var out []string
	for _, f := range tok {
		out = append(out, f.Get("grant_type"))
	}
	return out
}

func (g *fakeGateway) mcp(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	g.mu.Lock()
	g.mcpReqs = append(g.mcpReqs, mcpReq{header: r.Header.Clone(), body: string(body)})
	ok := g.access[tok]
	if ok && (g.rejectAll || g.rejectOnce) {
		g.rejectOnce = false
		delete(g.access, tok)
		ok = false
	}
	session := g.sessionID
	g.mu.Unlock()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway", error="invalid_token"`)
		writeJSONT(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") || !strings.Contains(r.Header.Get("Accept"), "application/json") {
		http.Error(w, "bad accept", http.StatusNotAcceptable)
		return
	}
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		// A batch: answer every request in one JSON array.
		var batch []json.RawMessage
		_ = json.Unmarshal(body, &batch)
		var out []map[string]any
		for _, m := range batch {
			msg.ID, msg.Method = nil, ""
			_ = json.Unmarshal(m, &msg)
			if len(msg.ID) > 0 {
				out = append(out, map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"method": msg.Method}})
			}
		}
		writeJSONT(w, 200, out)
		return
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		writeJSONT(w, 400, map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
		return
	}
	if len(msg.ID) == 0 { // a notification or a response
		w.WriteHeader(http.StatusAccepted)
		return
	}
	result := map[string]any{"method": msg.Method}
	switch msg.Method {
	case "initialize":
		result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": "fake", "version": "1"}}
		if session != "" {
			w.Header().Set("Mcp-Session-Id", session)
		}
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		if p.Name == "slow" {
			select {
			case <-g.slow:
			case <-r.Context().Done():
				return
			}
		}
		result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "called " + p.Name}}}
	case "sse":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, ": comment\n\nevent: message\nid: 1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\n")
		_, _ = fmt.Fprint(w, "data: \"params\":{\"progress\":1}}\n\n")
		_, _ = fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"via\":\"sse\"}}\r\n\r\n", msg.ID)
		return
	case "pretty":
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": %s,\n  \"result\": {\"multi\": \"line\"}\n}\n", msg.ID)
		return
	case "http500":
		http.Error(w, "upstream exploded", http.StatusInternalServerError)
		return
	}
	writeJSONT(w, 200, map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
}

func writeJSONT(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fakeClock is Now and Sleep for the proxy: Sleep advances time at once.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.sleeps = append(c.sleeps, d)
	c.mu.Unlock()
	return ctx.Err()
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) Sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}
