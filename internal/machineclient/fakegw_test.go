package machineclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGateway implements the machine endpoints of the gateway contract
// (docs/machines.md) in memory, strictly enough to catch client mistakes:
// it verifies assertion signatures, audience, lifetime and jti replay, and
// requires a live mgm_ bearer token on the machine API.
type fakeGateway struct {
	t   *testing.T
	srv *httptest.Server
	now func() time.Time

	mu sync.Mutex
	// device flow
	deviceReqs   []map[string]any
	pollScript   []string // error codes returned in order, then success
	polls        int
	deviceCode   string
	userCode     string
	interval     int
	enrollCode   string
	enrollReqs   []map[string]any
	machineID    string
	machineName  string
	pub          ed25519.PublicKey
	revoked      bool
	tokenTTL     int
	tokens       map[string]time.Time // live access tokens → expiry
	allTokens    []string
	issued       int
	jtis         map[string]bool
	assertions   []string
	failNextAPI  int // force 401 invalid_token on the next N machine API calls
	servers      map[string]*fakeServer
	puts         []string
	refreshes    []string
	logouts      int
	nameTakenFor map[string]bool
	capAfter     int // 409 cap_exceeded once more than capAfter servers exist (0 = no cap)
	offline      bool
}

type fakeServer struct {
	name, kind, path, serverID, tunnelID string
	approved                             int
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{
		t: t, now: time.Now, deviceCode: "dev-code-SECRET", userCode: "BCDF-GHJK", interval: 5,
		enrollCode: "mge_ENROLLSECRET", machineID: "0b9a3f4e-2c1d-4e5f-8a7b-6c5d4e3f2a1b", tokenTTL: 600,
		tokens: map[string]time.Time{}, jtis: map[string]bool{}, servers: map[string]*fakeServer{}, nameTakenFor: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /machine/device_authorization", g.deviceAuthorization)
	mux.HandleFunc("POST /machine/token", g.token)
	mux.HandleFunc("POST /machine/enroll", g.enroll)
	mux.HandleFunc("GET /machine/v1/self", g.api(g.self))
	mux.HandleFunc("PUT /machine/v1/servers/{name}", g.api(g.put))
	mux.HandleFunc("POST /machine/v1/servers/{name}/refresh", g.api(g.refresh))
	mux.HandleFunc("POST /machine/v1/logout", g.api(g.logout))
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) URL() string { return g.srv.URL }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": "fake: " + code})
}

func (g *fakeGateway) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		oauthErr(w, 400, "invalid_request")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.deviceReqs = append(g.deviceReqs, body)
	g.machineName, _ = body["name"].(string)
	g.pub = jwkPub(g.t, body["public_key"])
	writeJSON(w, 200, map[string]any{
		"device_code": g.deviceCode, "user_code": g.userCode,
		"verification_uri": g.URL() + "/activate", "verification_uri_complete": g.URL() + "/activate?code=" + g.userCode,
		"expires_in": 600, "interval": g.interval,
	})
}

func jwkPub(t *testing.T, v any) ed25519.PublicKey {
	m, _ := v.(map[string]any)
	if m["kty"] != "OKP" || m["crv"] != "Ed25519" {
		t.Errorf("bad jwk %v", v)
		return nil
	}
	x, err := base64.RawURLEncoding.DecodeString(m["x"].(string))
	if err != nil || len(x) != ed25519.PublicKeySize {
		t.Errorf("bad jwk x %v", v)
		return nil
	}
	return x
}

func (g *fakeGateway) enroll(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		oauthErr(w, 400, "invalid_request")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.enrollReqs = append(g.enrollReqs, body)
	if body["code"] != g.enrollCode {
		oauthErr(w, 400, "invalid_code")
		return
	}
	g.enrollCode = "used"
	g.machineName, _ = body["name"].(string)
	g.pub = jwkPub(g.t, body["public_key"])
	writeJSON(w, 200, map[string]any{"machine_id": g.machineID, "name": g.machineName, "gateway": g.URL()})
}

func (g *fakeGateway) token(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		g.t.Errorf("token endpoint content type %q", ct)
	}
	if err := r.ParseForm(); err != nil {
		oauthErr(w, 400, "invalid_request")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch r.PostForm.Get("grant_type") {
	case "urn:ietf:params:oauth:grant-type:device_code":
		if r.PostForm.Get("device_code") != g.deviceCode {
			oauthErr(w, 400, "expired_token")
			return
		}
		g.polls++
		if g.polls <= len(g.pollScript) {
			oauthErr(w, 400, g.pollScript[g.polls-1])
			return
		}
		g.deviceCode = "consumed"
		writeJSON(w, 200, map[string]any{"machine_id": g.machineID, "name": g.machineName, "gateway": g.URL()})
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		a := r.PostForm.Get("assertion")
		g.assertions = append(g.assertions, a)
		if err := g.checkAssertion(a); err != nil {
			g.t.Logf("fake gateway: assertion refused: %v", err)
			oauthErr(w, 400, "invalid_grant")
			return
		}
		g.issued++
		tok := fmt.Sprintf("mgm_%08d_%s", g.issued, randB64(32))
		g.allTokens = append(g.allTokens, tok)
		g.tokens[tok] = g.now().Add(time.Duration(g.tokenTTL) * time.Second)
		writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": g.tokenTTL, "scope": "machine"})
	default:
		oauthErr(w, 400, "unsupported_grant_type")
	}
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (g *fakeGateway) checkAssertion(a string) error {
	if g.revoked {
		return fmt.Errorf("revoked")
	}
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWS")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || g.pub == nil || !ed25519.Verify(g.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return fmt.Errorf("bad signature")
	}
	var hdr map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if json.Unmarshal(hb, &hdr) != nil || hdr["alg"] != "EdDSA" || hdr["typ"] != "JWT" {
		return fmt.Errorf("bad header %s", hb)
	}
	var c struct {
		Iss, Sub, Aud, Jti string
		Iat, Exp          int64
	}
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(cb, &c); err != nil {
		return err
	}
	now := g.now().Unix()
	switch {
	case c.Iss != g.machineID || c.Sub != g.machineID:
		return fmt.Errorf("iss/sub %q %q", c.Iss, c.Sub)
	case c.Aud != g.URL()+"/machine/token":
		return fmt.Errorf("aud %q", c.Aud)
	case c.Exp > c.Iat+300 || c.Exp <= c.Iat:
		return fmt.Errorf("lifetime")
	case c.Iat > now+60 || c.Exp < now-60:
		return fmt.Errorf("expired or future")
	case c.Jti == "" || g.jtis[c.Jti]:
		return fmt.Errorf("jti replay")
	}
	g.jtis[c.Jti] = true
	return nil
}

func (g *fakeGateway) api(h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		exp, live := g.tokens[tok]
		switch {
		case g.revoked:
			g.mu.Unlock()
			oauthErr(w, 403, "revoked")
			return
		case g.failNextAPI > 0:
			g.failNextAPI--
			delete(g.tokens, tok)
			g.mu.Unlock()
			oauthErr(w, 401, "invalid_token")
			return
		case !ok || !live || !g.now().Before(exp):
			g.mu.Unlock()
			oauthErr(w, 401, "invalid_token")
			return
		}
		g.mu.Unlock()
		h(w, r)
	}
}

func (g *fakeGateway) self(w http.ResponseWriter, _ *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	servers := []map[string]any{}
	for _, s := range g.servers {
		servers = append(servers, map[string]any{
			"name": s.name, "server_id": s.serverID, "tunnel_id": s.tunnelID, "status": "active",
			"approved_tools": s.approved, "review_url": g.URL() + "/servers/" + s.serverID,
		})
	}
	writeJSON(w, 200, map[string]any{"machine_id": g.machineID, "name": g.machineName, "owner": "Huy", "servers": servers})
}

func (g *fakeGateway) put(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct{ Kind, Path string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Kind != "http" && body.Kind != "stdio") {
		oauthErr(w, 400, "invalid_request")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.puts = append(g.puts, name)
	if g.nameTakenFor[name] {
		oauthErr(w, 409, "name_taken")
		return
	}
	s, ok := g.servers[name]
	created := false
	if !ok {
		if g.capAfter > 0 && len(g.servers) >= g.capAfter {
			writeJSON(w, 409, map[string]string{"error": "cap_exceeded", "error_description": "you have reached your limit of servers"})
			return
		}
		n := len(g.servers) + 1
		s = &fakeServer{name: name, serverID: fmt.Sprintf("srv-%d", n), tunnelID: fmt.Sprintf("tun-%d", n)}
		g.servers[name] = s
		created = true
	}
	s.kind, s.path = body.Kind, body.Path
	writeJSON(w, 200, map[string]any{
		"name": name, "server_id": s.serverID, "tunnel_id": s.tunnelID, "created": created,
		"review_url": g.URL() + "/servers/" + s.serverID,
	})
}

func (g *fakeGateway) refresh(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refreshes = append(g.refreshes, name)
	s, ok := g.servers[name]
	switch {
	case !ok:
		oauthErr(w, 404, "not_found")
	case g.offline:
		oauthErr(w, 409, "offline")
	default:
		writeJSON(w, 200, map[string]any{"version": 1, "added": 3, "changed": 0, "removed": 0, "review_url": g.URL() + "/servers/" + s.serverID})
	}
}

func (g *fakeGateway) logout(w http.ResponseWriter, _ *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.logouts++
	g.revoked = true
	w.WriteHeader(http.StatusNoContent)
}

// secrets returns every secret value the fake handed out or received, for
// leak checks.
func (g *fakeGateway) secrets() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := []string{"dev-code-SECRET", "mge_ENROLLSECRET"}
	out = append(out, g.allTokens...)
	out = append(out, g.assertions...)
	return out
}
