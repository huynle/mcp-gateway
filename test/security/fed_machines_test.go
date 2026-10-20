//go:build integration || e2e || security

package security

// Machine enrollment attacks (Brain decision ldjix4y1, docs/machines.md):
// forged, expired, replayed and mis-addressed assertions; revoked
// machines and inactive owners; machine tokens outside the machine API;
// one machine reaching another's or another user's servers; device code
// guessing; the approval page; enrollment codes under concurrency;
// revocation closing the live connection.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/machines"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// mach is an enrolled machine as its CLI holds it.
type mach struct {
	id   string
	priv ed25519.PrivateKey
}

// mcall calls a machine endpoint and decodes the JSON answer.
func (w *world) mcall(method, path, token, ctype, body string) (int, map[string]any) {
	w.t.Helper()
	req, _ := http.NewRequestWithContext(w.t.Context(), method, w.srv.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return res.StatusCode, out
}

func (w *world) tokenForm(v url.Values) (int, map[string]any) {
	return w.mcall(http.MethodPost, machines.TokenPath, "", "application/x-www-form-urlencoded", v.Encode())
}

// deviceRequest starts a device flow for a fresh key.
func (w *world) deviceRequest(name string) (deviceCode, userCode string, priv ed25519.PrivateKey) {
	w.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body, _ := json.Marshal(map[string]any{"name": name, "public_key": machines.PublicJWK(pub), "client_version": "sec"})
	code, out := w.mcall(http.MethodPost, machines.DeviceAuthorizationPath, "", "application/json", string(body))
	if code != http.StatusOK {
		w.t.Fatalf("device_authorization = %d %v", code, out)
	}
	deviceCode, userCode = out["device_code"].(string), out["user_code"].(string)
	w.forbid(deviceCode, "device code")
	return deviceCode, userCode, priv
}

var requestIDRE = regexp.MustCompile(`name="request_id" value="([0-9a-f-]{36})"`)

// approveInBrowser approves a user code on /activate as u.
func (w *world) approveInBrowser(u user, userCode string) (int, string) {
	w.t.Helper()
	code, _, html := w.get(u, "/activate?code="+url.QueryEscape(userCode))
	m := requestIDRE.FindStringSubmatch(html)
	if code != http.StatusOK || m == nil {
		return code, html
	}
	code, _, html = w.post(u, "/activate", url.Values{"action": {"approve"}, "request_id": {m[1]}, "code": {userCode}})
	return code, html
}

// enrollMachine runs the device flow, approved by u.
func (w *world) enrollMachine(u user, name string) mach {
	w.t.Helper()
	dc, uc, priv := w.deviceRequest(name)
	if code, html := w.approveInBrowser(u, uc); code != http.StatusOK || !strings.Contains(html, "Machine connected") {
		w.t.Fatalf("approve = %d\n%s", code, html)
	}
	code, out := w.tokenForm(url.Values{"grant_type": {machines.GrantDeviceCode}, "device_code": {dc}})
	if code != http.StatusOK {
		w.t.Fatalf("device token = %d %v", code, out)
	}
	return mach{id: out["machine_id"].(string), priv: priv}
}

// sign builds an assertion for m with claims changed by mod.
func (w *world) sign(priv ed25519.PrivateKey, machineID string, mod func(map[string]any)) string {
	w.t.Helper()
	now := time.Now()
	c := map[string]any{"iss": machineID, "sub": machineID, "aud": baseURL + machines.TokenPath,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": rand.Text()}
	if mod != nil {
		mod(c)
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		w.t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(c).Serialize()
	if err != nil {
		w.t.Fatal(err)
	}
	w.forbid(raw, "machine assertion")
	return raw
}

func (w *world) assertionGrant(a string) (int, map[string]any) {
	return w.tokenForm(url.Values{"grant_type": {machines.GrantJWTBearer}, "assertion": {a}})
}

// machineToken mints an access token for m.
func (w *world) machineToken(m mach) string {
	w.t.Helper()
	code, out := w.assertionGrant(w.sign(m.priv, m.id, nil))
	if code != http.StatusOK {
		w.t.Fatalf("jwt-bearer = %d %v", code, out)
	}
	tok := out["access_token"].(string)
	w.forbid(tok, "machine access token")
	return tok
}

func (w *world) putServer(tok, name string) (int, map[string]any) {
	return w.mcall(http.MethodPut, "/machine/v1/servers/"+name, tok, "application/json", `{"kind":"http","path":"/"}`)
}

// TestSecurityMachineAssertions: only a fresh, correctly signed and
// addressed assertion of a live machine yields a token, once.
func TestSecurityMachineAssertions(t *testing.T) {
	w := newWorld(t, options{federation: true})
	m := w.enrollMachine(w.alice, "laptop")
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	good := w.sign(m.priv, m.id, nil)
	if code, out := w.assertionGrant(good); code != http.StatusOK || out["scope"] != "machine" || out["expires_in"] != float64(600) {
		t.Fatalf("good assertion = %d %v", code, out)
	}
	cases := map[string]string{
		"replayed":                  good,
		"forged (other key)":        w.sign(other, m.id, nil),
		"wrong aud (/mcp)":          w.sign(m.priv, m.id, func(c map[string]any) { c["aud"] = baseURL + "/mcp" }),
		"wrong aud (other gateway)": w.sign(m.priv, m.id, func(c map[string]any) { c["aud"] = "https://evil.example" + machines.TokenPath }),
		"expired": w.sign(m.priv, m.id, func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(-10*time.Minute).Unix(), now.Add(-6*time.Minute).Unix()
		}),
		"too long-lived":         w.sign(m.priv, m.id, func(c map[string]any) { c["exp"] = now.Add(time.Hour).Unix() }),
		"sub of another machine": w.sign(m.priv, m.id, func(c map[string]any) { c["sub"] = "00000000-0000-4000-8000-000000000000" }),
		"unknown machine":        w.sign(m.priv, "00000000-0000-4000-8000-000000000000", nil),
		"alg none": func() string {
			p := strings.Split(good, ".")
			return "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + p[1] + "."
		}(),
	}
	for name, a := range cases {
		if code, out := w.assertionGrant(a); code != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

// TestSecurityMachineRevokedAndInactiveOwner: revocation and an inactive
// owner stop both new tokens and existing ones.
func TestSecurityMachineRevokedAndInactiveOwner(t *testing.T) {
	w := newWorld(t, options{federation: true})
	m := w.enrollMachine(w.alice, "laptop")
	tok := w.machineToken(m)
	if code, _ := w.mcall(http.MethodGet, "/machine/v1/self", tok, "", ""); code != http.StatusOK {
		t.Fatalf("self = %d", code)
	}
	// Owner revokes on /machines.
	if code, _, _ := w.post(w.alice, "/machines/"+m.id+"/revoke", nil); code != http.StatusSeeOther {
		t.Fatalf("revoke = %d", code)
	}
	if code, out := w.mcall(http.MethodGet, "/machine/v1/self", tok, "", ""); code != http.StatusForbidden || out["error"] != "revoked" {
		t.Fatalf("token of a revoked machine = %d %v", code, out)
	}
	if code, _ := w.assertionGrant(w.sign(m.priv, m.id, nil)); code != http.StatusBadRequest {
		t.Fatalf("assertion of a revoked machine = %d", code)
	}

	// Bob's machine, then Bob is disabled by an admin.
	mb := w.enrollMachine(w.bob, "desk")
	tokB := w.machineToken(mb)
	w.exec(`UPDATE users SET status = 'disabled' WHERE id = $1`, w.bob.id)
	if code, _ := w.mcall(http.MethodGet, "/machine/v1/self", tokB, "", ""); code != http.StatusForbidden {
		t.Fatalf("token of a disabled owner = %d", code)
	}
	if code, _ := w.assertionGrant(w.sign(mb.priv, mb.id, nil)); code != http.StatusBadRequest {
		t.Fatalf("assertion of a disabled owner = %d", code)
	}
	w.exec(`UPDATE users SET status = 'pending' WHERE id = $1`, w.bob.id)
	if code, _ := w.mcall(http.MethodGet, "/machine/v1/self", tokB, "", ""); code != http.StatusForbidden {
		t.Fatalf("token of a pending owner = %d", code)
	}
}

// TestSecurityMachineTokenScope: a machine token is accepted by the
// machine API only: not by /mcp, the portal, the legacy tunnel endpoint
// or the OAuth endpoints.
func TestSecurityMachineTokenScope(t *testing.T) {
	w := newWorld(t, options{federation: true})
	m := w.enrollMachine(w.alice, "laptop")
	tok := w.machineToken(m)
	if code, _, _ := w.rawCall(tok, "fake.list_items", map[string]any{}); code != http.StatusUnauthorized {
		t.Errorf("/mcp with a machine token = %d, want 401", code)
	}
	for _, path := range []string{"/machines", "/servers", "/account", "/tokens", "/admin/machines", "/activate"} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, w.srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		res, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Errorf("portal %s with a machine token = 200", path)
		}
	}
	if _, status, err := w.dialTunnel(t.Context(), bearer(tok)); err == nil || status != http.StatusUnauthorized {
		t.Errorf("legacy tunnel endpoint with a machine token = %d, %v", status, err)
	}
	// A harness token is not a machine token.
	harness := w.token(w.alice, tokens.CreateRequest{})
	if code, out := w.mcall(http.MethodGet, "/machine/v1/self", harness, "", ""); code != http.StatusUnauthorized || out["error"] != "invalid_token" {
		t.Errorf("machine API with a harness token = %d %v", code, out)
	}
}

// TestSecurityMachineCannotTouchOthersServers: a machine registers and
// refreshes only its own servers; another machine of the same user and
// another user's machine cannot take them, and a machine connection never
// carries a tunnel of another machine.
func TestSecurityMachineCannotTouchOthersServers(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ma := w.enrollMachine(w.alice, "laptop")
	ma2 := w.enrollMachine(w.alice, "desk")
	mb := w.enrollMachine(w.bob, "bobbox")
	tokA, tokA2, tokB := w.machineToken(ma), w.machineToken(ma2), w.machineToken(mb)

	code, out := w.putServer(tokA, "alice-fusion")
	if code != http.StatusOK {
		t.Fatalf("alice PUT = %d %v", code, out)
	}
	aliceTunnel := out["tunnel_id"].(string)
	w.addServer(w.bob, "bob-notes", "https://notes.example/mcp", nil)

	for name, c := range map[string]struct{ tok, server string }{
		"another user's machine takes alice's server": {tokB, "alice-fusion"},
		"another machine of alice takes it":           {tokA2, "alice-fusion"},
		"alice's machine takes bob's server":          {tokA, "bob-notes"},
	} {
		if code, out := w.putServer(c.tok, c.server); code != http.StatusConflict || out["error"] != "name_taken" {
			t.Errorf("%s: %d %v", name, code, out)
		}
		if code, _ := w.mcall(http.MethodPost, "/machine/v1/servers/"+c.server+"/refresh", c.tok, "", ""); code != http.StatusNotFound {
			t.Errorf("%s (refresh): %d", name, code)
		}
	}
	// Bob's server is untouched.
	if u := w.queryString(`SELECT url FROM mcp_servers WHERE name = 'bob-notes'`); u != "https://notes.example/mcp" {
		t.Fatalf("bob's server url = %q", u)
	}
	_, out = w.mcall(http.MethodGet, "/machine/v1/self", tokB, "", "")
	if servers, _ := out["servers"].([]any); len(servers) != 0 || out["owner"] != "Bob" {
		t.Fatalf("bob's machine sees %v", out)
	}

	// Bob's machine connects claiming alice's tunnel: it is not served.
	agent, err := tunnel.NewMachineAgent(tunnel.MachineAgentOptions{
		GatewayURL: w.srv.URL, Log: slog.New(slog.DiscardHandler),
		Token:   func(context.Context) (string, error) { return tokB, nil },
		Targets: map[string]http.Handler{aliceTunnel: http.NotFoundHandler()},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = agent.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w.fed.Tunnels.MachineConnected(mb.id) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !w.fed.Tunnels.MachineConnected(mb.id) {
		t.Fatal("bob's machine did not connect")
	}
	if w.fed.Tunnels.Online(aliceTunnel) {
		t.Fatal("bob's machine connection serves alice's tunnel")
	}
}

// TestSecurityMachineDeviceCodeGuessing: device codes cannot be guessed
// (256 bits, hashed) and failed polls are rate limited per address; user
// codes typed in the browser are rate limited per user.
func TestSecurityMachineDeviceCodeGuessing(t *testing.T) {
	w := newWorld(t, options{federation: true})
	limited := false
	for i := range 60 {
		fake, _ := machines.NewSecret(machines.DeviceCodePrefix)
		code, out := w.tokenForm(url.Values{"grant_type": {machines.GrantDeviceCode}, "device_code": {fake}})
		if code == http.StatusTooManyRequests {
			limited = true
			break
		}
		if code != http.StatusBadRequest || out["error"] != "expired_token" {
			t.Fatalf("guess %d = %d %v", i, code, out)
		}
	}
	if !limited {
		t.Fatal("60 wrong device codes from one address were never rate limited")
	}
	// User code guessing on /activate.
	tooMany := false
	for range 20 {
		code, _, html := w.get(w.bob, "/activate?code=BCDF-GHJK")
		if code == http.StatusTooManyRequests || strings.Contains(html, "Too many wrong codes") {
			tooMany = true
			break
		}
	}
	if !tooMany {
		t.Fatal("20 wrong user codes were never limited")
	}
	// Device authorization itself is limited per address.
	limited = false
	for range 30 {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		body, _ := json.Marshal(map[string]any{"name": "x", "public_key": machines.PublicJWK(pub)})
		if code, _ := w.mcall(http.MethodPost, machines.DeviceAuthorizationPath, "", "application/json", string(body)); code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("device authorization was never rate limited")
	}
}

// TestSecurityMachineApprovalPage: only a signed-in active user reaches
// /activate; the page shows name, fingerprint and IP; an approval binds
// the machine to the approver (whoever started the flow), never to anyone
// else; a pending user's approval does nothing.
func TestSecurityMachineApprovalPage(t *testing.T) {
	w := newWorld(t, options{federation: true})
	dc, uc, _ := w.deviceRequest("mallory-box")
	// Anonymous: sign-in first.
	if code, h, _ := w.get(user{}, "/activate?code="+url.QueryEscape(uc)); code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/signin") {
		t.Fatalf("anonymous /activate = %d %s", code, h.Get("Location"))
	}
	// Without the CSRF token: refused.
	_, _, html := w.get(w.bob, "/activate?code="+url.QueryEscape(uc))
	m := requestIDRE.FindStringSubmatch(html)
	if m == nil || !strings.Contains(html, "mallory-box") || !strings.Contains(html, "127.0.0.1") || !regexp.MustCompile(`<code class="fingerprint">\S{4} \S{4} \S{4} \S{4}</code>`).MatchString(html) {
		t.Fatalf("confirmation page lacks name, IP or a 4x4 fingerprint:\n%s", html)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, w.srv.URL+"/activate",
		strings.NewReader(url.Values{"action": {"approve"}, "request_id": {m[1]}, "code": {uc}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(w.bob.cookie)
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("approve without CSRF = %d", res.StatusCode)
	}
	// A pending user cannot approve.
	w.exec(`UPDATE users SET status = 'pending' WHERE id = $1`, w.alice.id)
	if code, html := w.approveInBrowser(w.alice, uc); code == http.StatusOK && strings.Contains(html, "Machine connected") {
		t.Fatal("a pending user approved a machine")
	}
	if n := w.queryString(`SELECT count(*)::text FROM machines WHERE owner_user_id = $1`, w.alice.id); n != "0" {
		t.Fatalf("pending alice owns %s machines", n)
	}
	w.exec(`UPDATE users SET status = 'active' WHERE id = $1`, w.alice.id)
	// Bob approves the code someone else started: the machine is Bob's.
	if code, html := w.approveInBrowser(w.bob, uc); code != http.StatusOK || !strings.Contains(html, "Machine connected") {
		t.Fatalf("bob approves = %d\n%s", code, html)
	}
	code, out := w.tokenForm(url.Values{"grant_type": {machines.GrantDeviceCode}, "device_code": {dc}})
	if code != http.StatusOK {
		t.Fatalf("poll = %d %v", code, out)
	}
	if owner := w.queryString(`SELECT owner_user_id::text FROM machines WHERE id = $1`, out["machine_id"]); owner != w.bob.id {
		t.Fatalf("machine owner = %s, want the approver %s", owner, w.bob.id)
	}
	// The machine id is handed out once.
	if code, out := w.tokenForm(url.Values{"grant_type": {machines.GrantDeviceCode}, "device_code": {dc}}); code != http.StatusBadRequest || out["error"] != "expired_token" {
		t.Fatalf("second poll = %d %v", code, out)
	}
	// Alice cannot approve it again.
	if code, html := w.approveInBrowser(w.alice, uc); code == http.StatusOK && strings.Contains(html, "Machine connected") {
		t.Fatal("an approved request was approved again")
	}
	// The audit shows the approval under the approver.
	found := false
	for _, e := range w.events(w.bob) {
		found = found || e.ResourceIdentity["action"] == "machine.approved"
	}
	if !found {
		t.Fatal("no machine.approved event for the approver")
	}
}

// TestSecurityMachineEnrollmentCodeSingleUse: concurrent enrollments with
// one code: exactly one machine.
func TestSecurityMachineEnrollmentCodeSingleUse(t *testing.T) {
	w := newWorld(t, options{federation: true})
	code, _, html := w.post(w.alice, "/machines/codes", url.Values{"label": {"ci"}, "ttl": {"1h"}})
	raw := regexp.MustCompile(`mge_[A-Za-z0-9]{8}_[A-Za-z0-9]{43}`).FindString(html)
	if code != http.StatusOK || raw == "" {
		t.Fatalf("create code = %d", code)
	}
	w.forbid(raw, "enrollment code")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			body, _ := json.Marshal(map[string]any{"code": raw, "name": "runner", "public_key": machines.PublicJWK(pub)})
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, w.srv.URL+machines.EnrollPath, strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent enrollments succeeded with one code, want 1", wins.Load())
	}
	if n := w.queryString(`SELECT count(*)::text FROM machines WHERE owner_user_id = $1`, w.alice.id); n != "1" {
		t.Fatalf("alice has %s machines", n)
	}
	// Codes are stored hashed only.
	if n := w.queryString(`SELECT count(*)::text FROM machine_enrollment_codes WHERE code_hash = convert_to($1, 'UTF8')`, raw); n != "0" {
		t.Fatal("an enrollment code is stored in clear")
	}
}

// TestSecurityMachineRevocationClosesTheConnection: revoking (owner or
// admin) closes the live machine connection with 4003 at once and takes
// its servers offline.
func TestSecurityMachineRevocationClosesTheConnection(t *testing.T) {
	w := newWorld(t, options{federation: true})
	for _, byAdmin := range []bool{false, true} {
		name := "laptop"
		if byAdmin {
			name = "desk"
		}
		m := w.enrollMachine(w.alice, name)
		tok := w.machineToken(m)
		_, out := w.putServer(tok, name+"-srv")
		tid := out["tunnel_id"].(string)
		agent, err := tunnel.NewMachineAgent(tunnel.MachineAgentOptions{
			GatewayURL: w.srv.URL, Log: slog.New(slog.DiscardHandler),
			Token:   func(context.Context) (string, error) { return tok, nil },
			Targets: map[string]http.Handler{tid: http.NotFoundHandler()},
		})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- agent.Run(t.Context()) }()
		deadline := time.Now().Add(5 * time.Second)
		for !w.fed.Tunnels.Online(tid) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if !w.fed.Tunnels.Online(tid) {
			t.Fatal("machine tunnel not online")
		}
		var code int
		if byAdmin {
			code, _, _ = w.post(w.admin, "/admin/machines/"+m.id+"/revoke", nil)
		} else {
			code, _, _ = w.post(w.alice, "/machines/"+m.id+"/revoke", nil)
		}
		if code != http.StatusSeeOther {
			t.Fatalf("revoke (admin=%v) = %d", byAdmin, code)
		}
		select {
		case err := <-done:
			if !errors.Is(err, tunnel.ErrRevoked) {
				t.Fatalf("agent ended with %v, want ErrRevoked", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("revocation (admin=%v) did not close the connection", byAdmin)
		}
		if w.fed.Tunnels.Online(tid) {
			t.Fatal("tunnel of a revoked machine still online")
		}
		// A non-admin cannot use the admin revoke.
		if !byAdmin {
			mb := w.enrollMachine(w.bob, "bobbox")
			if code, _, _ := w.post(w.alice, "/admin/machines/"+mb.id+"/revoke", nil); code != http.StatusNotFound {
				t.Fatalf("non-admin admin revoke = %d", code)
			}
			if code, _, _ := w.post(w.alice, "/machines/"+mb.id+"/revoke", nil); code != http.StatusNotFound {
				t.Fatalf("alice revokes bob's machine = %d", code)
			}
		}
	}
}
