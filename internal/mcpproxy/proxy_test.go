//go:build !windows

package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/machineclient"
)

// syncBuffer is a goroutine-safe stderr.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t       *testing.T
	g       *fakeGateway
	clock   *fakeClock
	dir     string
	secrets machineclient.SecretStore
	stdin   *io.PipeWriter
	lines   chan string
	stderr  *syncBuffer
	done    chan error

	mu  sync.Mutex
	raw []string // every stdout line
}

func baseOptions(t *testing.T, g *fakeGateway, clock *fakeClock, dir string) Options {
	t.Helper()
	ss, err := machineclient.NewSecretStore(machineclient.KeyStoreFile, dir, "mcp-gateway-proxy")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Gateway: g.URL(), Scope: "mcp", ClientName: "mcp-gateway proxy (testhost)", Version: "test",
		Dir: dir, Secrets: ss, Now: clock.Now, Sleep: clock.Sleep,
	}
}

// startProxy runs the proxy over pipes; mutate adjusts the options.
func startProxy(t *testing.T, g *fakeGateway, clock *fakeClock, dir string, mutate func(*Options)) *harness {
	t.Helper()
	o := baseOptions(t, g, clock, dir)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	h := &harness{t: t, g: g, clock: clock, dir: dir, secrets: o.Secrets, stdin: inW, lines: make(chan string, 100), stderr: &syncBuffer{}, done: make(chan error, 1)}
	o.Stdin, o.Stdout, o.Stderr = inR, outW, h.stderr
	if mutate != nil {
		mutate(&o)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		err := Run(ctx, o)
		_ = outW.Close()
		h.done <- err
	}()
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			h.mu.Lock()
			h.raw = append(h.raw, sc.Text())
			h.mu.Unlock()
			h.lines <- sc.Text()
		}
		close(h.lines)
	}()
	return h
}

func (h *harness) send(line string) {
	h.t.Helper()
	if _, err := io.WriteString(h.stdin, line+"\n"); err != nil {
		h.t.Fatalf("write stdin: %v", err)
	}
}

func (h *harness) recv() map[string]any {
	h.t.Helper()
	select {
	case l, ok := <-h.lines:
		if !ok {
			h.t.Fatalf("stdout closed; stderr:\n%s", h.stderr.String())
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			h.t.Fatalf("stdout line is not a JSON object: %q", l)
		}
		return m
	case <-time.After(10 * time.Second):
		h.t.Fatalf("no output; stderr:\n%s", h.stderr.String())
	}
	return nil
}

// noOutput asserts nothing arrives on stdout for a moment.
func (h *harness) noOutput() {
	h.t.Helper()
	select {
	case l, ok := <-h.lines:
		if ok {
			h.t.Fatalf("unexpected output %q", l)
		}
	case <-time.After(200 * time.Millisecond):
	}
}

// finish closes stdin and returns Run's error.
func (h *harness) finish() error {
	h.t.Helper()
	_ = h.stdin.Close()
	select {
	case err := <-h.done:
		return err
	case <-time.After(10 * time.Second):
		h.t.Fatalf("Run did not return after stdin EOF; stderr:\n%s", h.stderr.String())
	}
	return nil
}

// assertProtocolOnly checks that every stdout line is one JSON-RPC 2.0
// message (or batch) and that no token reached stdout or stderr.
func (h *harness) assertProtocolOnly() {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, l := range h.raw {
		var v any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			h.t.Fatalf("stdout line is not JSON: %q", l)
		}
		msgs := []any{v}
		if a, ok := v.([]any); ok {
			msgs = a
		}
		for _, m := range msgs {
			if o, ok := m.(map[string]any); !ok || o["jsonrpc"] != "2.0" {
				h.t.Fatalf("stdout line is not JSON-RPC 2.0: %q", l)
			}
		}
	}
	all := strings.Join(h.raw, "\n") + h.stderr.String()
	for _, secret := range []string{"gwr_rt", "at-", "gwd_device"} {
		if strings.Contains(all, secret) {
			h.t.Fatalf("a token (%s…) was printed:\n%s", secret, all)
		}
	}
}

func idOf(m map[string]any) float64 {
	f, _ := m["id"].(float64)
	return f
}

func seedStored(t *testing.T, o Options, clientID string) {
	t.Helper()
	cs := newCredStore(o.Dir, o.Gateway, o.Secrets)
	ctx := context.Background()
	if err := cs.saveClient(ctx, clientID, "mcp"); err != nil {
		t.Fatal(err)
	}
	if err := cs.saveRefresh(ctx, seedRT); err != nil {
		t.Fatal(err)
	}
}

func storedCreds(t *testing.T, o Options) *credentials {
	t.Helper()
	c, err := newCredStore(o.Dir, o.Gateway, o.Secrets).load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSignInDiscoversRegistersAndPollsDeviceFlow(t *testing.T) {
	g := newFakeGateway(t)
	g.devicePolls = []string{"authorization_pending", "slow_down", "authorization_pending", ""}
	clock := newFakeClock()
	dir := t.TempDir()
	h := startProxy(t, g, clock, dir, func(o *Options) { o.LoginOnly = true })
	if err := h.finish(); err != nil {
		t.Fatalf("login: %v\n%s", err, h.stderr.String())
	}
	regs, dev, _, _ := g.snapshot()
	if len(regs) != 1 {
		t.Fatalf("registrations %d", len(regs))
	}
	r := regs[0]
	if r["client_name"] != "mcp-gateway proxy (testhost)" || r["token_endpoint_auth_method"] != "none" {
		t.Fatalf("registration %v", r)
	}
	gt, _ := json.Marshal(r["grant_types"])
	if string(gt) != `["`+deviceGrant+`","refresh_token"]` {
		t.Fatalf("grant_types %s", gt)
	}
	if _, ok := r["redirect_uris"]; ok {
		t.Fatalf("a device client sends no redirect_uris: %v", r)
	}
	if len(dev) != 1 || dev[0].Get("scope") != "mcp" || dev[0].Get("resource") != g.URL()+"/mcp" || dev[0].Get("client_id") != "gwc_client1" {
		t.Fatalf("device authorization %v", dev)
	}
	if got := g.grantTypes(); len(got) != 4 || got[0] != deviceGrant {
		t.Fatalf("polls %v", got)
	}
	// interval 5 s, then slow_down adds 5 s for good.
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}
	if s := clock.Sleeps(); !slices.Equal(s, want) {
		t.Fatalf("sleeps %v, want %v", s, want)
	}
	errOut := h.stderr.String()
	for _, want := range []string{
		"To sign in, open " + g.URL() + "/activate and enter " + fakeUser,
		g.URL() + "/activate?code=" + fakeUser,
		"Signed in",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr misses %q:\n%s", want, errOut)
		}
	}
	h.assertProtocolOnly()
	c := storedCreds(t, baseOptions(t, g, clock, dir))
	if c.ClientID != "gwc_client1" || !strings.HasPrefix(c.RefreshToken, "gwr_rt") || c.Scope != "mcp" {
		t.Fatalf("stored %+v", c)
	}
	// The refresh token is in its own 0600 file, not in the state file.
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) != 1 {
		t.Fatalf("state files %v", matches)
	}
	state, _ := os.ReadFile(matches[0])
	if strings.Contains(string(state), "gwr_") || !strings.Contains(string(state), "gwc_client1") {
		t.Fatalf("state file %s", state)
	}
}

func TestSignInDeniedOrExpiredFails(t *testing.T) {
	for _, answer := range []string{"access_denied", "expired_token"} {
		t.Run(answer, func(t *testing.T) {
			g := newFakeGateway(t)
			g.devicePolls = []string{"authorization_pending", answer}
			h := startProxy(t, g, newFakeClock(), t.TempDir(), nil)
			h.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
			select {
			case err := <-h.done:
				if err == nil {
					t.Fatal("Run succeeded")
				}
				if answer == "access_denied" && !errors.Is(err, ErrSignInDenied) || answer == "expired_token" && !errors.Is(err, ErrSignInExpired) {
					t.Fatalf("err %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not fail")
			}
		})
	}
}

func TestSignInExpiresByDeadline(t *testing.T) {
	g := newFakeGateway(t)
	g.devicePolls = []string{"authorization_pending"} // forever
	h := startProxy(t, g, newFakeClock(), t.TempDir(), func(o *Options) { o.LoginOnly = true })
	if err := h.finish(); !errors.Is(err, ErrSignInExpired) {
		t.Fatalf("err %v", err)
	}
}

func TestForwardsRequestsAndNotifications(t *testing.T) {
	g := newFakeGateway(t)
	g.sessionID = "sess-1"
	h := startProxy(t, g, newFakeClock(), t.TempDir(), nil)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if m := h.recv(); idOf(m) != 1 || m["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize %v", m)
	}
	h.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	h.noOutput()
	h.send(`{"jsonrpc":"2.0","id":"two","method":"tools/list"}`)
	if m := h.recv(); m["id"] != "two" || m["result"].(map[string]any)["method"] != "tools/list" {
		t.Fatalf("tools/list %v", m)
	}
	h.send(`{"jsonrpc":"2.0","id":3,"method":"pretty"}`)
	if m := h.recv(); idOf(m) != 3 || m["result"].(map[string]any)["multi"] != "line" {
		t.Fatalf("pretty %v", m)
	}
	h.send(`   `) // blank lines are ignored
	h.send(`{not json`)
	if m := h.recv(); m["id"] != nil || m["error"].(map[string]any)["code"] != float64(-32700) {
		t.Fatalf("parse error %v", m)
	}
	h.send(`[{"jsonrpc":"2.0","id":7,"method":"a"},{"jsonrpc":"2.0","method":"n"}]`)
	select {
	case l := <-h.lines:
		var batch []map[string]any
		if err := json.Unmarshal([]byte(l), &batch); err != nil || len(batch) != 1 || idOf(batch[0]) != 7 {
			t.Fatalf("batch %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no batch answer")
	}
	h.send(`{"jsonrpc":"2.0","id":8,"method":"http500"}`)
	if m := h.recv(); idOf(m) != 8 || m["error"] == nil || !strings.Contains(m["error"].(map[string]any)["message"].(string), "500") {
		t.Fatalf("http 500 %v", m)
	}
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
	h.assertProtocolOnly()
	_, _, _, reqs := g.snapshot()
	last := reqs[len(reqs)-1]
	if last.header.Get("Mcp-Protocol-Version") != "2025-06-18" || last.header.Get("Mcp-Session-Id") != "sess-1" {
		t.Fatalf("headers after initialize %v", last.header)
	}
	if reqs[0].header.Get("Mcp-Session-Id") != "" || reqs[0].header.Get("Content-Type") != "application/json" {
		t.Fatalf("first request headers %v", reqs[0].header)
	}
}

func TestSSEResponse(t *testing.T) {
	g := newFakeGateway(t)
	h := startProxy(t, g, newFakeClock(), t.TempDir(), nil)
	h.send(`{"jsonrpc":"2.0","id":5,"method":"sse"}`)
	n := h.recv()
	if n["method"] != "notifications/progress" || n["params"].(map[string]any)["progress"] != float64(1) {
		t.Fatalf("first event %v", n)
	}
	if m := h.recv(); idOf(m) != 5 || m["result"].(map[string]any)["via"] != "sse" {
		t.Fatalf("second event %v", m)
	}
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
	h.assertProtocolOnly()
}

func TestConcurrentRequestsAreNotSerialised(t *testing.T) {
	g := newFakeGateway(t)
	h := startProxy(t, g, newFakeClock(), t.TempDir(), nil)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`)
	h.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fast"}}`)
	if m := h.recv(); idOf(m) != 2 {
		t.Fatalf("the fast call waited behind the slow one: %v", m)
	}
	close(g.slow)
	if m := h.recv(); idOf(m) != 1 {
		t.Fatalf("slow %v", m)
	}
	// Many at once: every answer arrives whole, one per line.
	for i := 10; i < 60; i++ {
		h.send(`{"jsonrpc":"2.0","id":` + itoa(i) + `,"method":"tools/call","params":{"name":"x"}}`)
	}
	seen := map[float64]bool{}
	for range 50 {
		seen[idOf(h.recv())] = true
	}
	if len(seen) != 50 {
		t.Fatalf("answers %d", len(seen))
	}
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
	h.assertProtocolOnly()
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestEOFWaitsForInFlightAnswers(t *testing.T) {
	g := newFakeGateway(t)
	h := startProxy(t, g, newFakeClock(), t.TempDir(), nil)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`)
	time.Sleep(100 * time.Millisecond)
	_ = h.stdin.Close()
	close(g.slow)
	if m := h.recv(); idOf(m) != 1 {
		t.Fatalf("%v", m)
	}
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit")
	}
}

func TestRefreshBeforeExpiryPersistsRotatedToken(t *testing.T) {
	g := newFakeGateway(t)
	g.seedOldClient()
	clock := newFakeClock()
	dir := t.TempDir()
	o := baseOptions(t, g, clock, dir)
	seedStored(t, o, "gwc_old")
	h := startProxy(t, g, clock, dir, nil)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if m := h.recv(); idOf(m) != 1 || m["error"] != nil {
		t.Fatalf("%v", m)
	}
	regs, dev, tok, _ := g.snapshot()
	if len(regs) != 0 || len(dev) != 0 {
		t.Fatalf("a stored sign-in must not register or prompt again: %d %d", len(regs), len(dev))
	}
	if len(tok) != 1 || tok[0].Get("grant_type") != "refresh_token" || tok[0].Get("refresh_token") != "gwr_rtseed" || tok[0].Get("client_id") != "gwc_old" {
		t.Fatalf("token requests %v", tok)
	}
	first := storedCreds(t, o).RefreshToken
	if first == "gwr_rtseed" || !strings.HasPrefix(first, "gwr_rt") {
		t.Fatalf("rotated token not persisted: %q", first)
	}
	// Still fresh: no refresh.
	clock.Advance(30 * time.Minute)
	h.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	h.recv()
	if n := len(g.grantTypes()); n != 1 {
		t.Fatalf("refreshed too early: %d", n)
	}
	// Within a minute of expiry: refreshed with the persisted token.
	clock.Advance(29*time.Minute + 30*time.Second)
	h.send(`{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	h.recv()
	_, _, tok, _ = g.snapshot()
	if len(tok) != 2 || tok[1].Get("refresh_token") != first {
		t.Fatalf("second refresh %v", tok)
	}
	if second := storedCreds(t, o).RefreshToken; second == first {
		t.Fatal("second rotation not persisted")
	}
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
	h.assertProtocolOnly()
}

func TestUnauthorizedRefreshesAndRetriesOnce(t *testing.T) {
	g := newFakeGateway(t)
	h := startProxy(t, g, newFakeClock(), t.TempDir(), nil)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	h.recv()
	g.mu.Lock()
	g.rejectOnce = true
	g.mu.Unlock()
	h.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if m := h.recv(); idOf(m) != 2 || m["error"] != nil {
		t.Fatalf("retry %v", m)
	}
	if got := g.grantTypes(); !slices.Equal(got, []string{deviceGrant, "refresh_token"}) {
		t.Fatalf("grants %v", got)
	}
	// Always 401: one refresh and one retry, then an error answer.
	g.mu.Lock()
	g.rejectAll = true
	g.mu.Unlock()
	_, _, _, before := g.snapshot()
	h.send(`{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	m := h.recv()
	if idOf(m) != 3 || m["error"] == nil {
		t.Fatalf("persistent 401 %v", m)
	}
	_, _, _, after := g.snapshot()
	if len(after)-len(before) != 2 {
		t.Fatalf("posts for one request after 401: %d", len(after)-len(before))
	}
	h.send(`{"jsonrpc":"2.0","method":"notifications/x"}`)
	h.noOutput() // a failed notification has no id to answer
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
	h.assertProtocolOnly()
}

func TestInvalidGrantRerunsDeviceFlow(t *testing.T) {
	g := newFakeGateway(t)
	g.seedOldClient()
	clock := newFakeClock()
	dir := t.TempDir()
	o := baseOptions(t, g, clock, dir)
	seedStored(t, o, "gwc_old")
	g.revokeAllRefresh() // Disconnect on /harnesses
	h := startProxy(t, g, clock, dir, nil)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if m := h.recv(); idOf(m) != 1 || m["error"] != nil {
		t.Fatalf("%v", m)
	}
	regs, dev, _, _ := g.snapshot()
	if len(regs) != 0 || len(dev) != 1 || dev[0].Get("client_id") != "gwc_old" {
		t.Fatalf("expected a new device flow with the same client: regs %d dev %v", len(regs), dev)
	}
	if got := g.grantTypes(); !slices.Equal(got, []string{"refresh_token", deviceGrant}) {
		t.Fatalf("grants %v", got)
	}
	if !strings.Contains(h.stderr.String(), "To sign in") {
		t.Fatalf("stderr %s", h.stderr.String())
	}
	c := storedCreds(t, o)
	if c.ClientID != "gwc_old" || c.RefreshToken == "gwr_rtseed" || c.RefreshToken == "" {
		t.Fatalf("stored %+v", c)
	}
	// Revoked while running: the next refresh re-runs the device flow.
	g.revokeAllRefresh()
	g.mu.Lock()
	g.rejectOnce = true
	g.mu.Unlock()
	h.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if m := h.recv(); idOf(m) != 2 || m["error"] != nil {
		t.Fatalf("%v", m)
	}
	if _, dev, _, _ = g.snapshot(); len(dev) != 2 {
		t.Fatalf("device flows %d", len(dev))
	}
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
	h.assertProtocolOnly()
}

func TestUnknownClientRegistersAgain(t *testing.T) {
	g := newFakeGateway(t)
	clock := newFakeClock()
	dir := t.TempDir()
	o := baseOptions(t, g, clock, dir)
	seedStored(t, o, "gwc_pruned") // the gateway pruned the client
	h := startProxy(t, g, clock, dir, func(o *Options) { o.LoginOnly = true })
	if err := h.finish(); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	regs, _, _, _ := g.snapshot()
	if len(regs) != 1 {
		t.Fatalf("registrations %d", len(regs))
	}
	if c := storedCreds(t, o); c.ClientID != "gwc_client1" {
		t.Fatalf("stored %+v", c)
	}
}

func TestScopeChangeSignsInAgain(t *testing.T) {
	g := newFakeGateway(t)
	g.seedOldClient()
	clock := newFakeClock()
	dir := t.TempDir()
	o := baseOptions(t, g, clock, dir)
	seedStored(t, o, "gwc_old")
	h := startProxy(t, g, clock, dir, func(o *Options) { o.Scope = "mcp:read"; o.LoginOnly = true })
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
	_, dev, _, _ := g.snapshot()
	if len(dev) != 1 || dev[0].Get("scope") != "mcp:read" {
		t.Fatalf("device %v", dev)
	}
	if c := storedCreds(t, o); c.Scope != "mcp:read" || c.ClientID != "gwc_old" {
		t.Fatalf("stored %+v", c)
	}
	// The sign-in for the old scope is revoked first (best effort).
	rev := g.revocations()
	if len(rev) != 1 || rev[0].Get("token") != seedRT || rev[0].Get("client_id") != "gwc_old" || rev[0].Get("token_type_hint") != "refresh_token" {
		t.Fatalf("revocations %v", rev)
	}
	if strings.Contains(h.stderr.String(), "waiting for another") {
		t.Errorf("waited for a lock nobody held:\n%s", h.stderr.String())
	}
}

// Revoking the old scope's sign-in never blocks the new one: a failing
// revocation endpoint, or none advertised, still signs in.
func TestScopeChangeRevokeIsBestEffort(t *testing.T) {
	for name, set := range map[string]func(*fakeGateway){
		"revocation fails":       func(g *fakeGateway) { g.revokeStatus = http.StatusServiceUnavailable },
		"no revocation endpoint": func(g *fakeGateway) { g.noRevoke = true },
	} {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t)
			g.seedOldClient()
			set(g)
			clock := newFakeClock()
			dir := t.TempDir()
			seedStored(t, baseOptions(t, g, clock, dir), "gwc_old")
			h := startProxy(t, g, clock, dir, func(o *Options) { o.Scope = "mcp:read"; o.LoginOnly = true })
			if err := h.finish(); err != nil {
				t.Fatalf("%v\n%s", err, h.stderr.String())
			}
			if c := storedCreds(t, baseOptions(t, g, clock, dir)); c.Scope != "mcp:read" || c.RefreshToken == seedRT {
				t.Fatalf("stored %+v", c)
			}
			if n := len(g.revocations()); (name == "no revocation endpoint") != (n == 0) {
				t.Fatalf("%d revocation requests", n)
			}
		})
	}
}

// A proxy that finds another proxy of the same gateway signing in (the
// credential lock is held) says so once on stderr and carries on when
// the lock is released.
func TestWaitingForAnotherProxySaysSoOnce(t *testing.T) {
	g := newFakeGateway(t)
	g.seedOldClient()
	clock := newFakeClock()
	dir := t.TempDir()
	o := baseOptions(t, g, clock, dir)
	seedStored(t, o, "gwc_old")
	unlock, err := newCredStore(o.Dir, o.Gateway, o.Secrets).lockWaiting(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := startProxy(t, g, clock, dir, func(o *Options) { o.LoginOnly = true })
	const msg = "waiting for another mcp-gateway proxy to finish signing in"
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(h.stderr.String(), msg) {
		if time.Now().After(deadline) {
			unlock()
			t.Fatalf("no waiting message; stderr:\n%s", h.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond) // several lock polls
	unlock()
	if err := h.finish(); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if n := strings.Count(h.stderr.String(), msg); n != 1 {
		t.Fatalf("waiting message printed %d times:\n%s", n, h.stderr.String())
	}
}

func TestStoresAreKeyedByGateway(t *testing.T) {
	g1, g2 := newFakeGateway(t), newFakeGateway(t)
	clock := newFakeClock()
	dir := t.TempDir()
	for _, g := range []*fakeGateway{g1, g2} {
		h := startProxy(t, g, clock, dir, func(o *Options) { o.LoginOnly = true })
		if err := h.finish(); err != nil {
			t.Fatal(err)
		}
	}
	c1 := storedCreds(t, baseOptions(t, g1, clock, dir))
	c2 := storedCreds(t, baseOptions(t, g2, clock, dir))
	if c1.RefreshToken == "" || c2.RefreshToken == "" || c1.RefreshToken == c2.RefreshToken {
		t.Fatalf("%+v %+v", c1, c2)
	}
	// Machine enrollment files are untouched.
	if _, err := os.Stat(filepath.Join(dir, "machine.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("touched machine.json")
	}
}

// Two proxies of the same user and host share the stored refresh token:
// each refresh starts from what the other persisted, so a rotation never
// presents a token that is already used (which would revoke the family).
func TestTwoProxiesShareTheRotatingToken(t *testing.T) {
	g := newFakeGateway(t)
	g.seedOldClient()
	clock := newFakeClock()
	dir := t.TempDir()
	o := baseOptions(t, g, clock, dir)
	seedStored(t, o, "gwc_old")
	a := startProxy(t, g, clock, dir, nil)
	b := startProxy(t, g, clock, dir, nil)
	for round := range 3 {
		for _, h := range []*harness{a, b} {
			h.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			if m := h.recv(); m["error"] != nil {
				t.Fatalf("round %d: %v\n%s", round, m, h.stderr.String())
			}
		}
		clock.Advance(time.Hour)
	}
	_, dev, _, _ := g.snapshot()
	if len(dev) != 0 {
		t.Fatalf("a proxy lost the sign-in and prompted again (%d device flows)", len(dev))
	}
	for _, h := range []*harness{a, b} {
		if err := h.finish(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOptionsValidation(t *testing.T) {
	g := newFakeGateway(t)
	o := baseOptions(t, g, newFakeClock(), t.TempDir())
	o.Stdin, o.Stdout, o.Stderr = strings.NewReader(""), io.Discard, io.Discard
	bad := o
	bad.Scope = "admin"
	if err := Run(context.Background(), bad); err == nil {
		t.Fatal("bad scope accepted")
	}
	bad = o
	bad.Gateway = "http://gw.example.com"
	if err := Run(context.Background(), bad); err == nil {
		t.Fatal("plain http to a remote gateway accepted")
	}
}

func TestDiscoveryRefusesForeignEndpoints(t *testing.T) {
	g := newFakeGateway(t)
	evil := newFakeGateway(t)
	// The authorization server metadata points the token endpoint elsewhere.
	g.mu.Lock()
	g.foreign = evil.URL()
	g.mu.Unlock()
	h := startProxy(t, g, newFakeClock(), t.TempDir(), func(o *Options) { o.LoginOnly = true })
	if err := h.finish(); err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("err %v", err)
	}
	if regs, _, _, _ := evil.snapshot(); len(regs) != 0 {
		t.Fatal("talked to the foreign endpoint")
	}
}

// `echo '{...}' | mcp-gateway proxy`: stdin ends before the sign-in does;
// the request still gets its answer once signed in.
func TestEOFDuringSignInStillAnswers(t *testing.T) {
	g := newFakeGateway(t)
	g.devicePolls = []string{"authorization_pending", "authorization_pending", ""}
	o := baseOptions(t, g, newFakeClock(), t.TempDir())
	var out bytes.Buffer
	stderr := &syncBuffer{}
	o.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	o.Stdout, o.Stderr = &out, stderr
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil || idOf(m) != 1 || m["error"] != nil {
		t.Fatalf("stdout %q", out.String())
	}
	if _, dev, _, _ := g.snapshot(); len(dev) != 1 {
		t.Fatalf("device flows %d (one code only)", len(dev))
	}
}

// After a denied sign-in no request starts another device flow.
func TestDeniedSignInIsFinal(t *testing.T) {
	g := newFakeGateway(t)
	g.devicePolls = []string{"access_denied"}
	o := baseOptions(t, g, newFakeClock(), t.TempDir())
	var lines strings.Builder
	for i := range 5 {
		lines.WriteString(`{"jsonrpc":"2.0","id":` + itoa(i) + `,"method":"ping"}` + "\n")
	}
	o.Stdin, o.Stdout, o.Stderr = strings.NewReader(lines.String()), io.Discard, io.Discard
	if err := Run(context.Background(), o); !errors.Is(err, ErrSignInDenied) {
		t.Fatalf("err %v", err)
	}
	if _, dev, _, _ := g.snapshot(); len(dev) != 1 {
		t.Fatalf("device flows %d after a denial", len(dev))
	}
}
