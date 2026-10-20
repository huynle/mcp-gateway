package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// gw is a gateway under test: a Service behind an httptest server.
type gw struct {
	svc *Service
	ms  *memStore
	srv *httptest.Server
	log *syncBuffer
	// tunnels numbers the names newTunnel gives (a live name is unique per owner).
	tunnels int
}

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

func newGW(t *testing.T, l Limits) *gw {
	t.Helper()
	ms := newMemStore()
	buf := &syncBuffer{}
	svc, err := NewService(Options{Store: ms, Machines: ms, Limits: l, Log: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(ConnectPath, svc.Handler())
	mux.Handle(MachineConnectPath, testMachineEndpoint(svc))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &gw{svc: svc, ms: ms, srv: srv, log: buf}
}

// agentRun is a running tunnel client.
type agentRun struct {
	cancel context.CancelFunc
	done   chan error
	log    *syncBuffer
}

func (g *gw) startAgent(t *testing.T, token string, h http.Handler) *agentRun {
	t.Helper()
	buf := &syncBuffer{}
	a, err := NewAgent(AgentOptions{
		GatewayURL: g.srv.URL, Token: token, Handler: h, HTTPClient: g.srv.Client(),
		Log:        slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &agentRun{cancel: cancel, done: make(chan error, 1), log: buf}
	go func() { r.done <- a.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-waitOr(r.done) })
	return r
}

func waitOr(ch chan error) chan error {
	out := make(chan error, 1)
	go func() {
		select {
		case err := <-ch:
			ch <- err // keep it for other readers
			out <- err
		case <-time.After(5 * time.Second):
			out <- errors.New("timeout")
		}
	}()
	return out
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (g *gw) newTunnel(t *testing.T) (id, token string) {
	t.Helper()
	g.tunnels++
	tun, raw, err := g.svc.CreateTunnel(context.Background(), ownerA, fmt.Sprintf("laptop-%d", g.tunnels))
	if err != nil {
		t.Fatal(err)
	}
	return tun.ID, raw
}

func (g *gw) client() *http.Client { return g.svc.HTTPClient(&http.Client{}) }

// do sends a request through the tunnel transport.
func (g *gw) do(method, u string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, u, body)
	if err != nil {
		return nil, err
	}
	return g.client().Do(req)
}

// doErr sends a request that is expected to fail and returns the error.
func (g *gw) doErr(method, u string, body io.Reader) error {
	resp, err := g.do(method, u, body)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

func classOf(err error) Class {
	var te *Error
	if errors.As(err, &te) {
		return te.Class
	}
	return ""
}

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Path", r.URL.RequestURI())
		w.Header().Set("X-Echo-Header", r.Header.Get("X-Test"))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	})
}

func TestConnectRefusesBadTokens(t *testing.T) {
	g := newGW(t, Limits{})
	id, raw := g.newTunnel(t)
	other, _, _ := GenerateToken()
	revokedID, revoked := g.newTunnel(t)
	if err := g.svc.Revoke(context.Background(), ownerA, revokedID); err != nil {
		t.Fatal(err)
	}
	for name, auth := range map[string]string{
		"missing": "", "malformed": "Bearer nope", "unknown": "Bearer " + other,
		"revoked": "Bearer " + revoked, "wrong scheme": "Basic " + raw,
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, g.srv.URL+ConnectPath, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := g.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, resp.StatusCode)
		}
	}
	// The agent gives up on 401 instead of retrying forever.
	r := g.startAgent(t, revoked, echoHandler())
	if err := <-waitOr(r.done); !errors.Is(err, ErrRejected) {
		t.Fatalf("agent with revoked token: %v, want ErrRejected", err)
	}
	if g.svc.Online(id) {
		t.Fatal("tunnel online without a client")
	}
}

func TestRoundTripThroughTunnel(t *testing.T) {
	g := newGW(t, Limits{})
	id, raw := g.newTunnel(t)
	g.startAgent(t, raw, echoHandler())
	eventually(t, "tunnel online", func() bool { return g.svc.Online(id) })
	if g.ms.touchCount() == 0 {
		t.Error("last_seen_at not touched on connect")
	}

	httpForm, err := ClientURL("tunnel://" + id + "/mcp/x?q=1")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"tunnel://" + id + "/mcp/x?q=1", httpForm} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader("hello"))
		req.Header.Set("X-Test", "v")
		resp, err := g.client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated || string(body) != "hello" ||
			resp.Header.Get("X-Echo-Method") != "POST" || resp.Header.Get("X-Echo-Path") != "/mcp/x?q=1" ||
			resp.Header.Get("X-Echo-Header") != "v" {
			t.Fatalf("%s: status %d body %q headers %v", u, resp.StatusCode, body, resp.Header)
		}
	}
}

func TestStreamingResponseArrivesBeforeHandlerEnds(t *testing.T) {
	g := newGW(t, Limits{})
	id, raw := g.newTunnel(t)
	release := make(chan struct{})
	g.startAgent(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: two\n\n")
	}))
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	resp, err := g.do(http.MethodGet, "tunnel://"+id+"/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: one\n" {
		t.Fatalf("first event %q, %v", line, err)
	}
	close(release)
	rest, _ := io.ReadAll(br)
	if string(rest) != "\ndata: two\n\n" {
		t.Fatalf("rest %q", rest)
	}
}

func TestOfflineTunnel(t *testing.T) {
	g := newGW(t, Limits{})
	id, _ := g.newTunnel(t)
	err := g.doErr(http.MethodGet, "tunnel://"+id+"/mcp", nil)
	if classOf(err) != ClassOffline {
		t.Fatalf("err %v, want class %s", err, ClassOffline)
	}
	// Non-tunnel URLs are refused, never dialled.
	err = g.doErr(http.MethodGet, "https://example.com/mcp", nil)
	if classOf(err) != ClassNotTunnel {
		t.Fatalf("err %v, want class %s", err, ClassNotTunnel)
	}
}

func TestReplacementConnection(t *testing.T) {
	g := newGW(t, Limits{})
	id, raw := g.newTunnel(t)
	first := g.startAgent(t, raw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "first") }))
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	g.startAgent(t, raw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "second") }))
	if err := <-waitOr(first.done); !errors.Is(err, ErrReplaced) {
		t.Fatalf("first agent: %v, want ErrReplaced", err)
	}
	eventually(t, "second serves", func() bool {
		resp, err := g.do(http.MethodGet, "tunnel://"+id+"/", nil)
		if err != nil {
			return false
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(b) == "second"
	})
}

func TestRevokeDropsLiveConnection(t *testing.T) {
	g := newGW(t, Limits{})
	id, raw := g.newTunnel(t)
	r := g.startAgent(t, raw, echoHandler())
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	if err := g.svc.Revoke(context.Background(), ownerA, id); err != nil {
		t.Fatal(err)
	}
	if err := <-waitOr(r.done); !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrRejected) {
		t.Fatalf("agent after revoke: %v", err)
	}
	if g.svc.Online(id) {
		t.Fatal("revoked tunnel still online")
	}
}

func TestHeartbeatNoticesRevocationByAnotherReplica(t *testing.T) {
	g := newGW(t, Limits{HeartbeatInterval: 20 * time.Millisecond})
	id, raw := g.newTunnel(t)
	r := g.startAgent(t, raw, echoHandler())
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	// Revoked directly in the store, as another replica would.
	if err := g.ms.RevokeTunnel(context.Background(), ownerA, id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := <-waitOr(r.done); !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrRejected) {
		t.Fatalf("agent: %v", err)
	}
}

func TestDisconnectCleansUp(t *testing.T) {
	g := newGW(t, Limits{})
	id, raw := g.newTunnel(t)
	started := make(chan struct{})
	r := g.startAgent(t, raw, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	errc := make(chan error, 1)
	go func() {
		errc <- g.doErr(http.MethodGet, "tunnel://"+id+"/hang", nil)
	}()
	<-started
	r.cancel()
	select {
	case err := <-errc:
		if classOf(err) != ClassOffline {
			t.Fatalf("in-flight request: %v, want %s", err, ClassOffline)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request not failed on disconnect")
	}
	eventually(t, "offline", func() bool { return !g.svc.Online(id) })
}

func TestRequestBodyBound(t *testing.T) {
	g := newGW(t, Limits{MaxRequestBytes: 1024})
	id, raw := g.newTunnel(t)
	called := make(chan struct{}, 1)
	g.startAgent(t, raw, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called <- struct{}{} }))
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	err := g.doErr(http.MethodPost, "tunnel://"+id+"/", bytes.NewReader(make([]byte, 2048)))
	if classOf(err) != ClassTooLarge {
		t.Fatalf("err %v, want %s", err, ClassTooLarge)
	}
	select {
	case <-called:
		t.Fatal("oversized request reached the local server")
	default:
	}
}

func TestResponseBodyBound(t *testing.T) {
	g := newGW(t, Limits{MaxResponseBytes: 1024})
	id, raw := g.newTunnel(t)
	g.startAgent(t, raw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 64<<10))
	}))
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	resp, err := g.do(http.MethodGet, "tunnel://"+id+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if classOf(err) != ClassTooLarge {
		t.Fatalf("read err %v, want %s", err, ClassTooLarge)
	}
}

func TestResponseHeaderTimeoutCancelsLocalRequest(t *testing.T) {
	g := newGW(t, Limits{ResponseHeaderTimeout: 100 * time.Millisecond})
	id, raw := g.newTunnel(t)
	cancelled := make(chan struct{})
	g.startAgent(t, raw, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(cancelled)
	}))
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	err := g.doErr(http.MethodGet, "tunnel://"+id+"/slow", nil)
	if classOf(err) != ClassTimeout {
		t.Fatalf("err %v, want %s", err, ClassTimeout)
	}
	var ne interface{ Timeout() bool }
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatal("timeout error does not report Timeout()")
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("local request not cancelled after the gateway gave up")
	}
}

func TestMaxConcurrentStreams(t *testing.T) {
	g := newGW(t, Limits{MaxStreams: 1})
	id, raw := g.newTunnel(t)
	inside := make(chan struct{})
	release := make(chan struct{})
	g.startAgent(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			close(inside)
			<-release
		}
		_, _ = io.WriteString(w, "ok")
	}))
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	done := make(chan error, 1)
	go func() {
		resp, err := g.do(http.MethodGet, "tunnel://"+id+"/hold", nil)
		if err == nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		done <- err
	}()
	<-inside
	err := g.doErr(http.MethodGet, "tunnel://"+id+"/second", nil)
	if classOf(err) != ClassBusy {
		t.Fatalf("err %v, want %s", err, ClassBusy)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The slot is released once the body is closed.
	resp, err := g.do(http.MethodGet, "tunnel://"+id+"/second", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestTokenNeverLogged(t *testing.T) {
	g := newGW(t, Limits{})
	id, raw := g.newTunnel(t)
	revokedID, revoked := g.newTunnel(t)
	if err := g.svc.Revoke(context.Background(), ownerA, revokedID); err != nil {
		t.Fatal(err)
	}
	ok := g.startAgent(t, raw, echoHandler())
	eventually(t, "online", func() bool { return g.svc.Online(id) })
	bad := g.startAgent(t, revoked, echoHandler())
	<-waitOr(bad.done)
	_ = g.doErr(http.MethodGet, "tunnel://"+id+"/", nil)
	logs := g.log.String() + ok.log.String() + bad.log.String()
	if logs == "" {
		t.Fatal("expected some log output")
	}
	for _, tok := range []string{raw, revoked} {
		secret := tok[len(TokenPrefix)+9:]
		if strings.Contains(logs, secret) || strings.Contains(logs, fmt.Sprintf("%x", HashToken(tok))) {
			t.Fatalf("token material in logs:\n%s", logs)
		}
	}
}

func TestParseURL(t *testing.T) {
	const id = "0b6f2f2e-6a43-4c55-9a1e-2f4b8d1c9e10"
	for _, tc := range []struct {
		in, id, path string
		ok           bool
	}{
		{"tunnel://" + id + "/mcp", id, "/mcp", true},
		{"tunnel://" + id, id, "/", true},
		{"http://" + id + ".tunnel.invalid/mcp?x=1", id, "/mcp?x=1", true},
		{"https://example.com/mcp", "", "", false},
		{"tunnel://not-a-uuid/mcp", "", "", false},
		{"tunnel://" + id + ":80/mcp", "", "", false},
		{"tunnel://user@" + id + "/mcp", "", "", false},
	} {
		gotID, gotPath, err := ParseURL(tc.in)
		if (err == nil) != tc.ok || gotID != tc.id || gotPath != tc.path {
			t.Errorf("ParseURL(%q) = %q, %q, %v", tc.in, gotID, gotPath, err)
		}
	}
	u, err := ClientURL("tunnel://" + strings.ToUpper(id) + "/mcp")
	if err != nil || u != "http://"+id+".tunnel.invalid/mcp" {
		t.Fatalf("ClientURL = %q, %v", u, err)
	}
}
