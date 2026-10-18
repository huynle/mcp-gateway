package tunnelclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
)

func TestSplitCommand(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
		bad  bool
	}{
		{in: "npx -y @scope/server", want: []string{"npx", "-y", "@scope/server"}},
		{in: `  python  "my server.py" --name 'a b' `, want: []string{"python", "my server.py", "--name", "a b"}},
		{in: `cmd a\ b "q\"x"`, want: []string{"cmd", "a b", `q"x`}},
		{in: `cmd ""`, want: []string{"cmd", ""}},
		{in: "", bad: true},
		{in: `cmd "unterminated`, bad: true},
		{in: `cmd 'x`, bad: true},
	} {
		got, err := splitCommand(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("splitCommand(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitCommand(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestParseConfig(t *testing.T) {
	tok, _, _ := tunnel.GenerateToken()
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	noEnv := env(nil)

	c, err := parseConfig([]string{"--gateway", "https://gw.example.com", "--token", tok, "--http", "http://localhost:8080/mcp"}, noEnv)
	if err != nil || c.token != tok || c.httpTarget.String() != "http://localhost:8080/mcp" || c.gateway != "https://gw.example.com" {
		t.Fatalf("http config = %+v, %v", c, err)
	}
	c, err = parseConfig([]string{"--gateway", "https://gw.example.com", "--stdio", "server --flag"}, env(map[string]string{"MCP_GATEWAY_TUNNEL_TOKEN": tok}))
	if err != nil || c.token != tok || !reflect.DeepEqual(c.stdio, []string{"server", "--flag"}) {
		t.Fatalf("stdio config = %+v, %v", c, err)
	}
	// Loopback gateways may use http (local testing).
	if _, err := parseConfig([]string{"--gateway", "http://127.0.0.1:18080", "--token", tok, "--http", "http://127.0.0.1:1/mcp"}, noEnv); err != nil {
		t.Fatalf("loopback http gateway refused: %v", err)
	}

	for name, args := range map[string][]string{
		"no token":         {"--gateway", "https://gw.example.com", "--http", "http://localhost:1/mcp"},
		"bad token":        {"--gateway", "https://gw.example.com", "--token", "mgt_nope", "--http", "http://localhost:1/mcp"},
		"no gateway":       {"--token", tok, "--http", "http://localhost:1/mcp"},
		"http gateway":     {"--gateway", "http://gw.example.com", "--token", tok, "--http", "http://localhost:1/mcp"},
		"neither":          {"--gateway", "https://gw.example.com", "--token", tok},
		"both":             {"--gateway", "https://gw.example.com", "--token", tok, "--http", "http://localhost:1/mcp", "--stdio", "x"},
		"bad target":       {"--gateway", "https://gw.example.com", "--token", tok, "--http", "ftp://localhost/x"},
		"bad stdio":        {"--gateway", "https://gw.example.com", "--token", tok, "--stdio", `"unterminated`},
		"positional extra": {"--gateway", "https://gw.example.com", "--token", tok, "--http", "http://localhost:1/mcp", "extra"},
	} {
		_, err := parseConfig(args, noEnv)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), tok) {
			t.Errorf("%s: error leaks the token: %v", name, err)
		}
	}
}

func TestHTTPForwarderStaysOnTarget(t *testing.T) {
	type seen struct{ host, uri, hdr string }
	got := make(chan seen, 4)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Host, r.URL.RequestURI(), r.Header.Get("X-Test")}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: x\n\n")
	}))
	defer target.Close()
	tu, _ := url.Parse(target.URL + "/mcp")
	fw := newHTTPForwarder(tu, target.Client())

	for _, tc := range []struct{ in, want string }{
		{"/", "/mcp"}, // the registered root maps to the target URL
		{"/messages?sessionId=1", "/messages?sessionId=1"}, // other paths stay on the target origin
		{"//evil.example/x", "//evil.example/x"},           // never another host
	} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://tunnel"+tc.in, strings.NewReader("{}"))
		req.RequestURI = tc.in
		req.URL, _ = url.ParseRequestURI(tc.in)
		req.Header.Set("X-Test", "v")
		rec := httptest.NewRecorder()
		fw.ServeHTTP(rec, req)
		s := <-got
		wantHost := strings.TrimPrefix(target.URL, "http://")
		if s.host != wantHost || s.uri != tc.want || s.hdr != "v" {
			t.Errorf("%s: target saw host %q uri %q hdr %q; want %q %q", tc.in, s.host, s.uri, s.hdr, wantHost, tc.want)
		}
		if rec.Code != http.StatusOK || rec.Body.String() != "data: x\n\n" || rec.Header().Get("Content-Type") != "text/event-stream" {
			t.Errorf("%s: response %d %q %v", tc.in, rec.Code, rec.Body.String(), rec.Header())
		}
	}

	// An unreachable target is a 502, not a hang or a crash.
	dead, _ := url.Parse("http://127.0.0.1:1/mcp")
	rec := httptest.NewRecorder()
	newHTTPForwarder(dead, target.Client()).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("dead target: %d, want 502", rec.Code)
	}
}

// runCmd runs the command in the background and returns its stderr and a
// stop function that cancels it and returns the exit code.
func runCmd(t *testing.T, args []string, env map[string]string) (*syncBuffer, func() int) {
	t.Helper()
	stderr := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	code := make(chan int, 1)
	go func() { code <- Run(ctx, Options{}, args, func(k string) string { return env[k] }, stderr) }()
	var once sync.Once
	var rc int
	stop := func() int {
		once.Do(func() {
			cancel()
			select {
			case rc = <-code:
			case <-time.After(15 * time.Second):
				t.Error("command did not exit after cancel")
				rc = -1
			}
		})
		return rc
	}
	t.Cleanup(func() { stop() })
	return stderr, stop
}

func TestHTTPServerThroughTunnel(t *testing.T) {
	g := newGateway(t)
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return echoServer() }, nil))
	defer upstream.Close()
	stderr, stop := runCmd(t, []string{"--gateway", g.url, "--http", upstream.URL + "/mcp"}, map[string]string{"MCP_GATEWAY_TUNNEL_TOKEN": g.token})
	g.waitOnline(t)

	s, err := g.session(t, "/")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	listAndCall(t, s)
	_ = s.Close()

	if code := stop(); code != 0 {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), g.token) || strings.Contains(stderr.String(), g.token[13:]) {
		t.Fatal("token in stderr")
	}
	if !strings.Contains(stderr.String(), "connected") {
		t.Fatalf("no status line on stderr:\n%s", stderr.String())
	}
}

func TestStdioServerThroughTunnelExec(t *testing.T) {
	g := newGateway(t)
	t.Setenv("MCP_TUNNEL_TEST_STDIO_SERVER", "1") // inherited by the child
	stderr, stop := runCmd(t, []string{"--gateway", g.url, "--token", g.token, "--stdio", `"` + os.Args[0] + `" -test.run=^$`}, nil)
	g.waitOnline(t)

	// Two independent gateway sessions share the one stdio process.
	for range 2 {
		s, err := g.session(t, "/mcp")
		if err != nil {
			t.Fatalf("Connect: %v\nstderr:\n%s", err, stderr.String())
		}
		listAndCall(t, s)
		res, err := s.CallTool(context.Background(), "fail", map[string]any{"text": "x"})
		if err != nil || !res.IsError {
			t.Fatalf("fail tool: %+v, %v", res, err)
		}
		_ = s.Close()
	}
	if code := stop(); code != 0 {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), g.token[13:]) {
		t.Fatal("token in stderr")
	}
}

func TestOfflineTunnelThroughFederationClient(t *testing.T) {
	g := newGateway(t)
	_, err := g.session(t, "/mcp")
	var te *tunnel.Error
	if !errors.As(err, &te) || te.Class != tunnel.ClassOffline {
		t.Fatalf("Connect to offline tunnel: %v, want *tunnel.Error class %s", err, tunnel.ClassOffline)
	}
}

// countingWriter counts initialize requests written to the child.
type countingWriter struct {
	w     io.Writer
	inits atomic.Int32
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), `"method":"initialize"`) {
		c.inits.Add(1)
	}
	return c.w.Write(p)
}

func TestStdioBridgeInMemoryConcurrentSessions(t *testing.T) {
	g := newGateway(t)
	// child stdin/stdout as pipes to an in-process go-sdk server.
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = echoServer().Run(ctx, &mcp.IOTransport{Reader: inR, Writer: outW}) }()
	cw := &countingWriter{w: inW}
	bridge := newStdioBridge(outR, cw, slog.New(slog.DiscardHandler))

	a, err := tunnel.NewAgent(tunnel.AgentOptions{GatewayURL: g.url, Token: g.token, Handler: bridge})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = a.Run(ctx) }()
	g.waitOnline(t)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := g.session(t, "/")
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = s.Close() }()
			for range 3 {
				res, err := s.CallTool(context.Background(), "echo", map[string]any{"text": "hi"})
				if err != nil || res.IsError {
					errs <- errors.New("call failed")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := cw.inits.Load(); n != 1 {
		t.Fatalf("stdio server saw %d initialize requests, want 1", n)
	}
}

// fakeChild is the other end of a bridge: it reads what the bridge writes
// and lets the test answer by hand.
type fakeChild struct {
	lines  chan map[string]any
	stdout *io.PipeWriter
}

func newFakeChild(t *testing.T) (*stdioBridge, *fakeChild) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	fc := &fakeChild{lines: make(chan map[string]any, 16), stdout: outW}
	go func() {
		sc := bufio.NewScanner(inR)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				fc.lines <- m
			}
		}
	}()
	b := newStdioBridge(outR, inW, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { _ = outW.Close(); _ = inW.Close() })
	return b, fc
}

func (fc *fakeChild) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m := <-fc.lines:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("bridge wrote nothing to the child")
		return nil
	}
}

func (fc *fakeChild) send(t *testing.T, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if _, err := fc.stdout.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
}

func post(b http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, req)
	return rec
}

func TestStdioBridgeProtocol(t *testing.T) {
	b, fc := newFakeChild(t)

	// server/discover is answered locally with "method not found", so the
	// gateway's client falls back to the classic initialize handshake.
	rec := post(b, `{"jsonrpc":"2.0","id":"d1","method":"server/discover","params":{}}`)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || resp["id"] != "d1" || resp["error"] == nil {
		t.Fatalf("discover: %d %s", rec.Code, rec.Body.String())
	}

	// A request is forwarded with the bridge's own id and answered with the
	// caller's id.
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- post(b, `{"jsonrpc":"2.0","id":"abc","method":"tools/list","params":{}}`) }()
	m := fc.next(t)
	if m["method"] != "tools/list" || m["id"] == "abc" {
		t.Fatalf("child got %v", m)
	}
	// Meanwhile the child asks the client something: refused, not hung.
	fc.send(t, map[string]any{"jsonrpc": "2.0", "id": 77, "method": "roots/list"})
	refusal := fc.next(t)
	if refusal["id"] != float64(77) || refusal["error"] == nil {
		t.Fatalf("server->client request answered with %v", refusal)
	}
	fc.send(t, map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": map[string]any{"tools": []any{}}})
	rec = <-done
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || resp["id"] != "abc" || resp["result"] == nil ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("tools/list: %d %s", rec.Code, rec.Body.String())
	}

	// Notifications are accepted (202) and forwarded.
	rec = post(b, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("notification: %d", rec.Code)
	}
	if m := fc.next(t); m["method"] != "notifications/cancelled" {
		t.Fatalf("child got %v", m)
	}

	// Malformed input.
	for name, body := range map[string]string{"batch": `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, "not json": `nope`} {
		if rec := post(b, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	if rec := post(b, `{"jsonrpc":"2.0","id":1,"method":"x","params":{"p":"`+strings.Repeat("a", maxBridgeBody)+`"}}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: %d, want 413", rec.Code)
	}
	rec = httptest.NewRecorder()
	b.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d, want 405", rec.Code)
	}

	// The child exits: pending and later requests fail with 502.
	go func() { done <- post(b, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}`) }()
	fc.next(t)
	_ = fc.stdout.Close()
	if rec := <-done; rec.Code != http.StatusBadGateway {
		t.Fatalf("pending after exit: %d, want 502", rec.Code)
	}
	if rec := post(b, `{"jsonrpc":"2.0","id":6,"method":"tools/list"}`); rec.Code != http.StatusBadGateway {
		t.Fatalf("after exit: %d, want 502", rec.Code)
	}
	select {
	case <-b.Done():
	default:
		t.Fatal("Done not closed after the child exited")
	}
}
