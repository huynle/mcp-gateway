package tunnelclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	bridge := tunnel.NewStdioBridge(outR, cw, slog.New(slog.DiscardHandler))

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
