//go:build integration || e2e

package e2e

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildTunnelBinary builds cmd/mcp-gateway-tunnel into a temporary
// directory: the scenario runs the real binary, as a user would.
func buildTunnelBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mcp-gateway-tunnel")
	out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "../../cmd/mcp-gateway-tunnel").CombinedOutput()
	if err != nil {
		t.Fatalf("build mcp-gateway-tunnel: %v\n%s", err, out)
	}
	return bin
}

// tunnelProc is one running mcp-gateway-tunnel.
type tunnelProc struct {
	cmd    *exec.Cmd
	stderr *syncBuffer
	done   chan error
}

// startTunnel runs the binary with --stdio pointing at this test binary
// re-executed as a stdio MCP server (TestMain), the token in the
// environment as the docs recommend.
func startTunnel(t *testing.T, bin, gateway, token string) *tunnelProc {
	t.Helper()
	p := &tunnelProc{stderr: &syncBuffer{}, done: make(chan error, 1)}
	p.cmd = exec.CommandContext(t.Context(), bin, "--gateway", gateway, "--stdio", `"`+os.Args[0]+`" -test.run=^$`)
	// At the end of the test: a graceful stop, then SIGKILL.
	p.cmd.Cancel = func() error { return p.cmd.Process.Signal(syscall.SIGTERM) }
	p.cmd.WaitDelay = 10 * time.Second
	p.cmd.Env = append(os.Environ(), "MCP_GATEWAY_TUNNEL_TOKEN="+token, stdioServerEnv+"=1")
	p.cmd.Stderr = p.stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(func() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
			_ = p.cmd.Process.Kill()
		}
	})
	return p
}

// wait returns the exit code once the process ends.
func (p *tunnelProc) wait(t *testing.T) int {
	t.Helper()
	select {
	case err := <-p.done:
		p.done <- err // for the cleanup
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatalf("tunnel client: %v", err)
		}
		return 0
	case <-time.After(15 * time.Second):
		t.Fatalf("tunnel client did not exit; stderr:\n%s", p.stderr.String())
		return -1
	}
}

var (
	tunnelTokenRE = regexp.MustCompile(`mgt_[0-9A-Za-z]{8}_[0-9A-Za-z]{43}`)
	tunnelIDRE    = regexp.MustCompile(`tunnel://([0-9a-f-]{36})`)
)

// TestE2EPluginsTunnelStdioServer is the tunnel scenario (task w2cd39bc):
// alice creates a tunnel on the portal (token shown once), runs the real
// mcp-gateway-tunnel binary with --stdio next to a stdio MCP server, adds
// the server as tunnel://<id>/, reviews it and calls its tool through
// /mcp. With the client stopped the call is refused as tunnel_offline;
// after an admin revokes the tunnel, the client stops for good and the
// call is refused as tunnel_unavailable.
func TestE2EPluginsTunnelStdioServer(t *testing.T) {
	w := newWorld(t, options{federation: true})
	bin := buildTunnelBinary(t)

	p := w.submit(w.alice, "/servers/tunnels", url.Values{"name": {"laptop"}})
	token, id := tunnelTokenRE.FindString(p.body), tunnelIDRE.FindStringSubmatch(p.body)
	if p.status != http.StatusOK || token == "" || id == nil {
		t.Fatalf("create tunnel = %d\n%s", p.status, snippet(p.body))
	}
	w.forbid(token, "tunnel token")
	tunnelID := id[1]
	if !strings.Contains(p.body, "mcp-gateway-tunnel --gateway "+baseURL) {
		t.Errorf("the token page lacks the command line")
	}
	if again := w.page(w.alice, "/servers"); strings.Contains(again.body, token) {
		t.Error("the tunnel token is shown again on the servers page")
	}

	online := func(want bool) {
		t.Helper()
		w.eventually("tunnel online="+map[bool]string{true: "true", false: "false"}[want], 15*time.Second, func() bool {
			return w.fed.Tunnels.Online(tunnelID) == want
		})
	}
	proc := startTunnel(t, bin, w.srv.URL, token)
	online(true)

	serverID := w.addServer(w.alice, url.Values{"name": {"laptop"}, "url_mode": {"tunnel"}, "tunnel_id": {tunnelID},
		"tunnel_path": {"/"}, "auth_kind": {"none"}, "credential_mode": {"per_user"}})
	w.approve(w.alice, serverID, w.refresh(w.alice, serverID), "echo")
	alice := w.client(w.alice)
	if !contains(toolNames(t, alice), "laptop.echo") {
		t.Fatalf("alice's tools lack laptop.echo")
	}
	if got := w.toolText(alice, "laptop.echo", map[string]any{"text": "hi"}); got != "stdio echo: hi" {
		t.Errorf("laptop.echo = %q", got)
	}
	// Bob sees nothing of alice's tunnel-backed server.
	if contains(toolNames(t, w.client(w.bob)), "laptop.echo") {
		t.Error("bob sees alice's tunnel-backed server")
	}

	// The client stops: tunnel_offline.
	_ = proc.cmd.Process.Signal(syscall.SIGTERM)
	if code := proc.wait(t); code != 0 {
		t.Errorf("tunnel client exit code after SIGTERM = %d, want 0", code)
	}
	online(false)
	if msg := w.toolError(alice, "laptop.echo", map[string]any{"text": "hi"}); !strings.Contains(msg, "tunnel is offline") {
		t.Errorf("offline call = %q", msg)
	}
	if !w.hasAudit(w.alice, "laptop.echo", "", "tunnel_offline") {
		t.Error("no audit row with class tunnel_offline")
	}

	// It comes back.
	proc = startTunnel(t, bin, w.srv.URL, token)
	online(true)
	if got := w.toolText(alice, "laptop.echo", map[string]any{"text": "again"}); got != "stdio echo: again" {
		t.Errorf("laptop.echo after reconnect = %q", got)
	}

	// An admin revokes the tunnel: the client stops for good.
	if p := w.page(w.admin, "/admin/tunnels"); p.status != http.StatusOK || !strings.Contains(p.body, "laptop") {
		t.Errorf("admin tunnels page = %d", p.status)
	}
	mustRedirect(t, "admin revoke", w.submit(w.admin, "/admin/tunnels/"+tunnelID+"/revoke", url.Values{}), "/admin/tunnels?done=revoked")
	if code := proc.wait(t); code != 1 {
		t.Errorf("tunnel client exit code after revoke = %d, want 1; stderr:\n%s", code, proc.stderr.String())
	}
	online(false)
	if msg := w.toolError(alice, "laptop.echo", map[string]any{"text": "hi"}); !strings.Contains(msg, "tunnel is not available") {
		t.Errorf("call after revoke = %q", msg)
	}
	if !w.hasAudit(w.alice, "laptop.echo", "", "tunnel_unavailable") {
		t.Error("no audit row with class tunnel_unavailable")
	}
	// A revoked token is refused at once.
	proc = startTunnel(t, bin, w.srv.URL, token)
	if code := proc.wait(t); code != 1 {
		t.Errorf("tunnel client with a revoked token: exit code %d, want 1", code)
	}
	if strings.Contains(proc.stderr.String(), token) {
		t.Error("the tunnel client printed its token")
	}
}

// TestE2EPluginsLegacySSEUpstream is the legacy transport scenario (task
// w2cd39bc): a server that only speaks the deprecated HTTP+SSE transport
// is detected, added, refreshed and called through the gateway, which
// falls back from Streamable HTTP automatically.
func TestE2EPluginsLegacySSEUpstream(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	s := sdk.NewServer(&sdk.Implementation{Name: "legacy", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "status", Description: "Status.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoIn) (*sdk.CallToolResult, any, error) {
			return textResult("ok over sse: " + in.Text), nil, nil
		})
	sse := sdk.NewSSEHandler(func(*http.Request) *sdk.Server { return s }, nil)
	var streams, refusedPosts atomic.Int32
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet:
			streams.Add(1)
		case r.Method == http.MethodPost && r.URL.Query().Get("sessionid") == "":
			refusedPosts.Add(1) // the Streamable HTTP attempt: 400 from a legacy server
		}
		sse.ServeHTTP(rw, r)
	}))
	t.Cleanup(srv.Close)

	if body := w.detect(w.alice, srv.URL+"/sse"); !strings.Contains(body, "Detected: <strong>none</strong>.") {
		t.Errorf("detect (legacy SSE server):\n%s", detectNotice(body))
	}
	id := w.addServer(w.alice, url.Values{"name": {"legacy"}, "url_mode": {"https"}, "url": {srv.URL + "/sse"},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	w.approve(w.alice, id, w.refresh(w.alice, id), "status")
	alice := w.client(w.alice)
	if got := w.toolText(alice, "legacy.status", map[string]any{"text": "hi"}); got != "ok over sse: hi" {
		t.Errorf("legacy.status = %q", got)
	}
	if streams.Load() == 0 || refusedPosts.Load() == 0 {
		t.Errorf("SSE streams %d, refused streamable POSTs %d: the gateway did not fall back to legacy SSE", streams.Load(), refusedPosts.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, h := range seen {
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
			t.Errorf("legacy upstream received gateway credentials: %v", h)
		}
	}
}
