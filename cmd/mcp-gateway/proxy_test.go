//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// proxyGateway is a minimal device-flow gateway with /mcp (the contract is
// tested in depth in internal/mcpproxy).
type proxyGateway struct {
	srv  *httptest.Server
	mu   sync.Mutex
	regs []map[string]any
	dev  []string // scopes asked for
}

func newProxyGateway(t *testing.T) *proxyGateway {
	t.Helper()
	g := &proxyGateway{}
	js := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		js(w, 200, map[string]any{"resource": g.srv.URL + "/mcp", "authorization_servers": []string{g.srv.URL}})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		b := g.srv.URL
		js(w, 200, map[string]any{"issuer": b, "token_endpoint": b + "/oauth/token", "registration_endpoint": b + "/oauth/register",
			"device_authorization_endpoint": b + "/oauth/device_authorization"})
	})
	mux.HandleFunc("POST /oauth/register", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		g.mu.Lock()
		g.regs = append(g.regs, req)
		g.mu.Unlock()
		js(w, 201, map[string]any{"client_id": "gwc_cli"})
	})
	mux.HandleFunc("POST /oauth/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		g.mu.Lock()
		g.dev = append(g.dev, r.PostForm.Get("scope"))
		g.mu.Unlock()
		js(w, 200, map[string]any{"device_code": "gwd_x", "user_code": "WXYZ-BCDF", "verification_uri": g.srv.URL + "/activate",
			"verification_uri_complete": g.srv.URL + "/activate?code=WXYZ-BCDF", "expires_in": 600, "interval": 5})
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		js(w, 200, map[string]any{"access_token": "at-cli", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "gwr_cli", "scope": "mcp"})
	})
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-cli" {
			w.WriteHeader(401)
			return
		}
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		js(w, 200, map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": map[string]any{"tools": []any{}}})
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func proxyEnv(home string, extra map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := extra[k]; ok {
			return v
		}
		if k == "HOME" {
			return home
		}
		return ""
	}
}

func withProxySeams(t *testing.T, in string) {
	t.Helper()
	oldIn, oldSleep, oldHost := proxyStdin, proxySleep, hostname
	t.Cleanup(func() { proxyStdin, proxySleep, hostname = oldIn, oldSleep, oldHost })
	proxyStdin = strings.NewReader(in)
	proxySleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	hostname = func() (string, error) { return "devbox", nil }
}

func TestProxyCommandServesStdio(t *testing.T) {
	g := newProxyGateway(t)
	home := t.TempDir()
	withProxySeams(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"proxy", "--key-store", "file"},
		proxyEnv(home, map[string]string{"MCP_GATEWAY_URL": g.srv.URL}), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\nstderr:\n%s", code, stderr.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil || resp["id"] != float64(1) || resp["result"] == nil {
		t.Fatalf("stdout must be exactly the JSON-RPC answer: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "To sign in, open "+g.srv.URL+"/activate and enter WXYZ-BCDF") {
		t.Fatalf("stderr:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String()+stdout.String(), "gwr_cli") {
		t.Fatal("printed the refresh token")
	}
	if len(g.regs) != 1 || g.regs[0]["client_name"] != "mcp-gateway proxy (devbox)" {
		t.Fatalf("registrations %v", g.regs)
	}
	// Stored under ~/.config/mcp-gateway/proxy, apart from machine.json.
	files, _ := filepath.Glob(filepath.Join(home, ".config", "mcp-gateway", "proxy", "*"))
	var kinds []string
	for _, f := range files {
		kinds = append(kinds, filepath.Ext(f))
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode())
		}
	}
	if strings.Join(kinds, ",") != ".json,.lock,.token" {
		t.Fatalf("proxy files %v", files)
	}

	// A second run reuses the stored sign-in: no new code.
	withProxySeams(t, "")
	stderr.Reset()
	code = run(context.Background(), []string{"proxy", "--key-store", "file", "--gateway", g.srv.URL, "--login"}, proxyEnv(home, nil), io.Discard, &stderr)
	if code != 0 || strings.Contains(stderr.String(), "To sign in") || len(g.regs) != 1 {
		t.Fatalf("second run: exit %d, regs %d\n%s", code, len(g.regs), stderr.String())
	}
}

func TestProxyGatewayFromConfig(t *testing.T) {
	g := newProxyGateway(t)
	home := t.TempDir()
	cfg := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(cfg, []byte("gateway: "+g.srv.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withProxySeams(t, "")
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"proxy", "--login", "--key-store", "file", "--scope", "mcp:read", "--config", cfg}, proxyEnv(home, nil), io.Discard, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
	if len(g.dev) != 1 || g.dev[0] != "mcp:read" {
		t.Fatalf("scopes %v", g.dev)
	}
}

func TestProxyUsage(t *testing.T) {
	withProxySeams(t, "")
	home := t.TempDir()
	for _, tc := range []struct {
		args   []string
		code   int
		stderr string
	}{
		{[]string{"proxy", "--scope", "admin", "--gateway", "https://gw.example.com"}, 2, "scope"},
		{[]string{"proxy", "extra"}, 2, "unexpected arguments"},
		{[]string{"proxy"}, 1, "no gateway"},
		{[]string{"proxy", "--gateway", "http://gw.example.com", "--key-store", "file"}, 1, "https"},
	} {
		var stderr bytes.Buffer
		code := run(context.Background(), tc.args, proxyEnv(home, nil), io.Discard, &stderr)
		if code != tc.code || !strings.Contains(stderr.String(), tc.stderr) {
			t.Errorf("%v: exit %d stderr %q", tc.args, code, stderr.String())
		}
	}
	code, out, _ := runCLI("help", "proxy")
	if code != 0 || !strings.Contains(out, "usage: mcp-gateway proxy") || !strings.Contains(out, "MCP_GATEWAY_URL") {
		t.Fatalf("help proxy: %d %q", code, out)
	}
	if _, out, _ := runCLI("help"); !strings.Contains(out, "proxy") {
		t.Fatalf("usage does not list proxy: %q", out)
	}
}
