//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/machineclient"
)

const cliMachineID = "0b9a3f4e-2c1d-4e5f-8a7b-6c5d4e3f2a1b"

// cliGateway is a minimal gateway for the CLI wiring tests (the contract is
// tested in depth in internal/machineclient).
type cliGateway struct {
	srv *httptest.Server
	mu  sync.Mutex
	// calls are "METHOD path" in order.
	calls []string
}

func newCLIGateway(t *testing.T) *cliGateway {
	t.Helper()
	g := &cliGateway{}
	mux := http.NewServeMux()
	js := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("POST /machine/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["code"] != "mge_CLISECRET" {
			w.WriteHeader(400)
			js(w, map[string]string{"error": "invalid_code"})
			return
		}
		js(w, map[string]any{"machine_id": cliMachineID, "name": body["name"], "gateway": g.srv.URL})
	})
	mux.HandleFunc("POST /machine/token", func(w http.ResponseWriter, _ *http.Request) {
		js(w, map[string]any{"access_token": "mgm_00000001_tok", "token_type": "Bearer", "expires_in": 600})
	})
	mux.HandleFunc("GET /machine/v1/self", func(w http.ResponseWriter, _ *http.Request) {
		js(w, map[string]any{"machine_id": cliMachineID, "name": "box", "owner": "Huy", "servers": []any{}})
	})
	mux.HandleFunc("PUT /machine/v1/servers/{name}", func(w http.ResponseWriter, r *http.Request) {
		js(w, map[string]any{"name": r.PathValue("name"), "server_id": "s1", "tunnel_id": "t1", "created": true, "review_url": g.srv.URL + "/servers/s1"})
	})
	mux.HandleFunc("POST /machine/v1/logout", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.calls = append(g.calls, r.Method+" "+r.URL.Path)
		g.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *cliGateway) called(call string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range g.calls {
		if c == call {
			return true
		}
	}
	return false
}

func runEnv(env map[string]string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, func(k string) string { return env[k] }, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func cliEnv(t *testing.T) map[string]string {
	t.Helper()
	home := t.TempDir()
	return map[string]string{"HOME": home, "PATH": "/usr/bin:/bin"}
}

func writeCLIConfig(t *testing.T, env map[string]string, content string) {
	t.Helper()
	p := filepath.Join(env["HOME"], ".config", "mcp-gateway", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loginCLI(t *testing.T, g *cliGateway, env map[string]string) {
	t.Helper()
	code, out, errOut := runEnv(env, "login", "--gateway", g.srv.URL, "--key-store", "file", "--enroll-code", "mge_CLISECRET", "--name", "box")
	if code != 0 {
		t.Fatalf("login: %d\n%s\n%s", code, out, errOut)
	}
	if strings.Contains(out+errOut, "mge_CLISECRET") {
		t.Fatal("the enrollment code was printed")
	}
}

func TestHelpListsMachineCommands(t *testing.T) {
	_, out, _ := runCLI("help")
	for _, c := range []string{"login", "status", "up", "logout", "service", "tunnel"} {
		if !strings.Contains(out, c) {
			t.Errorf("usage misses %s:\n%s", c, out)
		}
	}
	for cmd, want := range map[string]string{
		"login": "--enroll-code", "status": "usage: mcp-gateway status", "up": "--register-only",
		"logout": "usage: mcp-gateway logout", "service": "install|uninstall|status",
	} {
		code, out, errOut := runCLI("help", cmd)
		if code != 0 || !strings.Contains(out+errOut, want) {
			t.Errorf("help %s: %d %q", cmd, code, out+errOut)
		}
		code, out, errOut = runCLI(cmd, "--help")
		if code != 0 || !strings.Contains(out+errOut, want) {
			t.Errorf("%s --help: %d %q", cmd, code, out+errOut)
		}
	}
}

func TestLoginStatusUpLogout(t *testing.T) {
	g := newCLIGateway(t)
	env := cliEnv(t)
	loginCLI(t, g, env)
	stateDir := filepath.Join(env["HOME"], ".config", "mcp-gateway")
	st, err := machineclient.LoadState(stateDir)
	if err != nil || st.MachineID != cliMachineID || st.Name != "box" || st.KeyStore != "file" {
		t.Fatalf("%v %+v", err, st)
	}

	writeCLIConfig(t, env, "servers:\n  local:\n    http: http://127.0.0.1:9/mcp\n")
	code, out, errOut := runEnv(env, "status")
	if code != 0 || !strings.Contains(out, "credentials OK") || !strings.Contains(out, "local") {
		t.Fatalf("status: %d\n%s\n%s", code, out, errOut)
	}

	code, _, errOut = runEnv(env, "up", "--register-only")
	if code != 0 || !g.called("PUT /machine/v1/servers/local") || !strings.Contains(errOut, g.srv.URL+"/servers/s1") {
		t.Fatalf("up --register-only: %d %s", code, errOut)
	}

	code, out, errOut = runEnv(env, "logout")
	if code != 0 || !g.called("POST /machine/v1/logout") {
		t.Fatalf("logout: %d\n%s\n%s", code, out, errOut)
	}
	if _, err := machineclient.LoadState(stateDir); !errors.Is(err, machineclient.ErrNotLoggedIn) {
		t.Fatalf("state after logout: %v", err)
	}
	if code, _, _ := runEnv(env, "status"); code != 1 {
		t.Fatal("status of a logged-out machine must fail")
	}
}

func TestLoginUsesConfigAndEnvCode(t *testing.T) {
	g := newCLIGateway(t)
	env := cliEnv(t)
	env[EnvEnrollCode] = "mge_CLISECRET"
	writeCLIConfig(t, env, fmt.Sprintf("gateway: %s\nmachine: from-config\n", g.srv.URL))
	code, out, errOut := runEnv(env, "login", "--key-store", "file")
	if code != 0 || !strings.Contains(out, `"from-config"`) {
		t.Fatalf("login: %d\n%s\n%s", code, out, errOut)
	}
	code, _, errOut = runEnv(env, "login", "--key-store", "file")
	if code != 1 || !strings.Contains(errOut, "already logged in") {
		t.Fatalf("second login: %d %s", code, errOut)
	}
}

func TestLoginErrors(t *testing.T) {
	env := cliEnv(t)
	if code, _, errOut := runEnv(env, "login", "--key-store", "file"); code != 1 || !strings.Contains(errOut, "--gateway") {
		t.Fatalf("no gateway: %d %s", code, errOut)
	}
	if code, _, errOut := runEnv(env, "login", "--bogus"); code != 2 || !strings.Contains(errOut, "usage: mcp-gateway login") {
		t.Fatalf("bad flag: %d %s", code, errOut)
	}
	writeCLIConfig(t, env, "nope: 1\n")
	if code, _, errOut := runEnv(env, "login", "--gateway", "https://g.example.com"); code != 1 || !strings.Contains(errOut, "nope") {
		t.Fatalf("invalid config: %d %s", code, errOut)
	}
}

type cliConnector struct{ err error }

func (c cliConnector) Run(ctx context.Context, _ string, token func(context.Context) (string, error), _ map[string]machineclient.Target, onConnected func()) error {
	if _, err := token(ctx); err != nil {
		return err
	}
	onConnected()
	return c.err
}

func TestUpUsesTheConnector(t *testing.T) {
	g := newCLIGateway(t)
	env := cliEnv(t)
	loginCLI(t, g, env)
	writeCLIConfig(t, env, "servers:\n  local:\n    http: http://127.0.0.1:9/mcp\n")
	old := newConnector
	t.Cleanup(func() { newConnector = old })
	newConnector = func() machineclient.Connector { return cliConnector{err: machineclient.ErrRevoked} }
	code, _, errOut := runEnv(env, "up")
	if code != 1 || !strings.Contains(errOut, "revoked") || !strings.Contains(errOut, "connected to") {
		t.Fatalf("up: %d\n%s", code, errOut)
	}
}

func TestServiceCommands(t *testing.T) {
	g := newCLIGateway(t)
	env := cliEnv(t)
	oldGOOS, oldExec, oldExe := goos, serviceExec, executable
	t.Cleanup(func() { goos, serviceExec, executable = oldGOOS, oldExec, oldExe })
	goos = "linux"
	executable = func() (string, error) { return "/usr/local/bin/mcp-gateway", nil }
	var calls []string
	serviceExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}

	// Not logged in: refused before anything is written.
	writeCLIConfig(t, env, "servers:\n  local:\n    http: http://127.0.0.1:9/mcp\n")
	if code, _, errOut := runEnv(env, "service", "install"); code != 1 || !strings.Contains(errOut, "not logged in") {
		t.Fatalf("install while logged out: %d %s", code, errOut)
	}
	loginCLI(t, g, env)
	code, out, errOut := runEnv(env, "service", "install")
	if code != 0 {
		t.Fatalf("install: %d\n%s\n%s", code, out, errOut)
	}
	unit, err := os.ReadFile(filepath.Join(env["HOME"], ".config/systemd/user/mcp-gateway.service"))
	if err != nil || !strings.Contains(string(unit), `ExecStart="/usr/local/bin/mcp-gateway" "up" "--config"`) {
		t.Fatalf("unit %v:\n%s", err, unit)
	}
	if !strings.Contains(out, "$ systemctl --user enable mcp-gateway.service") || len(calls) != 3 {
		t.Fatalf("calls %v\n%s", calls, out)
	}
	if code, out, _ := runEnv(env, "service", "status"); code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("status: %d %s", code, out)
	}
	if code, _, _ := runEnv(env, "service", "uninstall"); code != 0 {
		t.Fatal("uninstall failed")
	}
	if code, _, errOut := runEnv(env, "service", "restart"); code != 2 || !strings.Contains(errOut, "unknown action") {
		t.Fatalf("unknown action: %d %s", code, errOut)
	}
	if code, _, _ := runEnv(env, "service"); code != 2 {
		t.Fatal("service without an action must be a usage error")
	}
}

func TestServiceInstallAcceptsActionsOnly(t *testing.T) {
	g := newCLIGateway(t)
	env := cliEnv(t)
	oldGOOS, oldExec, oldExe := goos, serviceExec, executable
	t.Cleanup(func() { goos, serviceExec, executable = oldGOOS, oldExec, oldExe })
	goos = "linux"
	executable = func() (string, error) { return "/usr/local/bin/mcp-gateway", nil }
	serviceExec = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	loginCLI(t, g, env)

	// Neither servers nor actions: the service could only crash-loop.
	writeCLIConfig(t, env, "servers: {}\n")
	if code, _, errOut := runEnv(env, "service", "install"); code != 1 || !strings.Contains(errOut, "no servers") {
		t.Fatalf("empty config: %d %s", code, errOut)
	}
	// Actions alone are something to serve.
	writeCLIConfig(t, env, "actions:\n  hello:\n    run: /bin/sh -c true\n    secret: stdin\n")
	if code, out, errOut := runEnv(env, "service", "install"); code != 0 {
		t.Fatalf("actions-only install: %d\n%s\n%s", code, out, errOut)
	}
}
