package machineclient

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestConfigPathPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag string
		env  map[string]string
		want string
	}{
		{"flag wins", "/flag.yaml", map[string]string{EnvConfig: "/env.yaml", "XDG_CONFIG_HOME": "/xdg", "HOME": "/home/u"}, "/flag.yaml"},
		{"env var", "", map[string]string{EnvConfig: "/env.yaml", "XDG_CONFIG_HOME": "/xdg", "HOME": "/home/u"}, "/env.yaml"},
		{"xdg", "", map[string]string{"XDG_CONFIG_HOME": "/xdg", "HOME": "/home/u"}, "/xdg/mcp-gateway/config.yaml"},
		{"home", "", map[string]string{"HOME": "/home/u"}, "/home/u/.config/mcp-gateway/config.yaml"},
		{"relative xdg ignored", "", map[string]string{"XDG_CONFIG_HOME": "rel", "HOME": "/home/u"}, "/home/u/.config/mcp-gateway/config.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ConfigPath(tc.flag, envMap(tc.env))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if _, err := ConfigPath("", envMap(nil)); err == nil {
		t.Fatal("no HOME: want an error")
	}
}

func TestStateDir(t *testing.T) {
	got, err := StateDir(envMap(map[string]string{"XDG_CONFIG_HOME": "/xdg", "HOME": "/h"}))
	if err != nil || got != "/xdg/mcp-gateway" {
		t.Fatalf("got %q %v", got, err)
	}
	got, err = StateDir(envMap(map[string]string{"HOME": "/h"}))
	if err != nil || got != "/h/.config/mcp-gateway" {
		t.Fatalf("got %q %v", got, err)
	}
}

const fullConfig = `
gateway: https://gateway.example.com/
machine: huy-macbook
servers:
  fusion360:
    http: http://127.0.0.1:27182/mcp
  everything:
    stdio: npx -y "@modelcontextprotocol/server-everything"
    env: {NODE_ENV: production, TOKEN: "${MY_TOKEN}"}
    cwd: ~/work
    inherit_env: [LANG]
  listy:
    command: [python3, -m, "my server"]
`

func TestParseConfigFull(t *testing.T) {
	c, err := ParseConfig([]byte(fullConfig))
	if err != nil {
		t.Fatal(err)
	}
	if c.Gateway != "https://gateway.example.com" {
		t.Errorf("gateway %q (trailing slash should be trimmed)", c.Gateway)
	}
	if c.Machine != "huy-macbook" {
		t.Errorf("machine %q", c.Machine)
	}
	if got := c.ServerNames(); !reflect.DeepEqual(got, []string{"everything", "fusion360", "listy"}) {
		t.Errorf("names %v", got)
	}
	f := c.Servers["fusion360"]
	if f.Name != "fusion360" || f.Kind != KindHTTP || f.URL != "http://127.0.0.1:27182/mcp" || f.Command != nil {
		t.Errorf("fusion360 %+v", f)
	}
	e := c.Servers["everything"]
	if e.Kind != KindStdio || !reflect.DeepEqual(e.Command, []string{"npx", "-y", "@modelcontextprotocol/server-everything"}) {
		t.Errorf("everything %+v", e)
	}
	if e.Env["NODE_ENV"] != "production" || e.Env["TOKEN"] != "${MY_TOKEN}" || e.Cwd != "~/work" || !reflect.DeepEqual(e.InheritEnv, []string{"LANG"}) {
		t.Errorf("everything env %+v", e)
	}
	if l := c.Servers["listy"]; !reflect.DeepEqual(l.Command, []string{"python3", "-m", "my server"}) || l.Kind != KindStdio {
		t.Errorf("listy %+v", l)
	}
}

func TestParseConfigMinimal(t *testing.T) {
	c, err := ParseConfig([]byte("servers:\n  a:\n    http: https://10.0.0.5/mcp\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Gateway != "" || c.Machine != "" || len(c.Servers) != 1 {
		t.Fatalf("%+v", c)
	}
	// An empty config (no servers yet) is valid: login works before servers exist.
	if _, err := ParseConfig([]byte("gateway: https://g.example.com\n")); err != nil {
		t.Fatal(err)
	}
}

func TestParseConfigRejects(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"unknown top key", "gateway: https://g.example.com\ntoken: x\n", "token"},
		{"unknown server key", "servers:\n  a:\n    http: http://localhost/\n    headers: {}\n", "headers"},
		{"both http and stdio", "servers:\n  a:\n    http: http://localhost/\n    stdio: foo\n", "exactly one"},
		{"stdio and command", "servers:\n  a:\n    stdio: foo\n    command: [foo]\n", "exactly one"},
		{"neither", "servers:\n  a:\n    cwd: /tmp\n", "exactly one"},
		{"bad scheme", "servers:\n  a:\n    http: ftp://localhost/\n", "http(s)"},
		{"no host", "servers:\n  a:\n    http: http:///mcp\n", "http(s)"},
		{"userinfo", "servers:\n  a:\n    http: http://u:p@localhost/\n", "credentials"},
		{"bad name", "servers:\n  A_B:\n    http: http://localhost/\n", "server name"},
		{"reserved name", "servers:\n  github:\n    http: http://localhost/\n", "reserved"},
		{"env on http", "servers:\n  a:\n    http: http://localhost/\n    env: {A: b}\n", "only for stdio"},
		{"cwd on http", "servers:\n  a:\n    http: http://localhost/\n    cwd: /tmp\n", "only for stdio"},
		{"inherit on http", "servers:\n  a:\n    http: http://localhost/\n    inherit_env: [A]\n", "only for stdio"},
		{"bad env name", "servers:\n  a:\n    stdio: foo\n    env: {\"A-B\": x}\n", "environment variable name"},
		{"bad inherit name", "servers:\n  a:\n    stdio: foo\n    inherit_env: [\"1A\"]\n", "environment variable name"},
		{"relative cwd", "servers:\n  a:\n    stdio: foo\n    cwd: work\n", "cwd"},
		{"empty stdio", "servers:\n  a:\n    stdio: '   '\n", "stdio"},
		{"unterminated quote", "servers:\n  a:\n    stdio: \"'foo\"\n", "stdio"},
		{"empty command", "servers:\n  a:\n    command: []\n", "exactly one"},
		{"empty command arg0", "servers:\n  a:\n    command: ['']\n", "command"},
		{"http gateway", "gateway: http://gateway.example.com\n", "https"},
		{"gateway path query", "gateway: https://g.example.com/?x=1\n", "base URL"},
		{"bad machine", "machine: -bad\n", "machine name"},
		{"duplicate key", "servers:\n  a:\n    stdio: foo\n  a:\n    stdio: bar\n", "already defined"},
		{"two documents", "gateway: https://g.example.com\n---\ngateway: https://h.example.com\n", "one YAML document"},
		{"not a mapping", "- a\n", "cannot unmarshal"},
		{"null server", "servers:\n  a:\n", "exactly one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestParseConfigAllowsLoopbackHTTPGateway(t *testing.T) {
	c, err := ParseConfig([]byte("gateway: http://127.0.0.1:8080\n"))
	if err != nil || c.Gateway != "http://127.0.0.1:8080" {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestLoadConfigFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(fullConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Path != p {
		t.Errorf("path %q", c.Path)
	}
	_, err = LoadConfig(filepath.Join(dir, "missing.yaml"))
	if err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Fatalf("missing file: %v", err)
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("nope: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bad); err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Fatalf("bad file error should name the file: %v", err)
	}
}

func TestMachineNames(t *testing.T) {
	for in, want := range map[string]string{
		"Huy-MacBook.local":     "huy-macbook",
		"my_host":               "my_host",
		"--weird--host":         "weird--host",
		"Ünïcode Host":          "n-code-host",
		"":                      "machine",
		"...":                   "machine",
		strings.Repeat("a", 80): strings.Repeat("a", 63),
	} {
		if got := DefaultMachineName(in); got != want {
			t.Errorf("DefaultMachineName(%q) = %q, want %q", in, got, want)
		}
		if err := ValidateMachineName(DefaultMachineName(in)); err != nil {
			t.Errorf("default name for %q invalid: %v", in, err)
		}
	}
	for _, bad := range []string{"", "-a", "_a", "A", "a b", strings.Repeat("a", 64)} {
		if ValidateMachineName(bad) == nil {
			t.Errorf("ValidateMachineName(%q) accepted", bad)
		}
	}
}
