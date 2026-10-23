package machineclient

import (
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const actionsConfig = `
servers:
  fusion:
    http: http://127.0.0.1:1/mcp
actions:
  sudo-apt-upgrade:
    run: sudo -A apt-get upgrade -y
    secret: askpass
    description: Upgrade the packages.
  psql-report:
    run: /usr/bin/psql "-h" '{host}' -U report --port={port} -c "select '{{literal}}'"
    secret: env:PGPASSWORD
    params:
      host: '[a-z0-9-]+'
      port: '[0-9]{2,5}'
    timeout: 30s
  feed:
    run: sh -c 'read x' sh
    secret: stdin
  piped:
    run: /bin/sh -c "cat <&3" sh
    secret: fd
`

// fakeLookPath resolves bare names under /opt/bin and refuses "missing".
func fakeLookPath(t *testing.T) {
	t.Helper()
	old := lookPath
	lookPath = func(file string) (string, error) {
		if strings.Contains(file, "missing") {
			return "", exec.ErrNotFound
		}
		if filepath.IsAbs(file) {
			return file, nil
		}
		return "/opt/bin/" + file, nil
	}
	t.Cleanup(func() { lookPath = old })
}

func TestParseConfigActions(t *testing.T) {
	fakeLookPath(t)
	c, err := ParseConfig([]byte(actionsConfig))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ActionNames(); !reflect.DeepEqual(got, []string{"feed", "piped", "psql-report", "sudo-apt-upgrade"}) {
		t.Fatalf("action names %v", got)
	}
	a := c.Actions["sudo-apt-upgrade"]
	if a.Name != "sudo-apt-upgrade" || a.Secret != SecretAskpass || a.Description != "Upgrade the packages." || a.Timeout != DefaultActionTimeout {
		t.Fatalf("sudo action %+v", a)
	}
	if got := a.Command(); got != "/opt/bin/sudo -A apt-get upgrade -y" {
		t.Fatalf("command %q", got)
	}
	p := c.Actions["psql-report"]
	if p.Secret != SecretEnv || p.SecretEnv != "PGPASSWORD" || p.Timeout != 30*time.Second {
		t.Fatalf("psql action %+v", p)
	}
	if got := p.Command(); got != `/usr/bin/psql -h {host} -U report --port={port} -c "select '{{literal}}'"` {
		t.Fatalf("command %q", got)
	}
	if got := p.ParamNames(); !reflect.DeepEqual(got, []string{"host", "port"}) {
		t.Fatalf("params %v", got)
	}
	if p.Params["host"].Pattern != "^(?:[a-z0-9-]+)$" {
		t.Fatalf("anchored pattern %q", p.Params["host"].Pattern)
	}
	argv, err := p.Argv(map[string]string{"host": "db-1", "port": "5432"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/psql", "-h", "db-1", "-U", "report", "--port=5432", "-c", "select '{literal}'"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv %q, want %q", argv, want)
	}
	if c.Actions["feed"].Secret != SecretStdin || c.Actions["piped"].Secret != SecretFD {
		t.Fatal("secret modes")
	}
}

func TestActionArgvRejectsBadParams(t *testing.T) {
	fakeLookPath(t)
	c, err := ParseConfig([]byte(actionsConfig))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Actions["psql-report"]
	for _, params := range []map[string]string{
		{"host": "db-1"},                                     // missing port
		{"host": "db; rm -rf /", "port": "5432"},             // pattern
		{"host": "db-1\nx", "port": "5432"},                  // anchoring: no multi-line escape
		{"host": "db-1", "port": "5432", "extra": "x"},       // undeclared
		{"host": "db-1", "port": "54321234"},                 // too long for {2,5}
		{"host": "db-1", "port": "5432", "secret": "hunter"}, // the secret is not a param
	} {
		if argv, err := p.Argv(params); err == nil {
			t.Errorf("params %q accepted: %q", params, argv)
		}
	}
}

func TestParseConfigActionsRejects(t *testing.T) {
	fakeLookPath(t)
	act := func(body string) string { return "actions:\n  a:\n" + body }
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"bad action name", "actions:\n  A:\n    run: x\n    secret: stdin\n", "action name"},
		{"leading dash", "actions:\n  -a:\n    run: x\n    secret: stdin\n", "action name"},
		{"long action name", "actions:\n  " + strings.Repeat("a", 64) + ":\n    run: x\n    secret: stdin\n", "action name"},
		{"unknown key", act("    run: x\n    secret: stdin\n    shell: true\n"), "shell"},
		{"null action", "actions:\n  a:\n", "run"},
		{"no run", act("    secret: stdin\n"), "run"},
		{"empty run", act("    run: '  '\n    secret: stdin\n"), "run"},
		{"unterminated", act("    run: \"echo 'x\"\n    secret: stdin\n"), "run"},
		{"relative path", act("    run: ./tool\n    secret: stdin\n"), "absolute"},
		{"not found", act("    run: missing-tool\n    secret: stdin\n"), "not found"},
		{"placeholder in program", act("    run: '{p}'\n    secret: stdin\n    params: {p: x}\n"), "program"},
		{"undeclared placeholder", act("    run: echo {host}\n    secret: stdin\n"), "host"},
		{"unused param", act("    run: echo hi\n    secret: stdin\n    params: {host: x}\n"), "not used"},
		{"bad param name", act("    run: echo {Host}\n    secret: stdin\n    params: {Host: x}\n"), "param name"},
		{"reserved param", act("    run: echo {secret}\n    secret: stdin\n    params: {secret: x}\n"), "reserved"},
		{"bad regex", act("    run: echo {p}\n    secret: stdin\n    params: {p: '('}\n"), "pattern"},
		{"no secret", act("    run: echo\n"), "secret"},
		{"bad secret", act("    run: echo\n    secret: argv\n"), "secret"},
		{"bad env secret", act("    run: echo\n    secret: env:pg-pass\n"), "env:"},
		{"empty env secret", act("    run: echo\n    secret: 'env:'\n"), "env:"},
		{"long description", act("    run: echo\n    secret: stdin\n    description: " + strings.Repeat("x", 501) + "\n"), "description"},
		{"bad timeout", act("    run: echo\n    secret: stdin\n    timeout: soon\n"), "timeout"},
		{"zero timeout", act("    run: echo\n    secret: stdin\n    timeout: 0s\n"), "timeout"},
		{"short timeout", act("    run: echo\n    secret: stdin\n    timeout: 500ms\n"), "timeout"},
		{"long timeout", act("    run: echo\n    secret: stdin\n    timeout: 31m\n"), "timeout"},
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

func TestParseConfigActionTimeoutBounds(t *testing.T) {
	fakeLookPath(t)
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{{"1s", time.Second}, {"30m", 30 * time.Minute}, {"90s", 90 * time.Second}} {
		c, err := ParseConfig([]byte("actions:\n  a:\n    run: echo\n    secret: stdin\n    timeout: " + tc.in + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if got := c.Actions["a"].Timeout; got != tc.want {
			t.Fatalf("%s: timeout %v", tc.in, got)
		}
	}
}

func TestParseConfigActionLookPathReal(t *testing.T) {
	c, err := ParseConfig([]byte("actions:\n  a:\n    run: sh -c true\n    secret: stdin\n"))
	if err != nil {
		t.Fatal(err)
	}
	argv, err := c.Actions["a"].Argv(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(argv[0]) || filepath.Base(argv[0]) != "sh" {
		t.Fatalf("argv[0] %q is not the resolved absolute path", argv[0])
	}
}

func TestActionsServerName(t *testing.T) {
	fakeLookPath(t)
	c, err := ParseConfig([]byte("servers:\n  devbox-actions:\n    stdio: srv\n  other:\n    stdio: srv\nactions:\n  a:\n    run: echo\n    secret: stdin\n"))
	if err != nil {
		t.Fatal(err)
	}
	if name, err := c.ActionsServerName("laptop"); err != nil || name != "laptop-actions" {
		t.Fatalf("name %q, %v", name, err)
	}
	if _, err := c.ActionsServerName("devbox"); err == nil || !strings.Contains(err.Error(), "devbox-actions") {
		t.Fatalf("collision with a configured server: %v", err)
	}
	if _, err := c.ActionsServerName(strings.Repeat("m", 56)); err == nil || !strings.Contains(err.Error(), "63") {
		t.Fatalf("too long: %v", err)
	}
	if name, err := c.ActionsServerName(strings.Repeat("m", 55)); err != nil || len(name) != 63 {
		t.Fatalf("63 characters fit: %q %v", name, err)
	}
	// The config's own machine name is checked at parse time.
	_, err = ParseConfig([]byte("machine: devbox\nservers:\n  devbox-actions:\n    stdio: srv\nactions:\n  a:\n    run: echo\n    secret: stdin\n"))
	if err == nil || !strings.Contains(err.Error(), "devbox-actions") {
		t.Fatalf("parse-time collision: %v", err)
	}
	// Without actions there is no actions server and no collision.
	c, err = ParseConfig([]byte("servers:\n  devbox-actions:\n    stdio: srv\n"))
	if err != nil {
		t.Fatal(err)
	}
	if name, err := c.ActionsServerName("devbox"); err != nil || name != "" {
		t.Fatalf("no actions: %q %v", name, err)
	}
}

func TestSplitRunWords(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{`a b  c`, []string{"a", "b", "c"}},
		{`a "b c" 'd e'`, []string{"a", "b c", "d e"}},
		{`a b\ c "x\"y" 'it''s'`, []string{"a", "b c", `x"y`, "its"}},
		{`a ""`, []string{"a", ""}},
		{`a $HOME * ; | > ~/x`, []string{"a", "$HOME", "*", ";", "|", ">", "~/x"}},
	} {
		got, err := splitRun(tc.in)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitRun(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{``, `   `, `a "b`, `a 'b`, `a \`} {
		if _, err := splitRun(bad); err == nil {
			t.Errorf("splitRun(%q) accepted", bad)
		}
	}
}
