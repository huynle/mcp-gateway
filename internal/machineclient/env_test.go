package machineclient

import (
	"reflect"
	"strings"
	"testing"
)

var cliEnviron = []string{
	"PATH=/usr/bin:/bin",
	"HOME=/home/u",
	"USER=u",
	"LANG=en_US.UTF-8",
	"LC_ALL=C",
	"LC_CTYPE=UTF-8",
	"TMPDIR=/tmp/u",
	"SHELL=/bin/zsh",
	"MCP_GATEWAY_TUNNEL_TOKEN=mgt_secret",
	"AWS_SECRET_ACCESS_KEY=aws-secret",
	"GITHUB_TOKEN=ghp_secret",
	"MY_TOKEN=s3cret",
	"EDITOR=vim",
}

func TestBuildStdioSpecCleanEnv(t *testing.T) {
	s := &Server{Name: "x", Kind: KindStdio, Command: []string{"npx", "-y", "srv"}}
	spec, err := BuildStdioSpec(s, cliEnviron)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"HOME=/home/u", "LANG=en_US.UTF-8", "LC_ALL=C", "LC_CTYPE=UTF-8", "PATH=/usr/bin:/bin", "TMPDIR=/tmp/u", "USER=u",
	}
	if !reflect.DeepEqual(spec.Env, want) {
		t.Fatalf("env\n got %v\nwant %v", spec.Env, want)
	}
	if !reflect.DeepEqual(spec.Command, []string{"npx", "-y", "srv"}) || spec.Dir != "" {
		t.Fatalf("spec %+v", spec)
	}
	// The spec must not alias the config's slice.
	spec.Command[0] = "changed"
	if s.Command[0] != "npx" {
		t.Fatal("spec aliases the server's command")
	}
}

func TestBuildStdioSpecNoSecrets(t *testing.T) {
	s := &Server{Name: "x", Kind: KindStdio, Command: []string{"srv"}, InheritEnv: []string{"EDITOR", "NOT_SET"}}
	spec, err := BuildStdioSpec(s, cliEnviron)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(spec.Env, "\n")
	for _, secret := range []string{"mgt_secret", "aws-secret", "ghp_secret", "s3cret", "SHELL"} {
		if strings.Contains(joined, secret) {
			t.Errorf("env leaks %q:\n%s", secret, joined)
		}
	}
	if !strings.Contains(joined, "EDITOR=vim") {
		t.Errorf("inherit_env EDITOR missing:\n%s", joined)
	}
	if strings.Contains(joined, "NOT_SET") {
		t.Errorf("an unset inherited variable must be skipped:\n%s", joined)
	}
}

func TestBuildStdioSpecEnvAndExpansion(t *testing.T) {
	s := &Server{
		Name: "x", Kind: KindStdio, Command: []string{"srv"},
		Env:        map[string]string{"API_KEY": "${MY_TOKEN}", "MODE": "a-${USER}-b $NOT_EXPANDED", "PATH": "/opt/bin"},
		InheritEnv: []string{"LANG"},
		Cwd:        "~/work",
	}
	spec, err := BuildStdioSpec(s, cliEnviron)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range spec.Env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Fatalf("duplicate %s in %v", k, spec.Env)
		}
		got[k] = v
	}
	if got["API_KEY"] != "s3cret" || got["MODE"] != "a-u-b $NOT_EXPANDED" || got["PATH"] != "/opt/bin" {
		t.Fatalf("env %v", got)
	}
	if spec.Dir != "/home/u/work" {
		t.Fatalf("dir %q", spec.Dir)
	}
	s.Cwd = "~"
	if spec, _ = BuildStdioSpec(s, cliEnviron); spec.Dir != "/home/u" {
		t.Fatalf("dir %q", spec.Dir)
	}
	s.Cwd = "/abs"
	if spec, _ = BuildStdioSpec(s, cliEnviron); spec.Dir != "/abs" {
		t.Fatalf("dir %q", spec.Dir)
	}
}

func TestBuildStdioSpecErrors(t *testing.T) {
	s := &Server{Name: "x", Kind: KindStdio, Command: []string{"srv"}, Env: map[string]string{"K": "${MISSING_VAR}"}}
	_, err := BuildStdioSpec(s, cliEnviron)
	if err == nil || !strings.Contains(err.Error(), "MISSING_VAR") {
		t.Fatalf("want an error naming MISSING_VAR, got %v", err)
	}
	s = &Server{Name: "x", Kind: KindStdio, Command: []string{"srv"}, Env: map[string]string{"K": "${BROKEN"}}
	if _, err = BuildStdioSpec(s, cliEnviron); err == nil {
		t.Fatal("unterminated ${ must be an error")
	}
	s = &Server{Name: "x", Kind: KindStdio, Command: []string{"srv"}, Cwd: "~/w"}
	if _, err = BuildStdioSpec(s, []string{"PATH=/bin"}); err == nil {
		t.Fatal("~ without HOME must be an error")
	}
	s = &Server{Name: "x", Kind: KindHTTP, URL: "http://localhost/"}
	if _, err = BuildStdioSpec(s, cliEnviron); err == nil {
		t.Fatal("an http server has no stdio spec")
	}
	// Errors never contain the values of referenced variables.
	s = &Server{Name: "x", Kind: KindStdio, Command: []string{"srv"}, Env: map[string]string{"K": "${MY_TOKEN}${MISSING_VAR}"}}
	if _, err = BuildStdioSpec(s, cliEnviron); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error %v", err)
	}
}
