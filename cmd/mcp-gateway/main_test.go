package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, func(string) string { return "" }, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestDispatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		code    int
		stdout  string // substring expected on stdout
		stderr  string // substring expected on stderr
		noStdio bool
	}{
		{name: "no args", args: nil, code: 2, stderr: "usage: mcp-gateway <command>"},
		{name: "unknown", args: []string{"frobnicate"}, code: 2, stderr: `unknown command "frobnicate"`},
		{name: "unknown shows usage", args: []string{"frobnicate"}, code: 2, stderr: "tunnel"},
		{name: "help", args: []string{"help"}, code: 0, stdout: "usage: mcp-gateway <command>"},
		{name: "-h", args: []string{"-h"}, code: 0, stdout: "usage: mcp-gateway <command>"},
		{name: "--help", args: []string{"--help"}, code: 0, stdout: "version"},
		{name: "version", args: []string{"version"}, code: 0, stdout: "mcp-gateway test-version"},
		{name: "--version", args: []string{"--version"}, code: 0, stdout: "mcp-gateway test-version"},
		{name: "help tunnel", args: []string{"help", "tunnel"}, code: 0, stderr: "--stdio"},
		{name: "help unknown", args: []string{"help", "nope"}, code: 2, stderr: `unknown command "nope"`},
		{name: "tunnel usage error", args: []string{"tunnel"}, code: 2, stderr: "mcp-gateway tunnel: "},
		{name: "tunnel version", args: []string{"tunnel", "--version"}, code: 0, stderr: "mcp-gateway tunnel test-version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version = "test-version"
			code, out, errOut := runCLI(tc.args...)
			if code != tc.code {
				t.Fatalf("exit code %d, want %d\nstdout:%s\nstderr:%s", code, tc.code, out, errOut)
			}
			if tc.stdout != "" && !strings.Contains(out, tc.stdout) {
				t.Errorf("stdout %q does not contain %q", out, tc.stdout)
			}
			if tc.stderr != "" && !strings.Contains(errOut, tc.stderr) {
				t.Errorf("stderr %q does not contain %q", errOut, tc.stderr)
			}
		})
	}
}

func TestTunnelHelpListsFlags(t *testing.T) {
	for _, args := range [][]string{{"tunnel", "--help"}, {"tunnel", "-h"}} {
		code, _, errOut := runCLI(args...)
		if code != 0 {
			t.Fatalf("%v: exit code %d, stderr:\n%s", args, code, errOut)
		}
		if !strings.Contains(errOut, "usage: mcp-gateway tunnel ") {
			t.Errorf("%v: usage does not name the subcommand:\n%s", args, errOut)
		}
		for _, flag := range []string{"--gateway", "--token", "--stdio", "--http", "--verbose", "--version", "MCP_GATEWAY_TUNNEL_TOKEN", "MCP_GATEWAY_URL"} {
			if !strings.Contains(errOut, flag) {
				t.Errorf("%v: help does not list %s:\n%s", args, flag, errOut)
			}
		}
	}
}
