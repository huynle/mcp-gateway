// Command mcp-gateway is the MCP gateway's client CLI, run on a user's
// machine. Its subcommands:
//
//	mcp-gateway login        enroll this machine (device flow or enrollment
//	                         code; internal/machineclient)
//	mcp-gateway status       check config.yaml, the machine and its servers
//	mcp-gateway up           serve config.yaml's servers over one connection
//	mcp-gateway logout       revoke this machine and delete its key
//	mcp-gateway service ...  install|uninstall|status of the background service
//	mcp-gateway proxy        stdio MCP server for a harness, forwarding to
//	                         the gateway's /mcp; signs in with a code
//	                         (device flow; internal/mcpproxy)
//	mcp-gateway tunnel ...   connect a local stdio or private HTTP MCP server
//	                         to the gateway with a tunnel token
//	                         (internal/tunnelclient; the mcp-gateway-tunnel
//	                         binary is an alias)
//	mcp-gateway version      print the version
//	mcp-gateway help [cmd]   show usage
//
// See docs/machines-cli.md, docs/harness-setup.md and docs/tunnel.md.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/huynle/mcp-gateway/internal/tunnelclient"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: mcp-gateway <command> [flags]

Commands:
  login     enroll this machine with the gateway (approve it in the browser, or --enroll-code)
  status    check config.yaml, this machine's credentials and its servers
  up        serve the servers of config.yaml through the gateway (one connection)
  logout    revoke this machine and delete its key
  service   install|uninstall|status: run "up" in the background (launchd / systemd)
  proxy     stdio MCP server for a harness (OpenCode, Claude Code, ...): forwards to the gateway, signs in with a code
  tunnel    connect one local stdio or private HTTP MCP server with a tunnel token
  version   print the version
  help      show this help, or "help <command>" for a command's flags

Run "mcp-gateway <command> --help" for its flags.`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run is main without the process globals; it returns the exit code:
// 0 on success, 1 when a command failed, 2 on a usage error.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, "%s\n", usage)
		return 2
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "tunnel":
		return tunnel(ctx, rest, getenv, stderr)
	case "login", "status", "up", "logout", "service", "proxy":
		return machineCommands[cmd](ctx, rest, getenv, stdout, stderr)
	case "version", "--version", "-version":
		say(stdout, "mcp-gateway %s\n", version)
		return 0
	case "help", "--help", "-help", "-h":
		if len(rest) == 0 {
			say(stdout, "%s\n", usage)
			return 0
		}
		switch rest[0] {
		case "tunnel":
			return tunnel(ctx, []string{"--help"}, getenv, stderr)
		case "login", "status", "up", "logout", "service", "proxy":
			return machineCommands[rest[0]](ctx, []string{"--help"}, getenv, stdout, stderr)
		case "version", "help":
			say(stdout, "%s\n", usage)
			return 0
		}
		return unknown(stderr, rest[0])
	default:
		return unknown(stderr, cmd)
	}
}

type command func(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int

// machineCommands are the commands that keep state under
// ~/.config/mcp-gateway: machine enrollment (machine.go) and the harness
// proxy (proxy.go).
var machineCommands = map[string]command{
	"login": login, "status": status, "up": up, "logout": logout, "service": service, "proxy": proxy,
}

func tunnel(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) int {
	opts := tunnelclient.Options{Name: "mcp-gateway tunnel", Version: version}
	return tunnelclient.Run(ctx, opts, args, getenv, stderr)
}

func unknown(stderr io.Writer, cmd string) int {
	say(stderr, "mcp-gateway: unknown command %q\n\n%s\n", cmd, usage)
	return 2
}

// say writes a line for the user; a failing writer is not worth handling.
func say(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
