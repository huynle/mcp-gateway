// Command mcp-gateway is the MCP gateway's client CLI, run on a user's
// machine. Its subcommands:
//
//	mcp-gateway tunnel ...   connect a local stdio or private HTTP MCP server
//	                         to the gateway (internal/tunnelclient; the
//	                         mcp-gateway-tunnel binary is an alias)
//	mcp-gateway version      print the version
//	mcp-gateway help [cmd]   show usage
//
// See docs/tunnel.md.
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
  tunnel    connect a local stdio or private HTTP MCP server to the gateway
  version   print the version
  help      show this help, or "help <command>" for a command's flags

Run "mcp-gateway tunnel --help" for the tunnel flags.`

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
		case "version", "help":
			say(stdout, "%s\n", usage)
			return 0
		}
		return unknown(stderr, rest[0])
	default:
		return unknown(stderr, cmd)
	}
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
