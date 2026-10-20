// Package tunnelclient is the user-side MCP tunnel client shared by the
// `mcp-gateway tunnel` subcommand (cmd/mcp-gateway) and the
// `mcp-gateway-tunnel` alias binary (cmd/mcp-gateway-tunnel). It connects
// a stdio or private-network MCP server to an MCP gateway. It runs on the
// user's machine, next to the server, and only ever connects out: it opens
// a WebSocket to the gateway's /tunnel/connect endpoint with a tunnel
// token, then serves the HTTP requests the gateway sends through it,
// either by bridging them to a stdio MCP server it starts (--stdio) or by
// forwarding them to a local HTTP MCP server (--http). See docs/tunnel.md.
package tunnelclient

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
)

// Environment variables read by the client.
const (
	EnvToken   = "MCP_GATEWAY_TUNNEL_TOKEN"
	EnvGateway = "MCP_GATEWAY_URL"
)

// usage is the help text; %[1]s is the command name as invoked
// ("mcp-gateway tunnel" or "mcp-gateway-tunnel").
const usage = `usage: %[1]s --gateway https://gateway.example.com [--token mgt_...] (--stdio "<command and args>" | --http http://localhost:PORT/mcp)

The token is read from --token or, preferably, $` + EnvToken + ` (flags are
visible to other local users in the process list). --gateway defaults to $` + EnvGateway + `.

Flags:
  --gateway URL     gateway base URL, https (http only for localhost); default $` + EnvGateway + `
  --token mgt_...   tunnel token; default $` + EnvToken + `
  --stdio "CMD"     start this stdio MCP server command and bridge it
  --http URL        forward to this private HTTP MCP server
  --verbose         debug logging
  --version         print the version`

type config struct {
	gateway    string
	token      string
	stdio      []string
	httpTarget *url.URL
	verbose    bool
}

// parseConfig reads flags and the environment. Error messages never
// contain the token.
func parseConfig(args []string, getenv func(string) string) (*config, error) {
	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	gateway := fs.String("gateway", getenv(EnvGateway), "gateway base URL (https)")
	token := fs.String("token", "", "tunnel token (default $"+EnvToken+")")
	stdio := fs.String("stdio", "", "stdio MCP server command and arguments")
	target := fs.String("http", "", "private HTTP MCP server URL")
	verbose := fs.Bool("verbose", false, "debug logging")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, errors.New("unexpected arguments after the flags (quote the --stdio command)")
	}
	c := &config{token: *token, verbose: *verbose}
	if c.token == "" {
		c.token = getenv(EnvToken)
	}
	if c.token == "" {
		return nil, errors.New("no tunnel token: set $" + EnvToken + " or --token")
	}
	if tunnel.ParseToken(c.token) != nil {
		return nil, errors.New("the tunnel token is malformed (expected mgt_...)")
	}
	gw, err := gatewayURL(*gateway)
	if err != nil {
		return nil, err
	}
	c.gateway = gw
	switch {
	case *stdio != "" && *target != "":
		return nil, errors.New("use either --stdio or --http, not both")
	case *stdio != "":
		if c.stdio, err = splitCommand(*stdio); err != nil {
			return nil, fmt.Errorf("--stdio: %w", err)
		}
	case *target != "":
		u, err := url.Parse(*target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, errors.New("--http must be an http(s) URL such as http://localhost:8080/mcp")
		}
		c.httpTarget = u
	default:
		return nil, errors.New("one of --stdio or --http is required")
	}
	return c, nil
}

// gatewayURL requires https, except for a loopback gateway (local testing).
func gatewayURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("--gateway is required (or $" + EnvGateway + ")")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("--gateway must be a base URL such as https://gateway.example.com")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", errors.New("--gateway must use https (http is allowed only for localhost)")
		}
	default:
		return "", errors.New("--gateway must use https")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// splitCommand splits a command line into arguments: whitespace separates,
// single quotes are literal, double quotes allow \" and \\, a backslash
// outside quotes escapes the next character. No shell expansion of any
// kind happens.
func splitCommand(s string) ([]string, error) {
	var (
		args    []string
		cur     strings.Builder
		inArg   bool
		quote   rune
		escaped bool
	)
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case quote == '"':
			switch r {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			default:
				cur.WriteRune(r)
			}
		case r == '\\':
			escaped, inArg = true, true
		case r == '\'' || r == '"':
			quote, inArg = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 || escaped {
		return nil, errors.New("unterminated quote or escape")
	}
	if inArg {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("empty command")
	}
	return args, nil
}

// Options name and version the running command.
type Options struct {
	// Name is the command as the user invoked it, used in status lines and
	// the usage text, e.g. "mcp-gateway tunnel". Default "mcp-gateway-tunnel".
	Name string
	// Version is printed by --version. Default "dev".
	Version string
}

// Run runs the tunnel client with the given arguments (without the command
// name) until ctx ends, the tunnel stops for good or the stdio server
// exits, and returns the process exit code: 0 on a graceful shutdown or
// --help/--version, 1 when the tunnel stopped, 2 on a usage error.
func Run(parent context.Context, opts Options, args []string, getenv func(string) string, stderr io.Writer) int {
	name, ver := opts.Name, opts.Version
	if name == "" {
		name = "mcp-gateway-tunnel"
	}
	if ver == "" {
		ver = "dev"
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-version") {
		say(stderr, "%s %s\n", name, ver)
		return 0
	}
	cfg, err := parseConfig(args, getenv)
	if errors.Is(err, flag.ErrHelp) {
		say(stderr, usage+"\n", name)
		return 0
	}
	if err != nil {
		say(stderr, "%s: %v\n\n"+usage+"\n", name, err)
		return 2
	}
	level := slog.LevelInfo
	if cfg.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		handler   http.Handler
		serving   string
		childDone <-chan struct{}
		proc      *tunnel.StdioProcess
	)
	if cfg.stdio != nil {
		proc, err = tunnel.StartStdio(ctx, tunnel.StdioOptions{Command: cfg.stdio, Env: childEnv(os.Environ()), Stderr: stderr, Log: log})
		if err != nil {
			say(stderr, "%s: start stdio server: %v\n", name, err)
			return 1
		}
		defer proc.Stop()
		handler, childDone = proc.Handler(), proc.Done()
		serving = "stdio server " + filepath.Base(cfg.stdio[0])
	} else {
		handler = tunnel.NewHTTPForwarder(cfg.httpTarget, localClient())
		serving = "HTTP server " + cfg.httpTarget.Host
	}

	gwHost := hostOf(cfg.gateway)
	agent, err := tunnel.NewAgent(tunnel.AgentOptions{
		GatewayURL: cfg.gateway, Token: cfg.token, Handler: handler, HTTPClient: gatewayClient(), Log: log,
		OnStatus: func(s tunnel.Status) { statusLine(stderr, name, s, gwHost, serving) },
	})
	if err != nil {
		say(stderr, "%s: %v\n", name, err)
		return 2
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var childExited atomic.Bool
	if childDone != nil {
		go func() {
			select {
			case <-childDone:
				childExited.Store(runCtx.Err() == nil)
				cancel()
			case <-runCtx.Done():
			}
		}()
	}
	err = agent.Run(runCtx)
	switch {
	case ctx.Err() != nil:
		say(stderr, "%s: shutting down\n", name)
		return 0
	case childExited.Load():
		say(stderr, "%s: the stdio server exited; stopping\n", name)
		return 1
	case errors.Is(err, tunnel.ErrRejected):
		say(stderr, "%s: the gateway rejected the token (wrong or revoked); create a new tunnel token in the portal\n", name)
	case errors.Is(err, tunnel.ErrReplaced):
		say(stderr, "%s: another tunnel client connected with this token; stopping\n", name)
	case errors.Is(err, tunnel.ErrRevoked):
		say(stderr, "%s: the tunnel was revoked; stopping\n", name)
	default:
		say(stderr, "%s: %v\n", name, err)
	}
	return 1
}

// say writes a line for the user; a failing stderr is not worth handling.
func say(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func statusLine(w io.Writer, name string, s tunnel.Status, gateway, serving string) {
	switch s.State {
	case tunnel.StateConnecting:
		say(w, "%s: connecting to %s\n", name, gateway)
	case tunnel.StateConnected:
		say(w, "%s: connected to %s, serving %s\n", name, gateway, serving)
	case tunnel.StateDisconnected:
		if s.RetryIn > 0 {
			say(w, "%s: disconnected (%v); retrying in %s\n", name, s.Err, s.RetryIn.Round(time.Millisecond))
		}
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// gatewayClient dials the gateway (environment proxies honoured).
func gatewayClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{Transport: tr}
}

// localClient talks to the private HTTP MCP server: no proxies (the server
// is local or on the user's network), redirects passed through untouched.
func localClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// childEnv is the stdio server's environment: ours without the tunnel
// token.
func childEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, EnvToken+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
