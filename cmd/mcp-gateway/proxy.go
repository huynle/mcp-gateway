package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/huynle/mcp-gateway/internal/machineclient"
	"github.com/huynle/mcp-gateway/internal/mcpproxy"
	"github.com/huynle/mcp-gateway/internal/tunnelclient"
)

// EnvGatewayURL names the gateway for `proxy` when --gateway is not
// given (the same variable as `tunnel`).
const EnvGatewayURL = tunnelclient.EnvGateway

// Seams for tests.
var (
	// proxyStdin is what `proxy` reads the harness's messages from.
	proxyStdin io.Reader = os.Stdin
	// proxySleep is the device-flow polling clock (nil: real time).
	proxySleep func(ctx context.Context, d time.Duration) error
)

const proxyUsage = `usage: mcp-gateway proxy [--gateway URL] [--scope mcp|mcp:read] [--login] [--key-store keychain|file] [--config PATH] [--verbose]

A stdio MCP server for any harness that starts local MCP commands
(OpenCode, Claude Code, ...): it forwards every message to the gateway's
/mcp endpoint. The first run signs in with a code: it prints a link and a
code on stderr; open the link on any device signed in to the portal and
press Allow. The sign-in is kept for this user and host (refresh token in
the keychain on macOS, else a 0600 file under ~/.config/mcp-gateway/proxy),
independent of "mcp-gateway login". Disconnect it on the portal's
Harnesses page; the next run asks for a new code.

stdout carries only MCP messages; everything else goes to stderr.

Flags:
  --gateway URL        gateway base URL (default $` + EnvGatewayURL + `, else gateway in
                       config.yaml, else the gateway this machine is logged in to)
  --scope SCOPE        mcp (everything your role allows, default) or mcp:read (read tools only)
  --login              sign in (if needed) and exit, without serving stdio
  --key-store STORE    keychain (macOS default) or file
  --config PATH        config file (default $MCP_GATEWAY_CONFIG, else ~/.config/mcp-gateway/config.yaml)
  --verbose            debug logging on stderr`

func proxy(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := cmdFlags("proxy")
	gateway := fs.String("gateway", "", "")
	scope := fs.String("scope", mcpproxy.ScopeFull, "")
	loginOnly := fs.Bool("login", false, "")
	keyStore := fs.String("key-store", machineclient.DefaultKeyStore(), "")
	configFlag := fs.String("config", "", "")
	verbose := fs.Bool("verbose", false, "")
	// --help goes to stdout like the other commands; when serving, stdout
	// is the protocol stream and nothing else is written there.
	if c, stop := parse(fs, args, proxyUsage, stdout, stderr); stop {
		return c
	}
	if *scope != mcpproxy.ScopeFull && *scope != mcpproxy.ScopeRead {
		say(stderr, "mcp-gateway proxy: --scope must be mcp or mcp:read\n\n%s\n", proxyUsage)
		return 2
	}
	cfgPath, stateDir, err := paths(*configFlag, getenv)
	if err != nil {
		return fail(stderr, "proxy", err)
	}
	gw, err := resolveProxyGateway(*gateway, cfgPath, stateDir, getenv)
	if err != nil {
		return fail(stderr, "proxy", err)
	}
	dir := filepath.Join(stateDir, "proxy")
	secrets, err := machineclient.NewSecretStore(*keyStore, dir, mcpproxy.SecretService)
	if err != nil {
		return fail(stderr, "proxy", err)
	}
	host, _ := hostname()
	host = strings.TrimSpace(host)
	if host == "" {
		host = "unknown host"
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	o := mcpproxy.Options{
		Gateway: gw, Scope: *scope, ClientName: "mcp-gateway proxy (" + host + ")", Version: version,
		Dir: dir, Secrets: secrets, LoginOnly: *loginOnly,
		Stdin: proxyStdin, Stdout: stdout, Stderr: stderr, Sleep: proxySleep,
	}
	if *verbose {
		o.Log = newLogger(stderr, true)
	}
	if *loginOnly {
		o.Stdout = nil
	}
	return exitFor(stderr, "proxy", mcpproxy.Run(ctx, o))
}

// resolveProxyGateway resolves the gateway: the flag, $MCP_GATEWAY_URL, the
// config file's gateway, then the gateway this machine is enrolled with.
func resolveProxyGateway(flagValue, cfgPath, stateDir string, getenv func(string) string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := getenv(EnvGatewayURL); v != "" {
		return v, nil
	}
	if _, err := os.Stat(cfgPath); err == nil {
		cfg, err := machineclient.LoadConfig(cfgPath)
		if err != nil {
			return "", err
		}
		if cfg.Gateway != "" {
			return cfg.Gateway, nil
		}
	}
	st, err := machineclient.LoadState(stateDir)
	switch {
	case err == nil:
		return st.Gateway, nil
	case errors.Is(err, machineclient.ErrNotLoggedIn):
		return "", fmt.Errorf("no gateway: pass --gateway, set $%s, or set gateway in %s", EnvGatewayURL, cfgPath)
	default:
		return "", err
	}
}
