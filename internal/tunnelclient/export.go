package tunnelclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

// The exports below let internal/machineclient (`mcp-gateway up`) reuse
// the tunnel client's stdio bridge and HTTP forwarder for each server of a
// machine; `mcp-gateway tunnel` itself is unchanged.

// SplitCommand splits a command line into arguments exactly like --stdio:
// whitespace separates, single quotes are literal, double quotes allow \"
// and \\, a backslash outside quotes escapes the next character. No shell
// expansion of any kind happens.
func SplitCommand(s string) ([]string, error) { return splitCommand(s) }

// NewHTTPForwarder forwards tunnel requests to a private HTTP MCP server
// (no proxies, redirects passed through), exactly like --http.
func NewHTTPForwarder(target *url.URL) http.Handler {
	return newHTTPForwarder(target, localClient())
}

// StdioCommand is a stdio MCP server to start.
type StdioCommand struct {
	// Argv is the program and its arguments (no shell).
	Argv []string
	// Env is the complete environment: nothing is inherited, nil is empty.
	Env []string
	// Dir is the working directory ("" = the caller's).
	Dir string
}

// StdioServer is a running stdio MCP server behind the JSON-RPC bridge of
// --stdio.
type StdioServer struct{ p *stdioProcess }

// StartStdio starts the server; its stderr goes to stderr. Cancelling ctx
// sends SIGTERM; Stop is the graceful way (close stdin, then SIGTERM,
// then SIGKILL).
func StartStdio(ctx context.Context, c StdioCommand, stderr io.Writer, log *slog.Logger) (*StdioServer, error) {
	if len(c.Argv) == 0 || c.Argv[0] == "" {
		return nil, errors.New("empty command")
	}
	p, err := startProcess(ctx, c.Argv, c.Env, c.Dir, stderr, log)
	if err != nil {
		return nil, err
	}
	return &StdioServer{p: p}, nil
}

// Handler serves the gateway's Streamable HTTP requests through the bridge.
func (s *StdioServer) Handler() http.Handler { return s.p.bridge }

// Done is closed when the process has exited.
func (s *StdioServer) Done() <-chan struct{} { return s.p.exited }

// Stop stops the process gracefully and waits for it.
func (s *StdioServer) Stop() { s.p.stop() }
