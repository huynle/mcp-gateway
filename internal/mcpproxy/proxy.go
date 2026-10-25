// Package mcpproxy is `mcp-gateway proxy`: a stdio MCP server that
// bridges any harness able to start a local MCP command to the gateway's
// /mcp endpoint, signing in with the OAuth device flow (RFC 8628) so it
// works on a remote host (SSH) where no browser can receive a redirect.
//
//   - Stdio side (bridge.go): newline-delimited JSON-RPC on stdin and
//     stdout (the MCP stdio transport). Every message is POSTed to /mcp
//     concurrently; JSON and text/event-stream answers are written back one
//     message per line, atomically; 202 answers write nothing. stdout
//     carries protocol messages only, everything for people goes to stderr.
//   - Auth (oauth.go, tokens.go): discovery (protected resource metadata,
//     then authorization server metadata, all on the gateway's origin),
//     dynamic registration as the public client "mcp-gateway proxy
//     (<host>)" for the device_code and refresh_token grants, the device
//     flow with the code on stderr, and rotating refresh tokens. The
//     access token lives in memory; it is refreshed a minute before expiry
//     and after a 401 (the request is retried once). invalid_grant (the
//     harness was disconnected on /harnesses) signs in again.
//   - Storage (store.go): per gateway, independent of machine enrollment:
//     the client id in a 0600 JSON file, the refresh token in the macOS
//     keychain (service "mcp-gateway-proxy") or a 0600 file, under a file
//     lock shared by every proxy of the user.
//
// Tokens and codes are never logged or printed (the user code is: it is
// what the user types).
package mcpproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/machineclient"
)

// Scopes the proxy can ask for.
const (
	ScopeFull = "mcp"
	ScopeRead = "mcp:read"
)

// DefaultMaxInFlight bounds concurrent requests to the gateway.
const DefaultMaxInFlight = 32

// Options configure Run.
type Options struct {
	// Gateway is the gateway base URL (https, or http on loopback).
	Gateway string
	// Scope is ScopeFull (default) or ScopeRead.
	Scope string
	// ClientName is the registered client name ("mcp-gateway proxy (<host>)").
	ClientName string
	// Version is the CLI version (User-Agent, software_version).
	Version string
	// Dir holds the proxy's state files (~/.config/mcp-gateway/proxy).
	Dir string
	// Secrets keeps the refresh token.
	Secrets machineclient.SecretStore
	// LoginOnly signs in (when needed) and returns without serving stdio.
	LoginOnly bool

	Stdin  io.Reader
	Stdout io.Writer
	// Stderr gets the sign-in instructions and problems.
	Stderr io.Writer
	// Log gets debug lines (never secrets); nil: none.
	Log *slog.Logger
	// HTTP is the client for the gateway; nil: one that never follows
	// redirects.
	HTTP *http.Client
	// Now and Sleep are the clock (nil: real time).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// MaxInFlight bounds concurrent requests (0: DefaultMaxInFlight).
	MaxInFlight int
}

func (o *Options) userAgent() string { return "mcp-gateway-proxy/" + o.Version }

func (o *Options) setDefaults() error {
	if o.Scope == "" {
		o.Scope = ScopeFull
	}
	if o.Scope != ScopeFull && o.Scope != ScopeRead {
		return fmt.Errorf("scope must be %s or %s", ScopeFull, ScopeRead)
	}
	if o.Gateway == "" {
		return errors.New("no gateway: pass --gateway, set $MCP_GATEWAY_URL or gateway in config.yaml")
	}
	gw, err := machineclient.GatewayURL(o.Gateway)
	if err != nil {
		return err
	}
	o.Gateway = gw
	if o.Dir == "" || o.Secrets == nil {
		return errors.New("no credential store")
	}
	if o.ClientName == "" {
		o.ClientName = "mcp-gateway proxy"
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = DefaultMaxInFlight
	}
	if !o.LoginOnly && (o.Stdin == nil || o.Stdout == nil) {
		return errors.New("no stdin or stdout")
	}
	return nil
}

// Run serves the harness on stdin/stdout until stdin closes (after the
// answers in flight are written) or ctx ends. It fails when the sign-in
// is denied or expires.
func Run(ctx context.Context, o Options) error {
	if err := o.setDefaults(); err != nil {
		return err
	}
	oc := &oauthClient{gateway: o.Gateway, userAgent: o.userAgent(), http: o.HTTP}
	ts := newTokenSource(&o, oc, newCredStore(o.Dir, o.Gateway, o.Secrets))
	if o.LoginOnly {
		if _, err := ts.Token(ctx); err != nil {
			return err
		}
		ts.say("signed in to %s (scope %s); the sign-in is kept in the %s store.", o.Gateway, o.Scope, o.Secrets.Name())
		return nil
	}
	b := &bridge{o: &o, ts: ts, out: &lineWriter{w: o.Stdout}}
	return b.serve(ctx)
}

func (b *bridge) serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	authCtx, authCancel := context.WithCancel(ctx)
	defer authCancel()

	fatal := make(chan error, 1)
	report := func(err error) {
		var se *signInError
		if errors.As(err, &se) {
			select {
			case fatal <- err:
			default:
			}
		}
	}
	var wg sync.WaitGroup
	// Sign in at once, so the code shows before the harness asks anything.
	wg.Go(func() {
		if _, err := b.ts.Token(authCtx); err != nil {
			report(err)
			if !errors.Is(err, context.Canceled) {
				var se *signInError
				if !errors.As(err, &se) {
					say(b.o.Stderr, "mcp-gateway proxy: %v\n", err)
				}
			}
		}
	})

	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(b.o.Stdin)
		sc.Buffer(make([]byte, 64<<10), maxMessage)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
		readErr <- sc.Err()
		close(lines)
	}()

	sem := make(chan struct{}, b.o.MaxInFlight)
	finish := func(err error) error {
		wg.Wait()
		select {
		case ferr := <-fatal:
			return ferr
		default:
		}
		return err
	}
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				// stdin closed: stop waiting for a sign-in, deliver the
				// answers in flight, exit.
				authCancel()
				err := <-readErr
				if err != nil {
					err = fmt.Errorf("read stdin: %w", err)
				}
				return finish(err)
			}
			select {
			case sem <- struct{}{}:
			case err := <-fatal:
				cancel()
				return finish(err)
			case <-ctx.Done():
				return finish(nil)
			}
			wg.Go(func() {
				defer func() { <-sem }()
				b.handle(ctx, authCtx, line, report)
			})
		case err := <-fatal:
			cancel()
			wg.Wait()
			return err
		case <-ctx.Done():
			return finish(nil)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func say(w io.Writer, format string, args ...any) {
	if w != nil {
		_, _ = fmt.Fprintf(w, format, args...)
	}
}
