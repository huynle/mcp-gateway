package oauthattack

import (
	"context"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/machineclient"
	"github.com/huynle/mcp-gateway/internal/mcpproxy"
)

// `mcp-gateway proxy` end to end against the whole in-process gateway
// (authorization server, the portal's /activate, /mcp): the official MCP
// Go SDK client is the harness, speaking stdio to the proxy; the proxy
// discovers, registers, shows a code, alice allows it in the browser, and
// the harness lists and calls tools. Disconnect on /harnesses ends the
// sign-in: the next renewal shows a new code and the session continues.

// codeWatcher is the proxy's stderr; it hands out each user code shown.
type codeWatcher struct {
	mu    sync.Mutex
	buf   strings.Builder
	codes chan string
}

var userCodeRE = regexp.MustCompile(`enter ([A-Z]{4}-[A-Z]{4})\n`)

func (c *codeWatcher) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	before := len(userCodeRE.FindAllString(c.buf.String(), -1))
	c.buf.Write(p)
	all := userCodeRE.FindAllStringSubmatch(c.buf.String(), -1)
	for _, m := range all[before:] {
		c.codes <- m[1]
	}
	return len(p), nil
}

func (c *codeWatcher) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *codeWatcher) next(t *testing.T) string {
	t.Helper()
	select {
	case code := <-c.codes:
		return code
	case <-time.After(10 * time.Second):
		t.Fatalf("the proxy showed no code; stderr:\n%s", c.String())
	}
	return ""
}

func TestProxyEndToEnd(t *testing.T) {
	g := newGateway(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	secrets, err := machineclient.NewSecretStore(machineclient.KeyStoreFile, t.TempDir(), mcpproxy.SecretService)
	if err != nil {
		t.Fatal(err)
	}
	stderr := &codeWatcher{codes: make(chan string, 4)}
	toProxyR, toProxyW := io.Pipe()
	fromProxyR, fromProxyW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := mcpproxy.Run(ctx, mcpproxy.Options{
			Gateway: g.base, ClientName: "mcp-gateway proxy (e2e-host)", Version: "e2e",
			Dir: t.TempDir(), Secrets: secrets,
			Stdin: toProxyR, Stdout: fromProxyW, Stderr: stderr,
			// The gateway's clock: each poll interval passes on it at once.
			Now: g.clock.Now,
			Sleep: func(ctx context.Context, d time.Duration) error {
				g.clock.Advance(d)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(10 * time.Millisecond):
					return nil
				}
			},
		})
		_ = fromProxyW.Close()
		done <- err
	}()

	// The harness connects; initialize waits for the sign-in.
	type connected struct {
		cs  *sdk.ClientSession
		err error
	}
	conn := make(chan connected, 1)
	go func() {
		client := sdk.NewClient(&sdk.Implementation{Name: "e2e-harness", Version: "1"}, nil)
		cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: fromProxyR, Writer: toProxyW}, nil)
		conn <- connected{cs, err}
	}()

	br := g.browser(t, true)
	g.allow(t, br, stderr.next(t))
	var cs *sdk.ClientSession
	select {
	case c := <-conn:
		if c.err != nil {
			t.Fatalf("connect: %v\nstderr:\n%s", c.err, stderr.String())
		}
		cs = c.cs
	case <-time.After(10 * time.Second):
		t.Fatalf("initialize did not complete; stderr:\n%s", stderr.String())
	}

	listAndCall := func(when string) {
		t.Helper()
		res, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("%s: tools/list: %v\nstderr:\n%s", when, err, stderr.String())
		}
		var names []string
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		if !strings.Contains(strings.Join(names, ","), "fake.list_accounts") {
			t.Fatalf("%s: tools %v", when, names)
		}
		call, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_accounts"})
		if err != nil || call.IsError {
			t.Fatalf("%s: tools/call: %v %+v", when, err, call)
		}
	}
	listAndCall("after sign-in")

	// The grant is the proxy's own client, approved by alice.
	red := wantAudit(t, g, "oauth_device_redeemed", "allow", 1)[0]
	if red.UserID != g.alice || red.ResourceIdentity["client_name"] != "mcp-gateway proxy (e2e-host)" {
		t.Errorf("redeemed event = %+v", red)
	}

	// An hour later the access token is renewed with the refresh token.
	g.clock.Advance(time.Hour)
	listAndCall("after refresh")
	if n := len(g.logs.Events("authserver.tokens_issued")); n < 2 {
		t.Errorf("tokens issued %d times, want a refresh", n)
	}

	// Disconnect on /harnesses: the next renewal signs in again.
	if err := g.authSvc.RevokeHarness(t.Context(), g.alice, red.TokenID); err != nil {
		t.Fatal(err)
	}
	g.clock.Advance(time.Hour)
	listed := make(chan struct{})
	go func() {
		defer close(listed)
		listAndCall("after disconnect")
	}()
	g.allow(t, br, stderr.next(t))
	select {
	case <-listed:
	case <-time.After(10 * time.Second):
		t.Fatalf("no answer after signing in again; stderr:\n%s", stderr.String())
	}
	if regs := len(g.logs.Events("authserver.client_registered")); regs != 1 {
		t.Errorf("registered %d clients; the proxy must keep its client", regs)
	}

	// The harness closes stdin: the proxy exits cleanly.
	if err := cs.Close(); err != nil {
		t.Logf("close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the proxy did not exit after stdin closed")
	}
	out := stderr.String()
	for _, secret := range []string{"gwr_", "gwd_", "eyJ"} {
		if strings.Contains(out, secret) {
			t.Fatalf("stderr shows a token (%s…):\n%s", secret, out)
		}
	}
}
