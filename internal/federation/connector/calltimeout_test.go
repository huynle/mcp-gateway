package connector

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/netguard"
	"github.com/huynle/mcp-gateway/internal/store"
)

const slowSrvID = "44444444-4444-4444-8444-444444444444"

// slowRender is an upstream like yoto-mcp's generate_cover: one tool that
// takes delay to answer, served with JSON responses so not even the
// response headers arrive before it is done (the case netguard's and the
// tunnel's header timeouts would cut).
func slowRender(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	s := sdk.NewServer(&sdk.Implementation{Name: "covers", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "render", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *sdk.CallToolRequest, in searchIn) (*sdk.CallToolResult, searchOut, error) {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, searchOut{}, ctx.Err()
			}
			return nil, searchOut{Hits: []string{"cover for " + in.Q}}, nil
		})
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// slowManager registers the slow upstream as server "covers" on a
// Manager with the given timeouts, over a netguard whose header timeout
// is derived the way Wire derives it (unless header > 0 overrides it).
func slowManager(t *testing.T, delay, timeout, callTimeout, header time.Duration) *fixture {
	t.Helper()
	srv := slowRender(t, delay)
	allow, err := netguard.NewStaticAllowList("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Discovery as the review would run it (default timeouts: fast here).
	c, err := client.New(client.Options{HTTPClient: netguard.New(netguard.Options{AllowList: allow}).Client()})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := c.Connect(t.Context(), client.Endpoint{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.Discover(t.Context(), cs)
	_ = cs.Close()
	if err != nil {
		t.Fatal(err)
	}

	f := &fixture{reg: connectors.NewRegistry(), st: newFakeStore(), creds: &fakeCreds{errs: map[string]error{}}, tunnels: &fakeTunnels{},
		perms: &fakePerms{denied: map[string]bool{}}, pol: &fakePolicy{denied: map[string]bool{}}}
	f.st.put(store.MCPServer{
		ID: slowSrvID, Name: "covers", URL: srv.URL, OwnerUserID: alice, Audience: store.MCPAudiencePrivate,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthAPIKey, Status: store.MCPServerActive,
	})
	f.st.visible[alice] = []string{slowSrvID}
	f.snaps = &fakeSnaps{st: f.st, records: map[string]*snapshot.Record{slowSrvID: {
		ID: "snap-covers", ServerID: slowSrvID, Version: 1, Status: store.MCPSnapshotApproved, Snapshot: snap,
		Review: snapshot.Review{"render": {Enabled: true, Kind: snapshot.KindRead}},
	}}}
	if header <= 0 {
		header = upstreamHeaderTimeout(timeout, callTimeout)
	}
	// The guard's whole-request Timeout stays short, like production's
	// default: the federation client drops it and bounds each operation
	// with its context.
	guard := netguard.New(netguard.Options{AllowList: allow, Timeout: timeout, ResponseHeaderTimeout: header})
	f.m, err = New(Options{
		Registry: f.reg, Store: f.st, Snapshots: f.snaps, Credentials: f.creds, Tunnels: f.tunnels, Permissions: f.perms,
		HTTPClient: guard.Client(), BaseURL: "https://gw.example", Timeout: timeout, CallTimeout: callTimeout,
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.Load(t.Context()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f
}

const (
	shortOp   = 300 * time.Millisecond
	slowTool  = 900 * time.Millisecond
	longCalls = 5 * time.Second
)

func TestManagerCallTimeoutDefaultCutsSlowTool(t *testing.T) {
	f := slowManager(t, slowTool, shortOp, 0, 0)
	_, err := f.call(t, alice, "covers.render", map[string]any{"q": "dinosaurs"})
	if toolErrClass(err) != "handler:upstream_timeout" {
		t.Fatalf("err = %v (%s), want upstream_timeout: without CallTimeout tools/call keeps Timeout", err, toolErrClass(err))
	}
}

func TestManagerCallTimeoutRaisedLetsSlowToolFinish(t *testing.T) {
	f := slowManager(t, slowTool, shortOp, longCalls, 0)
	res, err := f.call(t, alice, "covers.render", map[string]any{"q": "dinosaurs"})
	if err != nil {
		t.Fatalf("slow tool within CallTimeout: %v (%s)", err, toolErrClass(err))
	}
	out, ok := res.Content.(*sdk.CallToolResult)
	if !ok || out.IsError {
		t.Fatalf("result = %#v, want a successful CallToolResult", res.Content)
	}
}

// A guard whose header timeout was not raised still cuts the call: the
// derived header timeout is what makes the setting reach netguard.
func TestManagerCallTimeoutNeedsRaisedHeaderTimeout(t *testing.T) {
	f := slowManager(t, slowTool, shortOp, longCalls, shortOp)
	_, err := f.call(t, alice, "covers.render", map[string]any{"q": "dinosaurs"})
	if c := toolErrClass(err); c != "handler:upstream_timeout" {
		t.Fatalf("err = %v (%s), want upstream_timeout from the short header timeout", err, c)
	}
}

func TestUpstreamHeaderTimeout(t *testing.T) {
	for _, tc := range []struct {
		timeout, call, want time.Duration
	}{
		{0, 0, client.DefaultTimeout},
		{0, 5 * time.Minute, 5 * time.Minute},
		{0, 10 * time.Second, client.DefaultTimeout},
		{time.Minute, 0, time.Minute},
		{10 * time.Second, 2 * time.Minute, 2 * time.Minute},
	} {
		if got := upstreamHeaderTimeout(tc.timeout, tc.call); got != tc.want {
			t.Errorf("upstreamHeaderTimeout(%v, %v) = %v, want %v", tc.timeout, tc.call, got, tc.want)
		}
	}
}
