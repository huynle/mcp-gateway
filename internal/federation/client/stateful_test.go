package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Protocol versions used by the go-sdk v1.8.0.
const (
	pvModern = "2026-07-28" // SEP-2575, stateless-only on Streamable HTTP
	pvLegacy = "2025-11-25"
)

// statelessServer serves s over Streamable HTTP at /mcp with
// StreamableHTTPOptions{Stateless: true} (the only mode where a go-sdk
// server accepts 2026-07-28).
func statelessServer(t *testing.T, s *mcp.Server) *httptest.Server {
	t.Helper()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true})
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// twoSessions opens two sequential sessions to ep with ctx, and in each
// lists tools and calls echo. It returns the negotiated versions.
func twoSessions(ctx context.Context, c *Client, ep Endpoint) ([]string, error) {
	var versions []string
	for i := range 2 {
		s, err := c.Connect(ctx, ep)
		if err != nil {
			return versions, fmt.Errorf("session %d: connect: %w", i+1, err)
		}
		if _, err := s.ListTools(ctx); err != nil {
			_ = s.Close()
			return versions, fmt.Errorf("session %d: list: %w", i+1, err)
		}
		res, err := s.CallTool(ctx, "echo", map[string]any{"text": "hi"})
		_ = s.Close()
		if err != nil {
			return versions, fmt.Errorf("session %d: call: %w", i+1, err)
		}
		if res.IsError {
			return versions, fmt.Errorf("session %d: call: tool error", i+1)
		}
		versions = append(versions, s.ProtocolVersion())
	}
	return versions, nil
}

// A stateful go-sdk upstream (default StreamableHTTPOptions) serves two
// sequential sessions with list + call each.
func TestStatefulUpstreamTwoSessions(t *testing.T) {
	ts := streamableServer(t, fullServer(0, 0), nil)
	vs, err := twoSessions(ctxT(t), newTestClient(t, nil), Endpoint{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v != pvLegacy {
			t.Errorf("ProtocolVersion() = %q, want %q", v, pvLegacy)
		}
	}
}

// relay is the gateway's situation: a go-sdk MCP server (the gateway's
// /mcp) whose tool handler connects to an upstream with the inbound
// request's context. The go-sdk server stores the inbound
// Mcp-Protocol-Version in that context under the same key its client
// transport reads, so the client must not inherit it.
func relay(t *testing.T, c *Client, upstream Endpoint, frontVersion string) (string, error) {
	t.Helper()
	front := mcp.NewServer(&mcp.Implementation{Name: "gateway", Version: "0"}, nil)
	mcp.AddTool(front, &mcp.Tool{Name: "relay"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
			vs, err := twoSessions(ctx, c, upstream)
			if err != nil {
				return nil, struct{}{}, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(vs, ",")}}}, struct{}{}, nil
		})
	fts := statelessServer(t, front)

	cl := mcp.NewClient(&mcp.Implementation{Name: "downstream", Version: "0"}, nil)
	cs, err := cl.Connect(ctxT(t), &mcp.StreamableClientTransport{Endpoint: fts.URL + "/mcp", DisableStandaloneSSE: true},
		&mcp.ClientSessionOptions{ProtocolVersion: frontVersion})
	if err != nil {
		t.Fatalf("downstream connect: %v", err)
	}
	defer func() { _ = cs.Close() }()
	if got := cs.InitializeResult().ProtocolVersion; got != frontVersion {
		t.Fatalf("downstream negotiated %q, want %q", got, frontVersion)
	}
	res, err := cs.CallTool(ctxT(t), &mcp.CallToolParams{Name: "relay", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("relay call: %v", err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if res.IsError {
		return "", fmt.Errorf("%s", text)
	}
	return text, nil
}

// Regression (quirk 91d7smmg): called from a go-sdk server handler whose
// downstream client speaks 2026-07-28, the client sent
// Mcp-Protocol-Version: 2026-07-28 on an initialize asking 2025-11-25 and
// a stateful upstream answered 400 -32022.
func TestStatefulUpstreamFromServerHandler(t *testing.T) {
	up := streamableServer(t, fullServer(0, 0), nil)
	got, err := relay(t, newTestClient(t, nil), Endpoint{URL: up.URL + "/mcp"}, pvModern)
	if err != nil {
		t.Fatal(err)
	}
	if want := pvLegacy + "," + pvLegacy; got != want {
		t.Errorf("versions = %q, want %q", got, want)
	}
}

// An upstream that supports 2026-07-28 still negotiates it, whatever
// version the inbound request carried.
func TestModernUpstreamFromServerHandler(t *testing.T) {
	up := statelessServer(t, fullServer(0, 0))
	for _, front := range []string{pvModern, pvLegacy} {
		got, err := relay(t, newTestClient(t, nil), Endpoint{URL: up.URL + "/mcp"}, front)
		if err != nil {
			t.Fatalf("front %s: %v", front, err)
		}
		if want := pvModern + "," + pvModern; got != want {
			t.Errorf("front %s: versions = %q, want %q", front, got, want)
		}
	}
}

// A Streamable HTTP server rejecting the protocol version (400 with
// JSON-RPC -32022) is not a legacy server: auto must not fall back to
// HTTP+SSE, and the error keeps the code.
func TestAutoNoFallbackOnUnsupportedVersion(t *testing.T) {
	var log methodLog
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "GET requires an Mcp-Session-Id header", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32022,"message":"protocol version not supported","data":{"supported":["2024-11-05"]}}}`, req.ID)
	})
	ts := streamableServer(t, nil, func(http.Handler) http.Handler { return log.wrap(h) })
	_, err := newTestClient(t, nil).Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp"})
	e := wantClass(t, err, ClassProtocol)
	if e.Status != http.StatusBadRequest || e.RPCCode != -32022 {
		t.Errorf("err = %v (status %d, code %d), want HTTP 400 with JSON-RPC -32022", err, e.Status, e.RPCCode)
	}
	if n := log.gets(); n != 0 {
		t.Errorf("auto made %d GET requests (fell back to legacy SSE) on a version error", n)
	}
}

type gatewayKey struct{}

// withoutSDKValues hides only go-sdk keys: the gateway's own values (the
// Authorizer reads the user from them), deadlines and cancellation pass.
func TestWithoutSDKValuesKeepsOthers(t *testing.T) {
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), gatewayKey{}, "alice"))
	ctx := withoutSDKValues(parent)
	if ctx.Value(gatewayKey{}) != "alice" {
		t.Error("gateway value hidden")
	}
	if _, ok := ctx.Deadline(); ok {
		t.Error("unexpected deadline")
	}
	cancel()
	if ctx.Err() == nil {
		t.Error("cancellation not propagated")
	}
	if !isSDKKey(&mcp.Tool{}) || !isSDKKey(mcp.Implementation{}) || isSDKKey(gatewayKey{}) || isSDKKey(nil) || isSDKKey("x") {
		t.Error("isSDKKey misclassifies")
	}
}
