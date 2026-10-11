package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// rawServer is a hand-written Streamable HTTP JSON-RPC server for hostile
// behaviour. handle returns the HTTP response for a call; returning false
// falls back to the defaults (initialize succeeds, server/discover and
// everything else are "method not found").
func rawServer(t *testing.T, handle func(w http.ResponseWriter, method string, id json.RawMessage, params json.RawMessage) bool) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "no", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(body, &msg); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if msg.ID == nil { // notification
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if handle != nil && handle(w, msg.Method, msg.ID, msg.Params) {
			return
		}
		switch msg.Method {
		case "initialize":
			writeResult(w, msg.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}},
				"serverInfo":      map[string]any{"name": "raw", "version": "0"},
			})
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found: internal detail"}}`, msg.ID)
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "/mcp"
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	b, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, id, b)
}

func TestPaginationAcrossPages(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  func(*testing.T) string
	}{
		{"streamable", func(t *testing.T) string { return streamableServer(t, fullServer(25, 4), nil).URL + "/mcp" }},
		{"sse", func(t *testing.T) string { return sseServer(t, fullServer(25, 4), nil).URL + "/sse" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := connect(t, newTestClient(t, nil), Endpoint{URL: tc.url(t)})
			ctx := ctxT(t)
			tools, err := s.ListTools(ctx)
			if err != nil || len(tools) != 27 {
				t.Fatalf("ListTools = %d, %v; want 27", len(tools), err)
			}
			seen := map[string]bool{}
			for _, x := range tools {
				if seen[x.Name] {
					t.Fatalf("duplicate tool %s", x.Name)
				}
				seen[x.Name] = true
			}
			if rs, err := s.ListResources(ctx); err != nil || len(rs) != 26 {
				t.Fatalf("ListResources = %d, %v; want 26", len(rs), err)
			}
			if ps, err := s.ListPrompts(ctx); err != nil || len(ps) != 26 {
				t.Fatalf("ListPrompts = %d, %v; want 26", len(ps), err)
			}
		})
	}
}

func TestListCap(t *testing.T) {
	t.Run("default cap 1000", func(t *testing.T) {
		ts := streamableServer(t, toolsServer(2500), nil)
		s := connect(t, newTestClient(t, nil), Endpoint{URL: ts.URL + "/mcp"})
		tools, err := s.ListTools(ctxT(t))
		e := wantClass(t, err, ClassTooLarge)
		if tools != nil || e.Op != "tools/list" {
			t.Errorf("tools = %d, op = %q", len(tools), e.Op)
		}
	})
	t.Run("configured cap stops paging", func(t *testing.T) {
		ts := streamableServer(t, fullServer(40, 5), nil)
		s := connect(t, newTestClient(t, func(o *Options) { o.MaxListItems = 10 }), Endpoint{URL: ts.URL + "/mcp"})
		_, err := s.ListResources(ctxT(t))
		_ = wantClass(t, err, ClassTooLarge)
		if tools, err := s.ListTools(ctxT(t)); err == nil {
			t.Errorf("ListTools of 42 tools with cap 10 = %d tools", len(tools))
		}
	})
}

func TestHostilePagination(t *testing.T) {
	t.Run("repeating cursor", func(t *testing.T) {
		url := rawServer(t, func(w http.ResponseWriter, method string, id, _ json.RawMessage) bool {
			if method != "tools/list" {
				return false
			}
			writeResult(w, id, map[string]any{"tools": []any{}, "nextCursor": "again"})
			return true
		})
		s := connect(t, newTestClient(t, nil), Endpoint{URL: url, Transport: TransportStreamableHTTP})
		_, err := s.ListTools(ctxT(t))
		_ = wantClass(t, err, ClassProtocol)
	})
	t.Run("endless empty pages", func(t *testing.T) {
		var n atomic.Int64
		url := rawServer(t, func(w http.ResponseWriter, method string, id, _ json.RawMessage) bool {
			if method != "prompts/list" {
				return false
			}
			writeResult(w, id, map[string]any{"prompts": []any{}, "nextCursor": fmt.Sprintf("c%d", n.Add(1))})
			return true
		})
		c := newTestClient(t, func(o *Options) { o.MaxListItems = 20 })
		s := connect(t, c, Endpoint{URL: url, Transport: TransportStreamableHTTP})
		_, err := s.ListPrompts(ctxT(t))
		_ = wantClass(t, err, ClassTooLarge)
	})
}

// toolsServer has n trivial tools and nothing else.
func toolsServer(n int) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "many", Version: "1"}, nil)
	h := func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	}
	schema := json.RawMessage(`{"type":"object"}`)
	for i := range n {
		s.AddTool(&mcp.Tool{Name: fmt.Sprintf("t%05d", i), InputSchema: schema}, h)
	}
	return s
}

func bigServer(size int) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "big", Version: "1"}, nil)
	big := strings.Repeat("A", size)
	s.AddTool(&mcp.Tool{Name: "big", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: big}}}, nil
		})
	s.AddTool(&mcp.Tool{Name: "small", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
		})
	s.AddResource(&mcp.Resource{URI: "file:///big", Name: "big"},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: big}}}, nil
		})
	return s
}

func TestResultSizeBound(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  func(*testing.T) string
	}{
		{"streamable", func(t *testing.T) string { return streamableServer(t, bigServer(1<<20), nil).URL + "/mcp" }},
		{"sse", func(t *testing.T) string { return sseServer(t, bigServer(1<<20), nil).URL + "/sse" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := tc.url(t)
			c := newTestClient(t, func(o *Options) { o.MaxResultBytes = 128 << 10 })
			s := connect(t, c, Endpoint{URL: url})
			if res, err := s.CallTool(ctxT(t), "small", nil); err != nil || res.IsError {
				t.Fatalf("small call = %+v, %v", res, err)
			}
			_, err := s.CallTool(ctxT(t), "big", nil)
			_ = wantClass(t, err, ClassTooLarge)

			s2 := connect(t, c, Endpoint{URL: url})
			_, err = s2.ReadResource(ctxT(t), "file:///big")
			_ = wantClass(t, err, ClassTooLarge)
		})
	}
}

// slowServer's tool blocks until release is closed (the streamable server
// does not cancel handlers when the client gives up). Tests pass
// t.Context().Done(), which is closed before cleanups (server Close) run.
func slowServer(release <-chan struct{}) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "slow", Version: "1"}, nil)
	s.AddTool(&mcp.Tool{Name: "slow", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			select {
			case <-ctx.Done():
			case <-release:
			}
			return &mcp.CallToolResult{}, nil
		})
	return s
}

func TestSlowCallTimesOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  func(*testing.T) string
	}{
		{"streamable", func(t *testing.T) string {
			return streamableServer(t, slowServer(t.Context().Done()), nil).URL + "/mcp"
		}},
		{"sse", func(t *testing.T) string { return sseServer(t, slowServer(t.Context().Done()), nil).URL + "/sse" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(o *Options) { o.Timeout = 400 * time.Millisecond })
			s := connect(t, c, Endpoint{URL: tc.url(t)})
			start := time.Now()
			_, err := s.CallTool(ctxT(t), "slow", nil)
			_ = wantClass(t, err, ClassTimeout)
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("timeout took %v", d)
			}
		})
	}
}

func TestSlowHandshakeTimesOut(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	for _, tr := range []Transport{TransportAuto, TransportSSE} {
		c := newTestClient(t, func(o *Options) { o.Timeout = 300 * time.Millisecond })
		start := time.Now()
		_, err := c.Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp", Transport: tr})
		_ = wantClass(t, err, ClassTimeout)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: timeout took %v", tr, d)
		}
	}
}

func TestMalformedJSONIsProtocolError(t *testing.T) {
	t.Run("handshake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{nope secret-body`)
		}))
		t.Cleanup(ts.Close)
		_, err := newTestClient(t, nil).Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp", Transport: TransportStreamableHTTP})
		_ = wantClass(t, err, ClassProtocol)
		assertNoLeak(t, err, "secret-body")
	})
	t.Run("list", func(t *testing.T) {
		url := rawServer(t, func(w http.ResponseWriter, method string, _, _ json.RawMessage) bool {
			if method != "tools/list" {
				return false
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0",garbage`)
			return true
		})
		s := connect(t, newTestClient(t, nil), Endpoint{URL: url, Transport: TransportStreamableHTTP})
		_, err := s.ListTools(ctxT(t))
		_ = wantClass(t, err, ClassProtocol)
	})
	t.Run("html", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html>login</html>")
		}))
		t.Cleanup(ts.Close)
		_, err := newTestClient(t, nil).Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp"})
		_ = wantClass(t, err, ClassProtocol)
	})
}

func TestJSONRPCErrors(t *testing.T) {
	ts := streamableServer(t, fullServer(0, 0), nil)
	s := connect(t, newTestClient(t, nil), Endpoint{URL: ts.URL + "/mcp"})
	_, err := s.CallTool(ctxT(t), "no_such_tool", nil)
	e := wantClass(t, err, ClassToolError)
	if e.RPCCode == 0 {
		t.Error("RPCCode not set")
	}
	assertNoLeak(t, err, "no_such_tool")

	_, err = s.ReadResource(ctxT(t), "file:///missing")
	e = wantClass(t, err, ClassProtocol)
	if e.RPCCode == 0 {
		t.Error("RPCCode not set")
	}
	// The session survives JSON-RPC errors.
	if _, err := s.ListTools(ctxT(t)); err != nil {
		t.Fatalf("ListTools after errors: %v", err)
	}
}
