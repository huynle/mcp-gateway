package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/netguard"
)

// guardClient returns an *http.Client from the real netguard with the
// httptest servers' loopback address allow-listed.
func guardClient(t *testing.T) *http.Client {
	t.Helper()
	allow, err := netguard.NewStaticAllowList("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return netguard.New(netguard.Options{AllowList: allow, Timeout: 10 * time.Second}).Client()
}

// newTestClient builds a Client over the allow-listed guard; mutate tweaks
// the options before New.
func newTestClient(t *testing.T, mutate func(*Options)) *Client {
	t.Helper()
	o := Options{
		HTTPClient: guardClient(t),
		Timeout:    5 * time.Second,
		ClientName: "gateway-test",
		Log:        slog.New(slog.DiscardHandler),
	}
	if mutate != nil {
		mutate(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

type echoIn struct {
	Text string `json:"text"`
}

type echoOut struct {
	Echo string `json:"echo"`
}

// fullServer is a go-sdk server with tools, resources, templates and
// prompts. n controls how many of each list item exist beyond the fixed
// ones; pageSize 0 means the SDK default.
func fullServer(n, pageSize int) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "upstream", Version: "1.2.3"},
		&mcp.ServerOptions{Instructions: "use echo", PageSize: pageSize})
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "echoes"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, echoOut, error) {
			return nil, echoOut{Echo: in.Text}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "fail", Description: "always fails"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ echoIn) (*mcp.CallToolResult, echoOut, error) {
			return nil, echoOut{}, errors.New("boom from upstream")
		})
	s.AddResource(&mcp.Resource{URI: "file:///readme", Name: "readme", MIMEType: "text/plain"},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "hello"}}}, nil
		})
	s.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "file:///docs/{name}", Name: "docs"},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "doc"}}}, nil
		})
	s.AddPrompt(&mcp.Prompt{Name: "greet", Arguments: []*mcp.PromptArgument{{Name: "who", Required: true}}},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "hi " + req.Params.Arguments["who"]}}}}, nil
		})
	for i := range n {
		mcp.AddTool(s, &mcp.Tool{Name: fmt.Sprintf("tool_%04d", i)},
			func(_ context.Context, _ *mcp.CallToolRequest, _ echoIn) (*mcp.CallToolResult, echoOut, error) {
				return nil, echoOut{}, nil
			})
		uri := fmt.Sprintf("file:///r/%04d", i)
		s.AddResource(&mcp.Resource{URI: uri, Name: uri},
			func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return &mcp.ReadResourceResult{}, nil
			})
		s.AddPrompt(&mcp.Prompt{Name: fmt.Sprintf("prompt_%04d", i)},
			func(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				return &mcp.GetPromptResult{}, nil
			})
	}
	return s
}

// streamableServer serves s over Streamable HTTP at /mcp.
func streamableServer(t *testing.T, s *mcp.Server, wrap func(http.Handler) http.Handler) *httptest.Server {
	t.Helper()
	var h http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	if wrap != nil {
		h = wrap(h)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// sseServer serves s over the legacy 2024-11-05 HTTP+SSE transport at /sse.
func sseServer(t *testing.T, s *mcp.Server, wrap func(http.Handler) http.Handler) *httptest.Server {
	t.Helper()
	var h http.Handler = mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return s }, nil)
	if wrap != nil {
		h = wrap(h)
	}
	mux := http.NewServeMux()
	mux.Handle("/sse", h)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func connect(t *testing.T, c *Client, ep Endpoint) *Session {
	t.Helper()
	s, err := c.Connect(ctxT(t), ep)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// wantClass asserts err is an *Error of class want.
func wantClass(t *testing.T, err error, want Class) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want class %s", want)
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %T %v, want *Error of class %s", err, err, want)
	}
	if e.Class != want {
		t.Fatalf("class = %s (%v), want %s", e.Class, err, want)
	}
	return e
}

// assertNoLeak fails when an error message contains any of the secrets.
func assertNoLeak(t *testing.T, err error, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && strings.Contains(err.Error(), s) {
			t.Fatalf("error message %q leaks %q", err.Error(), s)
		}
	}
}

func mcpSSEHandler(s *mcp.Server) http.Handler {
	return mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return s }, nil)
}
