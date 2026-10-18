package tunnelclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	fedclient "github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// fakeStore is a minimal in-memory tunnel.Store.
type fakeStore struct {
	mu sync.Mutex
	n  int
	m  map[string]*store.MCPTunnel
}

func (f *fakeStore) CreateTunnel(_ context.Context, owner, name string, hash []byte) (*store.MCPTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]*store.MCPTunnel{}
	}
	f.n++
	t := &store.MCPTunnel{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", f.n), OwnerUserID: owner, Name: name, TokenHash: hash}
	f.m[t.ID] = t
	cp := *t
	return &cp, nil
}

func (f *fakeStore) RevokeTunnel(_ context.Context, owner, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.m[id]
	if t == nil || t.OwnerUserID != owner || t.RevokedAt != nil {
		return store.ErrNotFound
	}
	t.RevokedAt = &at
	return nil
}

func (f *fakeStore) TunnelByTokenHash(_ context.Context, h []byte) (*store.MCPTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.m {
		if bytes.Equal(t.TokenHash, h) {
			cp := *t
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) Tunnel(_ context.Context, id string) (*store.MCPTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t := f.m[id]; t != nil {
		cp := *t
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) TouchTunnel(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t := f.m[id]; t != nil {
		t.LastSeenAt = &at
		return nil
	}
	return store.ErrNotFound
}

const owner = "11111111-1111-4111-8111-111111111111"

// gateway is the gateway side of an end-to-end test.
type gateway struct {
	svc   *tunnel.Service
	url   string
	id    string
	token string
}

func newGateway(t *testing.T) *gateway {
	t.Helper()
	svc, err := tunnel.NewService(tunnel.Options{Store: &fakeStore{}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(tunnel.ConnectPath, svc.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	tun, raw, err := svc.CreateTunnel(context.Background(), owner, "test")
	if err != nil {
		t.Fatal(err)
	}
	return &gateway{svc: svc, url: srv.URL, id: tun.ID, token: raw}
}

func (g *gateway) waitOnline(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !g.svc.Online(g.id) {
		if time.Now().After(deadline) {
			t.Fatal("tunnel never came online")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// session connects the gateway's federation client to the tunnelled
// server, exactly as the connector will: tunnel-only HTTP client plus the
// http form of the tunnel URL.
func (g *gateway) session(t *testing.T, path string) (*fedclient.Session, error) {
	t.Helper()
	c, err := fedclient.New(fedclient.Options{HTTPClient: g.svc.HTTPClient(nil), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	u, err := tunnel.ClientURL(tunnel.URL(g.id, path))
	if err != nil {
		t.Fatal(err)
	}
	return c.Connect(context.Background(), fedclient.Endpoint{URL: u})
}

// listAndCall asserts the echo tool is listed and callable.
func listAndCall(t *testing.T, s *fedclient.Session) {
	t.Helper()
	ctx := context.Background()
	tools, err := s.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tl := range tools {
		names = append(names, tl.Name)
	}
	if !strings.Contains(strings.Join(names, ","), "echo") {
		t.Fatalf("tools = %v, want echo", names)
	}
	res, err := s.CallTool(ctx, "echo", map[string]any{"text": "hi"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("CallTool result = %+v", res)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(tc.Text, "hi") {
		t.Fatalf("CallTool content = %#v", res.Content[0])
	}
}

type echoIn struct {
	Text string `json:"text"`
}

type echoOut struct {
	Echo string `json:"echo"`
}

// echoServer is a go-sdk MCP server with one echo tool and one slow tool.
func echoServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "echo-server", Version: "1.0.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "echoes text"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, echoOut, error) {
			return nil, echoOut{Echo: in.Text}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "fail", Description: "always fails"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ echoIn) (*mcp.CallToolResult, echoOut, error) {
			return nil, echoOut{}, errors.New("boom")
		})
	return s
}

// TestMain doubles as a stdio MCP server when re-executed by the --stdio
// end-to-end test.
func TestMain(m *testing.M) {
	if os.Getenv("MCP_TUNNEL_TEST_STDIO_SERVER") == "1" {
		if err := echoServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			fmt.Fprintln(os.Stderr, "stdio server:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
