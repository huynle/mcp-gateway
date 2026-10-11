package portal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

type headerAuth struct{ token string }

func (a headerAuth) Authorize(_ context.Context, r *http.Request) error {
	r.Header.Set("Authorization", "Bearer "+a.token)
	return nil
}
func (headerAuth) Unauthorized(context.Context) error { return auth.ErrNeedsReconnect }

type fakeCredentials struct {
	err   error
	calls []string
}

func (f *fakeCredentials) ForUser(_ context.Context, s *store.MCPServer, userID string) (auth.Authorizer, error) {
	f.calls = append(f.calls, userID+"/"+s.ID)
	if f.err != nil {
		return nil, f.err
	}
	return headerAuth{token: "tok-" + userID}, nil
}

type fakeDialer struct {
	err        error
	authorized []string
	base       *http.Client
}

func (f *fakeDialer) Authorize(_ context.Context, owner, id string) error {
	f.authorized = append(f.authorized, owner+"/"+id)
	return f.err
}

func (f *fakeDialer) HTTPClient(base *http.Client) *http.Client { f.base = base; return base }

// upstream is a go-sdk server recording the headers of every request.
func upstream(t *testing.T) (*httptest.Server, func() []http.Header) {
	s := mcp.NewServer(&mcp.Implementation{Name: "up", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "ping", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []http.Header { mu.Lock(); defer mu.Unlock(); return seen }
}

func TestClientFactoryOpensSessionWithCredentialAndStaticHeaders(t *testing.T) {
	srv, seen := upstream(t)
	creds := &fakeCredentials{}
	f, err := NewClientFactory(FactoryOptions{Credentials: creds, Tunnels: &fakeDialer{}, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	hc, _ := json.Marshal(headerConfig{Static: map[string]string{"X-Team": "core"}})
	server := &store.MCPServer{ID: "s1", URL: srv.URL + "/mcp", Transport: store.MCPTransportAuto, OwnerUserID: bob, HeaderConfig: hc}
	sess, err := f.Open(t.Context(), server, alice)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	tools, err := sess.ListTools(t.Context())
	if err != nil || len(tools) != 1 || tools[0].Name != "ping" {
		t.Fatalf("tools %v %v", tools, err)
	}
	if err := sess.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if len(creds.calls) != 1 || creds.calls[0] != alice+"/s1" {
		t.Errorf("credential calls %v", creds.calls)
	}
	h := seen()
	if len(h) == 0 || h[0].Get("Authorization") != "Bearer tok-"+alice || h[0].Get("X-Team") != "core" {
		t.Errorf("upstream saw %v", h)
	}
}

func TestClientFactoryErrors(t *testing.T) {
	if _, err := NewClientFactory(FactoryOptions{}); err == nil {
		t.Error("missing options accepted")
	}
	srv, _ := upstream(t)
	creds := &fakeCredentials{err: auth.ErrNotConnected}
	dialer := &fakeDialer{err: tunnel.ErrForbidden}
	f, err := NewClientFactory(FactoryOptions{Credentials: creds, Tunnels: dialer, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	server := &store.MCPServer{ID: "s1", URL: srv.URL, OwnerUserID: alice}
	if _, err := f.Open(t.Context(), server, alice); !errors.Is(err, auth.ErrNotConnected) {
		t.Errorf("not connected: %v", err)
	}
	creds.err = nil
	tid := "5e000000-0000-4000-8000-0000000000aa"
	server.URL = tunnel.URL(tid, "/mcp")
	if _, err := f.Open(t.Context(), server, bob); !errors.Is(err, tunnel.ErrForbidden) {
		t.Errorf("tunnel not authorized: %v", err)
	}
	if len(dialer.authorized) != 1 || dialer.authorized[0] != alice+"/"+tid {
		t.Errorf("authorized %v (must be the server owner's tunnel)", dialer.authorized)
	}
}
