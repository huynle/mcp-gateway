package client

import (
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// methodLog records the HTTP methods a server saw.
type methodLog struct {
	mu      sync.Mutex
	methods []string
}

func (m *methodLog) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.methods = append(m.methods, r.Method)
		m.mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

func (m *methodLog) gets() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.methods {
		if x == http.MethodGet {
			n++
		}
	}
	return n
}

func exercise(t *testing.T, s *Session) {
	t.Helper()
	ctx := ctxT(t)
	tools, err := s.ListTools(ctx)
	if err != nil || len(tools) != 2 {
		t.Fatalf("ListTools = %d tools, %v", len(tools), err)
	}
	res, err := s.CallTool(ctx, "echo", map[string]any{"text": "x"})
	if err != nil || res.IsError {
		t.Fatalf("CallTool = %+v, %v", res, err)
	}
	if rr, err := s.ReadResource(ctx, "file:///readme"); err != nil || rr.Contents[0].Text != "hello" {
		t.Fatalf("ReadResource = %+v, %v", rr, err)
	}
}

func TestSSEExplicit(t *testing.T) {
	ts := sseServer(t, fullServer(0, 0), nil)
	s := connect(t, newTestClient(t, nil), Endpoint{URL: ts.URL + "/sse", Transport: TransportSSE})
	if s.Transport() != TransportSSE {
		t.Errorf("Transport() = %q", s.Transport())
	}
	if s.ServerInfo() == nil || s.ServerInfo().Name != "upstream" {
		t.Errorf("ServerInfo() = %+v", s.ServerInfo())
	}
	exercise(t, s)
}

func TestAutoPrefersStreamable(t *testing.T) {
	var log methodLog
	ts := streamableServer(t, fullServer(0, 0), log.wrap)
	for _, tr := range []Transport{TransportAuto, ""} {
		s := connect(t, newTestClient(t, nil), Endpoint{URL: ts.URL + "/mcp", Transport: tr})
		if s.Transport() != TransportStreamableHTTP {
			t.Errorf("Transport(%q) = %q, want streamable_http", tr, s.Transport())
		}
		exercise(t, s)
	}
	if n := log.gets(); n != 0 {
		t.Errorf("auto made %d GET requests against a streamable server", n)
	}
}

func TestAutoFallsBackToSSE(t *testing.T) {
	var log methodLog
	ts := sseServer(t, fullServer(0, 0), log.wrap)
	s := connect(t, newTestClient(t, nil), Endpoint{URL: ts.URL + "/sse", Transport: TransportAuto})
	if s.Transport() != TransportSSE {
		t.Fatalf("Transport() = %q, want sse", s.Transport())
	}
	exercise(t, s)
	if log.gets() != 1 {
		t.Errorf("GET count = %d, want 1 (the SSE stream)", log.gets())
	}
}

func TestAutoFallsBackOn404And405(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		sse := mcpSSEHandler(fullServer(0, 0))
		ts := sseServer(t, nil, func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.RawQuery == "" {
					http.Error(w, "nope", status)
					return
				}
				sse.ServeHTTP(w, r)
			})
		})
		s := connect(t, newTestClient(t, nil), Endpoint{URL: ts.URL + "/sse"})
		if s.Transport() != TransportSSE {
			t.Errorf("status %d: Transport() = %q, want sse", status, s.Transport())
		}
	}
}

// The legacy GET stream must outlive the handshake timeout: only the
// handshake and each call are bounded, not the session.
func TestSSESessionOutlivesHandshakeTimeout(t *testing.T) {
	ts := sseServer(t, fullServer(0, 0), nil)
	c := newTestClient(t, func(o *Options) { o.Timeout = 300 * time.Millisecond })
	s := connect(t, c, Endpoint{URL: ts.URL + "/sse", Transport: TransportSSE})
	time.Sleep(700 * time.Millisecond)
	if _, err := s.ListTools(ctxT(t)); err != nil {
		t.Fatalf("ListTools after the handshake timeout: %v", err)
	}
}

func TestConnectRejectsBadEndpoint(t *testing.T) {
	c := newTestClient(t, nil)
	for _, ep := range []Endpoint{
		{URL: "https://example.com/mcp", Transport: "websocket"},
		{URL: "://bad"},
		{URL: ""},
		{URL: "ftp://example.com/mcp"},
		{URL: "https://example.com/mcp", Headers: map[string]string{"Bad Name": "x"}},
		{URL: "https://example.com/mcp", Headers: map[string]string{"X-Ok": "line\r\nbreak"}},
		{URL: "https://example.com/mcp", Headers: map[string]string{"Mcp-Session-Id": "x"}},
		{URL: "https://example.com/mcp", Headers: map[string]string{"host": "x"}},
	} {
		if s, err := c.Connect(ctxT(t), ep); err == nil {
			_ = s.Close()
			t.Errorf("Connect(%+v) succeeded", ep)
		} else if !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("Connect(%+v) = %v, want ErrInvalidEndpoint", ep, err)
		}
	}
}
