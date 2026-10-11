package client

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	apiKey    = "s3cret-key"
	challenge = `Bearer realm="upstream", resource_metadata="https://upstream.example/.well-known/oauth-protected-resource"`
)

// headerAuthorizer adds X-Api-Key and counts calls.
type headerAuthorizer struct {
	calls atomic.Int64
	err   error
}

func (a *headerAuthorizer) Authorize(_ context.Context, req *http.Request) error {
	a.calls.Add(1)
	if a.err != nil {
		return a.err
	}
	req.Header.Set("X-Api-Key", apiKey)
	return nil
}

// requireKey answers 401 with a challenge unless X-Api-Key matches, and
// records every request's headers.
type requireKey struct {
	mu      sync.Mutex
	headers []http.Header
	status  int // 0 → 401
}

func (rk *requireKey) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rk.mu.Lock()
		rk.headers = append(rk.headers, r.Header.Clone())
		rk.mu.Unlock()
		if r.Header.Get("X-Api-Key") != apiKey {
			status := rk.status
			if status == 0 {
				status = http.StatusUnauthorized
			}
			w.Header().Set("WWW-Authenticate", challenge)
			http.Error(w, "upstream secret detail: token for alice expired", status)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (rk *requireKey) seen() []http.Header {
	rk.mu.Lock()
	defer rk.mu.Unlock()
	return append([]http.Header(nil), rk.headers...)
}

func TestAuthorizerAddsCredentialsToEveryRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		tr   Transport
		srv  func(*testing.T, *requireKey) string
	}{
		{"streamable", TransportStreamableHTTP, func(t *testing.T, rk *requireKey) string {
			return streamableServer(t, fullServer(0, 0), rk.wrap).URL + "/mcp"
		}},
		{"sse", TransportSSE, func(t *testing.T, rk *requireKey) string {
			return sseServer(t, fullServer(0, 0), rk.wrap).URL + "/sse"
		}},
		{"auto-sse", TransportAuto, func(t *testing.T, rk *requireKey) string {
			return sseServer(t, fullServer(0, 0), rk.wrap).URL + "/sse"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rk := &requireKey{}
			url := tc.srv(t, rk)
			auth := &headerAuthorizer{}
			c := newTestClient(t, func(o *Options) { o.Authorizer = auth })
			s := connect(t, c, Endpoint{URL: url, Transport: tc.tr, Headers: map[string]string{"X-Tenant": "t1"}})
			exercise(t, s)
			_ = s.Close()
			seen := rk.seen()
			if int(auth.calls.Load()) < len(seen) {
				t.Errorf("Authorizer called %d times for %d requests", auth.calls.Load(), len(seen))
			}
			for i, h := range seen {
				if h.Get("X-Api-Key") != apiKey {
					t.Errorf("request %d had no credential", i)
				}
				if h.Get("X-Tenant") != "t1" {
					t.Errorf("request %d lacks the static header", i)
				}
			}
		})
	}
}

func TestAuthRequiredKeepsChallenge(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		tr         Transport
		sse        bool
	}{
		{"streamable", "/mcp", TransportStreamableHTTP, false},
		{"auto", "/mcp", TransportAuto, false},
		{"sse", "/sse", TransportSSE, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rk := &requireKey{}
			var base string
			if tc.sse {
				base = sseServer(t, fullServer(0, 0), rk.wrap).URL
			} else {
				base = streamableServer(t, fullServer(0, 0), rk.wrap).URL
			}
			url := base + tc.path + "?token=querysecret"
			_, err := newTestClient(t, nil).Connect(ctxT(t), Endpoint{URL: url, Transport: tc.tr})
			e := wantClass(t, err, ClassAuthRequired)
			if e.Status != http.StatusUnauthorized {
				t.Errorf("Status = %d", e.Status)
			}
			if e.WWWAuthenticate != challenge {
				t.Errorf("WWWAuthenticate = %q", e.WWWAuthenticate)
			}
			assertNoLeak(t, err, "querysecret", "alice", "resource_metadata", base)
			for _, h := range rk.seen() {
				if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
					t.Errorf("credential header sent without an Authorizer: %v", h)
				}
			}
		})
	}
}

func TestAuthRequiredDoesNotFallBack(t *testing.T) {
	rk := &requireKey{}
	var log methodLog
	ts := streamableServer(t, fullServer(0, 0), func(h http.Handler) http.Handler { return log.wrap(rk.wrap(h)) })
	_, err := newTestClient(t, nil).Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp"})
	_ = wantClass(t, err, ClassAuthRequired)
	if log.gets() != 0 {
		t.Error("auto fell back to SSE after a 401")
	}
}

func TestForbidden(t *testing.T) {
	rk := &requireKey{status: http.StatusForbidden}
	ts := streamableServer(t, fullServer(0, 0), rk.wrap)
	_, err := newTestClient(t, nil).Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp"})
	e := wantClass(t, err, ClassForbidden)
	if e.Status != http.StatusForbidden || e.WWWAuthenticate != challenge {
		t.Errorf("Status/WWWAuthenticate = %d %q", e.Status, e.WWWAuthenticate)
	}
}

func TestAuthorizerFailure(t *testing.T) {
	ts := streamableServer(t, fullServer(0, 0), nil)
	auth := &headerAuthorizer{err: errors.New("no token stored for user 42")}
	c := newTestClient(t, func(o *Options) { o.Authorizer = auth })
	_, err := c.Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp"})
	_ = wantClass(t, err, ClassAuthRequired)
	assertNoLeak(t, err, "user 42")
	if !strings.Contains(err.Error(), "authorizer") {
		t.Errorf("message %q does not say the authorizer failed", err)
	}
}

func TestNoAuthAddsNothing(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err := (NoAuth{}).Authorize(context.Background(), req); err != nil || len(req.Header) != 0 {
		t.Fatalf("NoAuth = %v, headers %v", err, req.Header)
	}
}
