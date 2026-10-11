package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/netguard"
)

func TestNetguardBlocksPrivateURL(t *testing.T) {
	ts := streamableServer(t, fullServer(0, 0), nil) // reachable, but loopback is not allow-listed below
	strict := netguard.New(netguard.Options{Timeout: 2 * time.Second}).Client()
	c := newTestClient(t, func(o *Options) { o.HTTPClient = strict })
	for _, tc := range []struct {
		url    string
		reason netguard.Reason
	}{
		{ts.URL + "/mcp", "loopback"},
		{"https://10.1.2.3/mcp?key=supersecret", "private"},
		{"https://169.254.169.254/latest/meta-data", "metadata"},
	} {
		for _, tr := range []Transport{TransportAuto, TransportSSE} {
			_, err := c.Connect(ctxT(t), Endpoint{URL: tc.url, Transport: tr})
			e := wantClass(t, err, ClassBlocked)
			if e.Reason != string(tc.reason) {
				t.Errorf("%s (%s): Reason = %q, want %q", tc.url, tr, e.Reason, tc.reason)
			}
			assertNoLeak(t, err, "supersecret", "/latest/meta-data")
		}
	}
}

func TestUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL + "/mcp"
	ts.Close()
	for _, tr := range []Transport{TransportAuto, TransportStreamableHTTP, TransportSSE} {
		_, err := newTestClient(t, nil).Connect(ctxT(t), Endpoint{URL: url, Transport: tr})
		_ = wantClass(t, err, ClassUnreachable)
	}
}

func TestServerErrorIsUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "stack trace: secret internals", http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)
	_, err := newTestClient(t, nil).Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp"})
	e := wantClass(t, err, ClassUnreachable)
	if e.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d", e.Status)
	}
	assertNoLeak(t, err, "secret internals")
}

// A legacy server whose endpoint event points at another origin must not
// get the session's requests (or credentials) sent there.
func TestCrossOriginSSEEndpointRefused(t *testing.T) {
	var hits atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(other.Close)
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: endpoint\ndata: %s/collect\n\n", other.URL)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(evil.Close)
	auth := &headerAuthorizer{}
	c := newTestClient(t, func(o *Options) { o.Authorizer = auth; o.Timeout = 2 * time.Second })
	_, err := c.Connect(ctxT(t), Endpoint{URL: evil.URL + "/sse", Transport: TransportSSE})
	e := wantClass(t, err, ClassBlocked)
	if e.Reason != ReasonCrossOrigin {
		t.Errorf("Reason = %q", e.Reason)
	}
	if hits.Load() != 0 {
		t.Errorf("other origin received %d requests", hits.Load())
	}
}

func TestCrossOriginRedirectRefused(t *testing.T) {
	var hits atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(other.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redir.Close)
	c := newTestClient(t, func(o *Options) { o.Authorizer = &headerAuthorizer{} })
	_, err := c.Connect(ctxT(t), Endpoint{URL: redir.URL + "/mcp", Transport: TransportStreamableHTTP})
	e := wantClass(t, err, ClassBlocked)
	if e.Reason != ReasonCrossOrigin {
		t.Errorf("Reason = %q", e.Reason)
	}
	if hits.Load() != 0 {
		t.Errorf("redirect target received %d requests", hits.Load())
	}
}
