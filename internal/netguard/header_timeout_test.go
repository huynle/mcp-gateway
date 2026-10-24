package netguard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// slowHeaders answers after delay (headers included).
func slowHeaders(delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(delay):
		}
		_, _ = io.WriteString(w, "done")
	}))
}

// zeroTimeoutClient is the guard's client with the whole-request timeout
// removed, the way the federation client uses it (per-operation contexts
// bound requests instead).
func zeroTimeoutClient(g *Guard) *http.Client {
	hc := g.Client()
	hc.Timeout = 0
	return hc
}

func TestResponseHeaderTimeoutDefaultsToTimeout(t *testing.T) {
	srv := slowHeaders(600 * time.Millisecond)
	defer srv.Close()
	g := newLocalGuard(t, Options{Timeout: 150 * time.Millisecond})

	resp, err := get(t, zeroTimeoutClient(g), srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("want a response header timeout: it defaults to Timeout")
	}
	var te interface{ Timeout() bool }
	if !errors.As(err, &te) || !te.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

func TestResponseHeaderTimeoutRaised(t *testing.T) {
	srv := slowHeaders(600 * time.Millisecond)
	defer srv.Close()
	g := newLocalGuard(t, Options{Timeout: 150 * time.Millisecond, ResponseHeaderTimeout: 5 * time.Second})

	// Without the client timeout, a slow header within ResponseHeaderTimeout
	// is fine.
	resp, err := get(t, zeroTimeoutClient(g), srv.URL)
	if err != nil {
		t.Fatalf("slow headers within ResponseHeaderTimeout: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "done" {
		t.Fatalf("body = %q", b)
	}

	// Client() keeps the whole-request Timeout (OAuth and other plain
	// uses are not lengthened).
	resp, err = get(t, g.Client(), srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("Client() must keep the short whole-request Timeout")
	}

	// A request context still bounds it.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err = zeroTimeoutClient(g).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the request context must still bound the wait")
	}
}
