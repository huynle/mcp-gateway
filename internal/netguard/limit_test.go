package netguard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error { c.closed = true; return nil }

func TestLimitedBody(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		max     int64
		wantErr bool
	}{
		{"empty", 0, 10, false},
		{"under", 9, 10, false},
		{"exactly at cap", 10, 10, false},
		{"one over", 11, 10, true},
		{"far over", 10000, 10, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &closeRecorder{Reader: strings.NewReader(strings.Repeat("x", tt.size))}
			rc := LimitedBody(src, tt.max)
			got, err := io.ReadAll(rc)
			if tt.wantErr {
				if !errors.Is(err, ErrResponseTooLarge) {
					t.Fatalf("err = %v, want ErrResponseTooLarge", err)
				}
				if int64(len(got)) > tt.max {
					t.Fatalf("returned %d bytes past the cap %d", len(got), tt.max)
				}
				// Further reads keep failing.
				if _, err := rc.Read(make([]byte, 1)); !errors.Is(err, ErrResponseTooLarge) {
					t.Fatalf("second read err = %v", err)
				}
			} else if err != nil || len(got) != tt.size {
				t.Fatalf("ReadAll = %d bytes, %v; want %d, nil", len(got), err, tt.size)
			}
			if err := rc.Close(); err != nil || !src.closed {
				t.Fatalf("Close = %v, closed=%v", err, src.closed)
			}
		})
	}
}

func newLocalGuard(t *testing.T, o Options) *Guard {
	t.Helper()
	o.AllowList = mustAllow(t, "127.0.0.1/32") // the httptest server lives on loopback
	return New(o)
}

func TestClientCapsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 1024
		if r.URL.Path == "/big" {
			n = 4096
		}
		_, _ = io.WriteString(w, strings.Repeat("a", n))
	}))
	defer srv.Close()
	g := newLocalGuard(t, Options{MaxResponseBytes: 1024})

	resp, err := get(t, g.Client(), srv.URL+"/ok")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || len(b) != 1024 {
		t.Fatalf("at-cap body: %d bytes, %v", len(b), err)
	}

	resp, err = get(t, g.Client(), srv.URL+"/big")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized body err = %v, want ErrResponseTooLarge", err)
	}

	// The bare Transport caps too.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/big", nil)
	resp, err = g.Transport().RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("transport oversized body err = %v", err)
	}
}

func TestClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	g := newLocalGuard(t, Options{Timeout: 100 * time.Millisecond})

	start := time.Now()
	resp, err := get(t, g.Client(), srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("want a timeout error")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("request took %v despite a 100ms timeout", d)
	}
	var te interface{ Timeout() bool }
	if !errors.As(err, &te) || !te.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
}
