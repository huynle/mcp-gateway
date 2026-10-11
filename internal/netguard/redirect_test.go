package netguard

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// redirectServer redirects /to?u=<target> to target and /hop/<n> to
// /hop/<n-1> until /hop/0, which answers "done".
func redirectServer(tls bool) *httptest.Server {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/to" {
			http.Redirect(w, r, r.URL.Query().Get("u"), http.StatusFound)
			return
		}
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/hop/%d", &n); err == nil {
			if n == 0 {
				_, _ = io.WriteString(w, "done")
				return
			}
			http.Redirect(w, r, "/hop/"+strconv.Itoa(n-1), http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	if tls {
		return httptest.NewTLSServer(h)
	}
	return httptest.NewServer(h)
}

func TestRedirectsAreRevalidated(t *testing.T) {
	srv := redirectServer(false)
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	res := newFakeResolver()
	res.set("public.example", []string{publicIP})
	res.set("internal.example", []string{"10.0.0.1"})
	dialer := newFakeDialer()
	dialer.routePublic(srv)
	g := New(Options{Resolver: res, Dial: dialer.dial, AllowHTTP: true})
	base := fmt.Sprintf("http://public.example:%d", port)

	tests := []struct {
		name   string
		target string
		want   Reason
	}{
		{"to loopback", "http://127.0.0.1/", ReasonLoopback},
		{"to loopback with port", fmt.Sprintf("http://127.0.0.1:%d/hop/0", port), ReasonLoopback},
		{"to metadata", "http://169.254.169.254/latest/meta-data/iam/", ReasonMetadata},
		{"to decimal loopback", "http://2130706433/", ReasonLoopback},
		{"to mapped v6 loopback", "http://[::ffff:127.0.0.1]/", ReasonLoopback},
		{"to name resolving private", "http://internal.example/", ReasonPrivate},
		{"to userinfo", "http://u:p@public.example/", ReasonUserinfo},
		{"to other scheme", "gopher://public.example/", ReasonScheme},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := get(t, g.Client(), base+"/to?u="+url.QueryEscape(tt.target))
			if err == nil {
				_ = resp.Body.Close()
			}
			wantBlocked(t, err, tt.want)
		})
	}
}

func TestRedirectLimit(t *testing.T) {
	srv := redirectServer(false)
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	res := newFakeResolver()
	res.set("public.example", []string{publicIP})
	dialer := newFakeDialer()
	dialer.routePublic(srv)
	g := New(Options{Resolver: res, Dial: dialer.dial, AllowHTTP: true})

	resp, err := get(t, g.Client(), fmt.Sprintf("http://public.example:%d/hop/%d", port, MaxRedirects))
	if err != nil {
		t.Fatalf("%d redirects: %v", MaxRedirects, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "done" {
		t.Fatalf("body = %q", body)
	}

	resp, err = get(t, g.Client(), fmt.Sprintf("http://public.example:%d/hop/%d", port, MaxRedirects+1))
	if err == nil {
		_ = resp.Body.Close()
	}
	wantBlocked(t, err, ReasonTooManyRedirects)
}

func TestRedirectDowngradeBlocked(t *testing.T) {
	srv := redirectServer(true)
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	res := newFakeResolver()
	res.set("example.com", []string{publicIP}) // httptest's certificate covers example.com
	dialer := newFakeDialer()
	dialer.routePublic(srv)
	// Even with AllowHTTP and an allow-listed host, https must not become http.
	g := New(Options{Resolver: res, Dial: dialer.dial, AllowHTTP: true, AllowList: mustAllow(t, "example.com")})
	trustServer(g, srv)
	base := fmt.Sprintf("https://example.com:%d", port)

	// Sanity: an https→https redirect on the same host works.
	resp, err := get(t, g.Client(), base+"/hop/2")
	if err != nil {
		t.Fatalf("https redirects: %v", err)
	}
	_ = resp.Body.Close()

	resp, err = get(t, g.Client(), base+"/to?u="+url.QueryEscape(fmt.Sprintf("http://example.com:%d/hop/0", port)))
	if err == nil {
		_ = resp.Body.Close()
	}
	wantBlocked(t, err, ReasonRedirectDowngrade)
}
