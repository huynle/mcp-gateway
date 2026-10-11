package netguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeResolver answers from a table. Each host has a sequence of answers;
// call n gets answer min(n, len-1), so a two-element sequence models DNS
// that changes between lookups (rebinding).
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	calls   map[string]int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][][]netip.Addr{}, calls: map[string]int{}}
}

func (r *fakeResolver) set(host string, seq ...[]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out [][]netip.Addr
	for _, ans := range seq {
		var addrs []netip.Addr
		for _, a := range ans {
			addrs = append(addrs, netip.MustParseAddr(a))
		}
		out = append(out, addrs)
	}
	r.answers[host] = out
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq, ok := r.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	n := r.calls[host]
	r.calls[host]++
	if n >= len(seq) {
		n = len(seq) - 1
	}
	return seq[n], nil
}

func (r *fakeResolver) count(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

// fakeDialer pretends to be the internet: a dial to a routed (public) IP is
// forwarded to a local httptest listener. It records every address the
// guard asked it to dial.
type fakeDialer struct {
	mu     sync.Mutex
	routes map[netip.Addr]string
	dialed []string
}

func newFakeDialer() *fakeDialer { return &fakeDialer{routes: map[netip.Addr]string{}} }

func (d *fakeDialer) route(ip string, srv *httptest.Server) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.routes[netip.MustParseAddr(ip)] = srv.Listener.Addr().String()
}

func (d *fakeDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	ap, err := netip.ParseAddrPort(addr)
	target, ok := d.routes[ap.Addr()]
	d.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("fake dialer: address %q is not a literal IP:port", addr)
	}
	if !ok {
		return nil, fmt.Errorf("fake dialer: %s is unroutable in tests", addr)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, target)
}

func (d *fakeDialer) dials() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

type countingMetrics struct {
	mu sync.Mutex
	n  map[Reason]int
}

func (m *countingMetrics) BlockedDial(r Reason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.n == nil {
		m.n = map[Reason]int{}
	}
	m.n[r]++
}

func (m *countingMetrics) get(r Reason) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n[r]
}

const publicIP = "93.184.216.34"

func mustAllow(t *testing.T, entries ...string) *StaticAllowList {
	t.Helper()
	al, err := NewStaticAllowList(entries...)
	if err != nil {
		t.Fatal(err)
	}
	return al
}

func wantBlocked(t *testing.T, err error, reason Reason) {
	t.Helper()
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("err = %v, want *BlockedError(%s)", err, reason)
	}
	if be.Reason != reason {
		t.Fatalf("blocked reason = %q, want %q (err %v)", be.Reason, reason, err)
	}
}

// trustServer makes the guard's base transport trust srv's test certificate.
func trustServer(g *Guard, srv *httptest.Server) {
	g.base.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
}

func get(t *testing.T, c *http.Client, rawURL string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q): %v", rawURL, err)
	}
	return c.Do(req)
}

func TestCheckURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		allowHTTP bool
		allow     []string
		want      Reason // "" = allowed
	}{
		{"https name", "https://mcp.example.com/mcp", false, nil, ""},
		{"https name with port", "https://mcp.example.com:8443/mcp", false, nil, ""},
		{"https public literal", "https://8.8.8.8/", false, nil, ""},
		{"http blocked by default", "http://mcp.example.com/", false, nil, ReasonScheme},
		{"http with AllowHTTP", "http://mcp.example.com/", true, nil, ""},
		{"http for allow-listed host", "http://internal.example/", false, []string{"internal.example"}, ""},
		{"other scheme", "ftp://mcp.example.com/", true, nil, ReasonScheme},
		{"file scheme", "file:///etc/passwd", true, nil, ReasonScheme},
		{"userinfo", "https://user:pa55@mcp.example.com/", false, nil, ReasonUserinfo},
		{"userinfo name only", "https://user@mcp.example.com/", false, nil, ReasonUserinfo},
		{"decimal loopback", "http://2130706433/", true, nil, ReasonLoopback},
		{"hex short loopback", "http://0x7f.1/", true, nil, ReasonLoopback},
		{"octal loopback", "http://017700000001/", true, nil, ReasonLoopback},
		{"mapped loopback", "http://[::ffff:127.0.0.1]/", true, nil, ReasonLoopback},
		{"v6 loopback", "https://[::1]:8443/", false, nil, ReasonLoopback},
		{"loopback literal", "https://127.0.0.1/", false, nil, ReasonLoopback},
		{"localhost", "https://localhost/", false, nil, ReasonLoopback},
		{"metadata", "http://169.254.169.254/latest/meta-data/", true, nil, ReasonMetadata},
		{"metadata v6", "http://[fd00:ec2::254]/", true, nil, ReasonMetadata},
		{"metadata decimal", "http://2852039166/", true, nil, ReasonMetadata},
		{"private", "https://10.0.0.1:8443/", false, nil, ReasonPrivate},
		{"cgnat", "https://100.100.100.200/", false, nil, ReasonCGNAT},
		{"zone", "https://[fe80::1%25en0]/", false, nil, ReasonZone},
		{"ambiguous public", "https://134744072/", false, nil, ReasonAmbiguousIP},
		{"empty host", "https:///path", false, nil, ReasonInvalidHost},
		{"allow-listed private literal", "https://10.1.2.3/", false, []string{"10.1.0.0/16"}, ""},
		{"allow-listed literal permits http", "http://10.1.2.3/", false, []string{"10.1.0.0/16"}, ""},
		{"allow list cannot open ambiguous", "https://0x0a.1.2.3/", false, []string{"10.0.0.0/8"}, ReasonPrivate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New(Options{AllowHTTP: tt.allowHTTP, AllowList: mustAllow(t, tt.allow...)})
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			err = g.CheckURL(context.Background(), u)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("CheckURL(%s) = %v, want nil", tt.url, err)
				}
				return
			}
			wantBlocked(t, err, tt.want)
			if strings.Contains(err.Error(), "pa55") || strings.Contains(err.Error(), "/latest") {
				t.Fatalf("error leaks URL parts: %v", err)
			}
		})
	}
}

func TestDialBlocksResolvedInternalAddresses(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  Reason
	}{
		{"loopback", []string{"127.0.0.1"}, ReasonLoopback},
		{"v6 loopback", []string{"::1"}, ReasonLoopback},
		{"private", []string{"192.168.0.10"}, ReasonPrivate},
		{"ula", []string{"fd12::1"}, ReasonPrivate},
		{"link-local", []string{"169.254.10.10"}, ReasonLinkLocal},
		{"v6 link-local", []string{"fe80::1"}, ReasonLinkLocal},
		{"metadata", []string{"169.254.169.254"}, ReasonMetadata},
		{"metadata v6", []string{"fd00:ec2::254"}, ReasonMetadata},
		{"cgnat", []string{"100.64.1.1"}, ReasonCGNAT},
		{"multicast", []string{"224.0.0.251"}, ReasonMulticast},
		{"broadcast", []string{"255.255.255.255"}, ReasonBroadcast},
		{"unspecified", []string{"0.0.0.0"}, ReasonUnspecified},
		{"this network", []string{"0.1.2.3"}, ReasonThisNetwork},
		{"mapped", []string{"::ffff:10.0.0.1"}, ReasonPrivate},
		{"nat64", []string{"64:ff9b::7f00:1"}, ReasonLoopback},
		{"6to4", []string{"2002:a9fe:a9fe::"}, ReasonMetadata},
		{"public then private in one answer", []string{publicIP, "10.0.0.1"}, ReasonPrivate},
		{"private then public in one answer", []string{"10.0.0.1", publicIP}, ReasonPrivate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := newFakeResolver()
			res.set("evil.example", tt.addrs)
			dialer := newFakeDialer()
			g := New(Options{Resolver: res, Dial: dialer.dial})
			resp, err := get(t, g.Client(), "https://evil.example/")
			if err == nil {
				_ = resp.Body.Close()
			}
			wantBlocked(t, err, tt.want)
			if d := dialer.dials(); len(d) != 0 {
				t.Fatalf("guard dialled %v for a blocked host", d)
			}
		})
	}
}

func TestDialUsesCheckedAddressDespiteRebinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	res := newFakeResolver()
	// First lookup: public. Every later lookup: loopback.
	res.set("rebind.example", []string{publicIP}, []string{"127.0.0.1"})
	dialer := newFakeDialer()
	dialer.route(publicIP, srv)
	g := New(Options{Resolver: res, Dial: dialer.dial, AllowHTTP: true})

	resp, err := get(t, g.Client(), fmt.Sprintf("http://rebind.example:%d/", port))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	if n := res.count("rebind.example"); n != 1 {
		t.Fatalf("resolver called %d times, want exactly 1 (check and dial must share one answer)", n)
	}
	want := fmt.Sprintf("%s:%d", publicIP, port)
	if d := dialer.dials(); len(d) != 1 || d[0] != want {
		t.Fatalf("dialled %v, want [%s]", d, want)
	}
}

func TestDialRefusesNonTCPAndDialsOnlyLiterals(t *testing.T) {
	g := New(Options{Resolver: newFakeResolver(), Dial: newFakeDialer().dial})
	_, err := g.dialContext(context.Background(), "udp", publicIP+":53")
	wantBlocked(t, err, ReasonNetwork)
	_, err = g.dialContext(context.Background(), "tcp", "0x7f.1:80")
	wantBlocked(t, err, ReasonLoopback)
	_, err = g.dialContext(context.Background(), "tcp", "[::ffff:169.254.169.254]:80")
	wantBlocked(t, err, ReasonMetadata)
}

func TestLoopbackTestServerBlockedUnlessAllowListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	g := New(Options{AllowHTTP: true})
	resp, err := get(t, g.Client(), srv.URL)
	if err == nil {
		_ = resp.Body.Close()
	}
	wantBlocked(t, err, ReasonLoopback)

	g = New(Options{AllowList: mustAllow(t, "127.0.0.1/32")})
	resp, err = get(t, g.Client(), srv.URL) // http permitted because the host is allow-listed
	if err != nil {
		t.Fatalf("allow-listed Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestAllowListedHostPassesWithOriginalSNIAndHost(t *testing.T) {
	var gotHost, gotSNI string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotSNI = r.Host, r.TLS.ServerName
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	res := newFakeResolver()
	res.set("example.com", []string{"127.0.0.1"}) // httptest's certificate covers example.com
	g := New(Options{Resolver: res, AllowList: mustAllow(t, "example.com")})
	trustServer(g, srv)

	resp, err := get(t, g.Client(), fmt.Sprintf("https://example.com:%d/", port))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "hello" {
		t.Fatalf("body = %q", body)
	}
	if gotSNI != "example.com" || !strings.HasPrefix(gotHost, "example.com") {
		t.Fatalf("server saw SNI %q Host %q, want example.com", gotSNI, gotHost)
	}

	// The same host without the allow list is refused at dial time.
	g = New(Options{Resolver: res})
	trustServer(g, srv)
	resp, err = get(t, g.Client(), fmt.Sprintf("https://example.com:%d/", port))
	if err == nil {
		_ = resp.Body.Close()
	}
	wantBlocked(t, err, ReasonLoopback)
}

func TestBlockedIsCountedAndLoggedWithoutURL(t *testing.T) {
	var logs bytes.Buffer
	m := &countingMetrics{}
	res := newFakeResolver()
	res.set("evil.example", []string{"127.0.0.1"})
	g := New(Options{
		Resolver: res,
		Dial:     newFakeDialer().dial,
		Metrics:  m,
		Log:      slog.New(slog.NewTextHandler(&logs, nil)),
	})

	resp, err := get(t, g.Client(), "https://evil.example/secret-path?token=abc123")
	if err == nil {
		_ = resp.Body.Close()
	}
	wantBlocked(t, err, ReasonLoopback)
	var be *BlockedError
	_ = errors.As(err, &be)
	if strings.Contains(be.Error(), "secret-path") || strings.Contains(be.Error(), "abc123") {
		t.Fatalf("BlockedError leaks the URL: %v", be)
	}

	u, _ := url.Parse("https://alice:hunter2@evil.example/x")
	wantBlocked(t, g.CheckURL(context.Background(), u), ReasonUserinfo)

	if m.get(ReasonLoopback) != 1 || m.get(ReasonUserinfo) != 1 {
		t.Fatalf("metrics = %v", m.n)
	}
	out := logs.String()
	for _, leak := range []string{"secret-path", "abc123", "alice", "hunter2", "/x"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaks %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "evil.example") || !strings.Contains(out, "loopback") {
		t.Fatalf("log lacks host or reason: %s", out)
	}
}

func TestClientDoesNotUseEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
	t.Setenv("HTTP_PROXY", "http://10.0.0.1:3128")
	g := New(Options{})
	if g.base.Proxy != nil {
		t.Fatal("base transport has a Proxy func; proxies would bypass the dial check")
	}
}
