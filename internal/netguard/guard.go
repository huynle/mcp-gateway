package netguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Request-stage reasons.
const (
	ReasonScheme   Reason = "scheme"   // not https (or http when permitted)
	ReasonUserinfo Reason = "userinfo" // user[:password]@ in the URL
	ReasonNetwork  Reason = "network"  // a dial on anything but TCP
)

// Defaults applied by New for zero Options fields.
const (
	DefaultTimeout          = 30 * time.Second
	DefaultMaxResponseBytes = 10 << 20 // 10 MiB
	dialTimeout             = 10 * time.Second
)

// BlockedError is returned (possibly wrapped by net/http in a *url.Error)
// when the guard refuses a request, redirect or dial. Use errors.As to
// detect it. Its message names the host and the reason only: never the
// path, query or credentials.
type BlockedError struct {
	Reason Reason
	Host   string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("netguard: request to %q blocked: %s", e.Host, e.Reason)
}

// Resolver resolves host names; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc opens a connection. The guard only ever calls it with a checked
// literal "ip:port" address.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Metrics receives one call per refused request, redirect or dial.
// PrometheusMetrics implements it as blocked_dials_total{reason}.
type Metrics interface {
	BlockedDial(reason Reason)
}

// Options configure a Guard. The zero value is a safe default: https only,
// nothing allow-listed, the system resolver, DefaultTimeout and
// DefaultMaxResponseBytes.
type Options struct {
	// AllowList opens otherwise-blocked destinations; nil allows nothing.
	AllowList AllowList
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// Dial defaults to a net.Dialer with a 10 s connect timeout. Tests
	// inject one to route "public" addresses to local servers.
	Dial DialFunc
	// Timeout bounds a whole request through Client (dial, headers, body).
	Timeout time.Duration
	// MaxResponseBytes caps every response body read through the guard;
	// reading past it fails with ErrResponseTooLarge.
	MaxResponseBytes int64
	// AllowHTTP permits plain http to any (non-internal) host. Allow-listed
	// hosts may always use http.
	AllowHTTP bool
	// Metrics and Log observe refusals; both optional. Log receives the
	// host and reason only.
	Metrics Metrics
	Log     *slog.Logger
}

// Guard is the SSRF-safe outbound HTTP stack. Build one with New and share
// it; it is safe for concurrent use.
type Guard struct {
	allow     AllowList
	resolver  Resolver
	dial      DialFunc
	timeout   time.Duration
	maxBody   int64
	allowHTTP bool
	metrics   Metrics
	log       *slog.Logger

	base *http.Transport
	rt   http.RoundTripper
}

// New builds a Guard from o, filling defaults.
func New(o Options) *Guard {
	g := &Guard{
		allow:     o.AllowList,
		resolver:  o.Resolver,
		dial:      o.Dial,
		timeout:   o.Timeout,
		maxBody:   o.MaxResponseBytes,
		allowHTTP: o.AllowHTTP,
		metrics:   o.Metrics,
		log:       o.Log,
	}
	if g.resolver == nil {
		g.resolver = net.DefaultResolver
	}
	if g.dial == nil {
		d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
		g.dial = d.DialContext
	}
	if g.timeout <= 0 {
		g.timeout = DefaultTimeout
	}
	if g.maxBody <= 0 {
		g.maxBody = DefaultMaxResponseBytes
	}
	if g.log == nil {
		g.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	g.base = &http.Transport{
		Proxy:                 nil, // a proxy would make the proxy, not us, choose the destination
		DialContext:           g.dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: g.timeout,
	}
	g.rt = &guardTransport{g: g, base: g.base}
	return g
}

// Client returns a new *http.Client that uses Transport, the request
// timeout and the redirect policy.
func (g *Guard) Client() *http.Client {
	return &http.Client{Transport: g.rt, Timeout: g.timeout, CheckRedirect: g.checkRedirect}
}

// Transport returns the guarded RoundTripper: every request URL is checked
// (CheckURL), every dial is checked, and response bodies are capped. It
// does not follow redirects; Client does, re-checking each hop.
func (g *Guard) Transport() http.RoundTripper { return g.rt }

// CheckURL validates u without any network access: scheme, userinfo and
// literal hosts. Resolved addresses are checked later, at dial time. It is
// also the check to run when a user saves a server URL.
func (g *Guard) CheckURL(ctx context.Context, u *url.URL) error {
	if u == nil {
		return g.block("", ReasonInvalidHost)
	}
	host := u.Hostname()
	if u.User != nil {
		return g.block(host, ReasonUserinfo)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return g.block(host, ReasonScheme)
	}
	ip, reason := parseHost(host)
	if reason != "" && !g.overrides(ctx, host, ip, reason) {
		return g.block(host, reason)
	}
	if scheme == "http" && !g.allowHTTP && !g.allowed(ctx, host, ip) {
		return g.block(host, ReasonScheme)
	}
	return nil
}

// overrides reports whether the allow list may open a host refused by
// parseHost. Ambiguous numeric hosts, malformed hosts and zoned IPv6 are
// never opened: they cannot be named exactly in an allow list.
func (g *Guard) overrides(ctx context.Context, host string, ip netip.Addr, reason Reason) bool {
	switch reason {
	case ReasonAmbiguousIP, ReasonInvalidHost, ReasonZone, ReasonInvalid:
		return false
	}
	if !ip.IsValid() && endsInNumber(normalizeHost(host)) {
		return false // non-canonical numeric form of an internal address
	}
	return g.allowed(ctx, host, ip)
}

func (g *Guard) allowed(ctx context.Context, host string, ip netip.Addr) bool {
	return g.allow != nil && g.allow.Allowed(ctx, host, ip)
}

// dialContext is the transport's DialContext: resolve once, refuse if any
// answer is internal and not allow-listed, then dial the checked addresses
// themselves so a later DNS answer cannot change the destination.
func (g *Guard) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, g.block("", ReasonInvalidHost)
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, g.block(host, ReasonNetwork)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, g.block(host, ReasonInvalidHost)
	}

	ip, reason := parseHost(host)
	if reason != "" && !g.overrides(ctx, host, ip, reason) {
		return nil, g.block(host, reason)
	}
	var addrs []netip.Addr
	if ip.IsValid() {
		addrs = []netip.Addr{ip}
	} else {
		addrs, err = g.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("netguard: resolve %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("netguard: resolve %q: no addresses", host)
		}
	}
	for _, a := range addrs {
		if r, blocked := classifyAddr(a); blocked && !g.allowed(ctx, host, a) {
			return nil, g.block(host, r)
		}
	}

	var errs []error
	for _, a := range addrs {
		conn, err := g.dial(ctx, network, netip.AddrPortFrom(a.Unmap(), uint16(port)).String())
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// block records a refusal and returns its error. Only the host and the
// reason are logged.
func (g *Guard) block(host string, reason Reason) error {
	if len(host) > 253 {
		host = host[:253]
	}
	if g.metrics != nil {
		g.metrics.BlockedDial(reason)
	}
	g.log.Warn("netguard: blocked outbound request", "host", host, "reason", string(reason))
	return &BlockedError{Reason: reason, Host: host}
}

// guardTransport checks each request URL before handing it to the base
// transport (whose DialContext checks the addresses).
type guardTransport struct {
	g    *Guard
	base http.RoundTripper
}

func (t *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.g.CheckURL(req.Context(), req.URL); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return t.base.RoundTrip(req)
}
