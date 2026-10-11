// Package client talks to remote MCP servers as an MCP client, always
// through an injected netguard HTTP client.
package client

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Transport selects the MCP HTTP transport.
type Transport string

// Transports.
const (
	TransportAuto           Transport = "auto"
	TransportStreamableHTTP Transport = "streamable_http"
	TransportSSE            Transport = "sse"
)

// Defaults applied by New.
const (
	DefaultTimeout    = 30 * time.Second
	DefaultClientName = "mcp-gateway"
)

// Options configure a Client.
type Options struct {
	HTTPClient     *http.Client
	Authorizer     Authorizer
	Timeout        time.Duration
	MaxResultBytes int64
	ClientName     string
	ClientVersion  string
	Log            *slog.Logger
}

// Client connects to remote MCP servers.
type Client struct {
	hc      *http.Client
	auth    Authorizer
	timeout time.Duration
	impl    *mcp.Implementation
	log     *slog.Logger
}

// New builds a Client.
func New(o Options) (*Client, error) {
	if o.HTTPClient == nil {
		return nil, errors.New("federation client: Options.HTTPClient is required (use netguard.Guard.Client())")
	}
	if o.HTTPClient.Transport == nil {
		return nil, errors.New("federation client: Options.HTTPClient has no Transport (use netguard.Guard.Client())")
	}
	c := &Client{hc: o.HTTPClient, auth: o.Authorizer, timeout: o.Timeout, log: o.Log}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	name := o.ClientName
	if name == "" {
		name = DefaultClientName
	}
	c.impl = &mcp.Implementation{Name: name, Version: o.ClientVersion}
	return c, nil
}

// Connect connects to ep and completes the MCP handshake within the
// client's Timeout.
func (c *Client) Connect(ctx context.Context, ep Endpoint) (*Session, error) {
	v, err := validate(ep)
	if err != nil {
		return nil, err
	}
	switch v.transport {
	case TransportStreamableHTTP, TransportSSE:
		return c.connect(ctx, v, v.transport)
	}
	s, err := c.connect(ctx, v, TransportStreamableHTTP)
	var e *Error
	if err == nil || !errors.As(err, &e) || e.Class != ClassProtocol || !legacyStatus(e.Status) {
		return s, err
	}
	c.log.Info("federation client: falling back to legacy HTTP+SSE",
		"host", v.u.Hostname(), "status", e.Status)
	return c.connect(ctx, v, TransportSSE)
}

// legacyStatus reports whether an HTTP status answering the Streamable
// HTTP POST means "this is a legacy HTTP+SSE server": any 4xx except the
// ones about credentials, timing or rate (MCP spec, backwards
// compatibility section).
func legacyStatus(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusProxyAuthRequired,
		http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return code >= 400 && code <= 499
}

func (c *Client) connect(ctx context.Context, v *validated, tr Transport) (*Session, error) {
	hsObs := &observer{}
	sessObs := &observer{}
	// The session context outlives Connect: the legacy SSE GET stream is
	// opened with it and must stay up until Close.
	sessCtx, sessCancel := context.WithCancel(withObserver(context.WithoutCancel(ctx), sessObs))
	hctx, hcancel := context.WithTimeout(withObserver(ctx, hsObs), c.timeout)
	defer hcancel()
	stop := context.AfterFunc(hctx, sessCancel) // abort a hanging transport connect

	hc := *c.hc
	hc.Timeout = 0 // per-operation contexts bound requests; see doc.go
	hc.Transport = &roundTripper{base: c.hc.Transport, origin: origin(v.u), headers: v.headers, auth: c.auth}

	var inner mcp.Transport
	if tr == TransportSSE {
		inner = &mcp.SSEClientTransport{Endpoint: v.u.String(), HTTPClient: &hc}
	} else {
		inner = &mcp.StreamableClientTransport{Endpoint: v.u.String(), HTTPClient: &hc,
			DisableStandaloneSSE: true, MaxRetries: -1}
	}
	cl := mcp.NewClient(c.impl, &mcp.ClientOptions{Logger: c.log})
	cs, err := cl.Connect(hctx, &detached{inner: inner, ctx: sessCtx}, nil)
	if err != nil {
		stop()
		sessCancel()
		return nil, classify(hctx, opConnect, err, hsObs, sessObs)
	}
	if !stop() {
		_ = cs.Close()
		sessCancel()
		return nil, classify(hctx, opConnect, context.DeadlineExceeded, hsObs, sessObs)
	}
	return &Session{c: c, cs: cs, transport: tr, cancel: sessCancel, obs: sessObs}, nil
}

// detached connects the inner transport with the session context instead
// of the handshake context.
type detached struct {
	inner mcp.Transport
	ctx   context.Context
}

func (d *detached) Connect(context.Context) (mcp.Connection, error) { return d.inner.Connect(d.ctx) }
