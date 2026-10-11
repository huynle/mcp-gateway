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
	// DefaultMaxResultBytes bounds one JSON-RPC response on the wire.
	DefaultMaxResultBytes = 4 << 20
	// DefaultMaxListItems bounds the items of one list operation.
	DefaultMaxListItems = 1000
	// sseSlack keeps the SDK's own SSE event cap above ours, so our bound
	// (which classifies) always trips first.
	sseSlack = 64 << 10
)

// Options configure a Client.
type Options struct {
	HTTPClient     *http.Client
	Authorizer     Authorizer
	Timeout        time.Duration
	MaxResultBytes int64
	MaxListItems   int
	ClientName     string
	ClientVersion  string
	Log            *slog.Logger
	OnCall         func(CallInfo)
}

// Client connects to remote MCP servers.
type Client struct {
	hc      *http.Client
	auth    Authorizer
	timeout time.Duration
	maxBody int64
	maxList int
	onCall  func(CallInfo)
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
	c := &Client{hc: o.HTTPClient, auth: o.Authorizer, timeout: o.Timeout, log: o.Log, onCall: o.OnCall}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	c.maxBody = o.MaxResultBytes
	if c.maxBody <= 0 {
		c.maxBody = DefaultMaxResultBytes
	}
	c.maxList = o.MaxListItems
	if c.maxList <= 0 {
		c.maxList = DefaultMaxListItems
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
	ctx = withoutSDKValues(ctx)
	start := time.Now()
	tr := v.transport
	if tr == TransportAuto {
		tr = TransportStreamableHTTP
	}
	s, err := c.connect(ctx, v, tr)
	var e *Error
	if v.transport == TransportAuto && err != nil && errors.As(err, &e) &&
		e.Class == ClassProtocol && legacyStatus(e.Status) && e.RPCCode != mcp.CodeUnsupportedProtocolVersion {
		c.log.Info("federation client: falling back to legacy HTTP+SSE",
			"host", v.u.Hostname(), "status", e.Status)
		tr = TransportSSE
		s, err = c.connect(ctx, v, tr)
	}
	c.report(v.label, opConnect, tr, start, err)
	return s, err
}

// legacyStatus reports whether an HTTP status answering the Streamable
// HTTP POST means "this is a legacy HTTP+SSE server": any 4xx except the
// ones about credentials, timing or rate (MCP spec, backwards
// compatibility section). Connect also never falls back when the 4xx
// carried JSON-RPC -32022 (unsupported protocol version): that server
// speaks Streamable HTTP, and a fallback would only hide the real error.
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
	hc.Transport = &roundTripper{base: c.hc.Transport, origin: origin(v.u), headers: v.headers, auth: c.auth, maxBody: c.maxBody, life: sessCtx}

	var inner mcp.Transport
	if tr == TransportSSE {
		inner = &mcp.SSEClientTransport{Endpoint: v.u.String(), HTTPClient: &hc, MaxEventSize: int(c.maxBody) + sseSlack}
	} else {
		inner = &mcp.StreamableClientTransport{Endpoint: v.u.String(), HTTPClient: &hc,
			DisableStandaloneSSE: true, MaxRetries: -1, MaxEventSize: int(c.maxBody) + sseSlack}
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
	return &Session{c: c, cs: cs, transport: tr, cancel: sessCancel, obs: sessObs, label: v.label}, nil
}

// detached connects the inner transport with the session context instead
// of the handshake context.
type detached struct {
	inner mcp.Transport
	ctx   context.Context
}

func (d *detached) Connect(context.Context) (mcp.Connection, error) { return d.inner.Connect(d.ctx) }
