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
	DefaultTimeout = 30 * time.Second
)

// Options configure a Client.
type Options struct {
	HTTPClient     *http.Client
	Timeout        time.Duration
	MaxResultBytes int64
	ClientName     string
	ClientVersion  string
	Log            *slog.Logger
}

// Client connects to remote MCP servers.
type Client struct {
	hc      *http.Client
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
	c := &Client{hc: o.HTTPClient, timeout: o.Timeout, log: o.Log}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	c.impl = &mcp.Implementation{Name: o.ClientName, Version: o.ClientVersion}
	return c, nil
}

// Endpoint is a remote MCP server.
type Endpoint struct {
	URL       string
	Transport Transport
	Headers   map[string]string
}

// Connect connects to ep and completes the MCP handshake.
func (c *Client) Connect(ctx context.Context, ep Endpoint) (*Session, error) {
	hc := *c.hc
	hc.Timeout = 0
	var t mcp.Transport
	switch ep.Transport {
	case TransportSSE:
		t = &mcp.SSEClientTransport{Endpoint: ep.URL, HTTPClient: &hc}
	default:
		t = &mcp.StreamableClientTransport{Endpoint: ep.URL, HTTPClient: &hc, DisableStandaloneSSE: true, MaxRetries: -1}
	}
	cl := mcp.NewClient(c.impl, &mcp.ClientOptions{Logger: c.log})
	hctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cs, err := cl.Connect(hctx, t, nil)
	if err != nil {
		return nil, err
	}
	return &Session{c: c, cs: cs, transport: ep.Transport}, nil
}

// Class is an error class.
type Class string

// Error is a classified error.
type Error struct {
	Class Class
}

func (e *Error) Error() string { return string(e.Class) }
