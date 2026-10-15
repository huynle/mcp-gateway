package github

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	gh "github.com/google/go-github/v90/github"
	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// TokenSourceFunc returns the oauth2.TokenSource of one of userID's
// connections (connections.Service.TokenSource has this signature). The
// connector calls it once per tool call with Call.Principal.UserID and
// Call.Account and never keeps the token.
type TokenSourceFunc func(ctx context.Context, userID, connectionID string) oauth2.TokenSource

// DefaultTimeout bounds one tool call's GitHub requests.
const DefaultTimeout = 30 * time.Second

// Options configures New. Tokens is required; the rest is optional.
type Options struct {
	// Tokens supplies the connection's token source per call.
	Tokens TokenSourceFunc
	// HTTPClient is the base client GitHub requests go through (its
	// Transport is wrapped with the bearer token); http.DefaultClient's
	// transport when nil.
	HTTPClient *http.Client
	// BaseURL is the REST API root with a trailing slash:
	// https://api.github.com/ (default) or https://<ghes>/api/v3/.
	BaseURL string
	// Bounds caps page size (at most 100, GitHub's own maximum) and result
	// size for every tool; zero fields take the package defaults.
	Bounds connectors.Bounds
	// Timeout bounds one tool call; DefaultTimeout when zero.
	Timeout time.Duration
}

// Connector is the GitHub connector. Safe for concurrent use: it holds no
// per-call state and builds one go-github client per call.
type Connector struct {
	tokens    TokenSourceFunc
	transport http.RoundTripper
	baseURL   string
	bounds    connectors.Bounds
	timeout   time.Duration
}

// New builds a GitHub connector.
func New(opts Options) (*Connector, error) {
	if opts.Tokens == nil {
		return nil, errors.New("github: Options.Tokens is required")
	}
	base := opts.BaseURL
	if base == "" {
		base = DefaultAPIBase
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("github: BaseURL %q must be an absolute http(s) URL", opts.BaseURL)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	bounds := opts.Bounds
	if bounds.MaxPageSize <= 0 {
		bounds.MaxPageSize = connectors.DefaultMaxPageSize
	}
	if bounds.MaxPageSize > maxPerPage {
		bounds.MaxPageSize = maxPerPage
	}
	if bounds.MaxResultBytes <= 0 {
		bounds.MaxResultBytes = connectors.DefaultMaxResultBytes
	}
	transport := http.DefaultTransport
	if opts.HTTPClient != nil && opts.HTTPClient.Transport != nil {
		transport = opts.HTTPClient.Transport
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Connector{tokens: opts.Tokens, transport: transport, baseURL: u.String(), bounds: bounds, timeout: timeout}, nil
}

// App implements connectors.Connector.
func (c *Connector) App() string { return App }

// Tools implements connectors.Connector. Handlers are nil: Call dispatches
// by name (see connectors.Connector).
func (c *Connector) Tools() []connectors.Tool {
	return slices.Concat(c.readTools(), c.writeTools(), c.repoTools(), c.issueTools(), c.pullTools())
}

// toolGroups lists the read and write handlers of every tool group.
func (c *Connector) toolGroups() (reads, writes map[string]handler) {
	reads, writes = c.handlers(), c.writeHandlers()
	for _, group := range []func() (map[string]handler, map[string]handler){c.repoHandlers, c.issueHandlers, c.pullHandlers} {
		r, w := group()
		maps.Copy(reads, r)
		maps.Copy(writes, w)
	}
	return reads, writes
}

// handler runs one tool against an authenticated client.
type handler func(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error)

// Call implements connectors.Connector: dispatches by name, fetches the
// connection's token, runs the tool under the timeout and maps failures
// (5xx and network to Unavailable, rate limits to RateLimited, the rest
// to *Error).
func (c *Connector) Call(ctx context.Context, call connectors.Call) (connectors.Result, error) {
	name := shortName(call.Tool)
	reads, writes := c.toolGroups()
	run, ok := reads[name]
	write := false
	if !ok {
		run, ok = writes[name]
		write = true
	}
	if !ok {
		return connectors.Result{}, fmt.Errorf("%w: %q", connectors.ErrUnknownTool, call.Tool)
	}
	if write && call.OperationID == "" {
		return connectors.Result{}, ErrMissingOperation
	}
	if call.Account == "" {
		return connectors.Result{}, &Error{Class: ClassNoAccount, Message: "no connected GitHub account: connect one on the portal (Connections)"}
	}
	if call.Args == nil {
		call.Args = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.client(ctx, call)
	if err != nil {
		return connectors.Result{}, err
	}
	res, err := run(ctx, client, call)
	if err != nil {
		var e *Error
		// Reads report an unreachable GitHub as Unavailable; a write never
		// does (its error says whether the outcome is known).
		if !write && errors.As(err, &e) && e.Class == ClassUnavailable {
			return connectors.Result{Unavailable: true}, nil
		}
		return connectors.Result{}, err
	}
	return res, nil
}

// client fetches the connection's token (one call to the token source:
// a refresh happens there when needed) and builds a go-github client
// that sends it.
func (c *Connector) client(ctx context.Context, call connectors.Call) (*gh.Client, error) {
	tok, err := c.tokens(ctx, call.Principal.UserID, call.Account).Token()
	if err != nil {
		return nil, classify("authenticate", err)
	}
	httpClient := &http.Client{Transport: &oauth2.Transport{Source: oauth2.StaticTokenSource(tok), Base: c.transport}}
	return newClient(httpClient, c.baseURL)
}

// shortName strips the "github." prefix.
func shortName(tool string) string {
	if i := strings.IndexByte(tool, '.'); i >= 0 {
		return tool[i+1:]
	}
	return tool
}
