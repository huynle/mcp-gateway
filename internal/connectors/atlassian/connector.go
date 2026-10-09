package atlassian

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// TokenSourceFunc returns the oauth2.TokenSource of one of userID's
// connections (connections.Service.TokenSource has this signature). The
// connector calls it once per tool call with Call.Principal.UserID and
// Call.Account and never keeps the token.
type TokenSourceFunc func(ctx context.Context, userID, connectionID string) oauth2.TokenSource

// Site is the Atlassian site a connection is bound to: the cloud id every
// product request is addressed with (from the connection's external
// account id "<account id>@<cloud id>", see Binder) and, when known, the
// site's URL (https://<site>.atlassian.net) used to build the links in
// results. URL may be empty; links are then omitted.
type Site struct {
	CloudID string
	URL     string
}

// SiteSourceFunc returns the site one of userID's connections is bound
// to. cmd/gateway implements it over the connections service
// (ParseExternalAccountID on the connection's external account id).
type SiteSourceFunc func(ctx context.Context, userID, connectionID string) (Site, error)

// DefaultTimeout bounds one tool call's Atlassian requests.
const DefaultTimeout = 30 * time.Second

// Options configures New. Tokens and Sites are required; the rest is
// optional.
type Options struct {
	// Tokens supplies the connection's token source per call.
	Tokens TokenSourceFunc
	// Sites supplies the connection's bound site per call.
	Sites SiteSourceFunc
	// HTTPClient is the base client requests go through (its Transport is
	// wrapped with the bearer token); http.DefaultClient's transport when
	// nil.
	HTTPClient *http.Client
	// BaseURL is the API gateway root without a trailing slash
	// (DefaultAPIBase).
	BaseURL string
	// Bounds caps page size (at most 100, Atlassian's own maximum on the
	// endpoints used) and result size for every tool; zero fields take the
	// package defaults.
	Bounds connectors.Bounds
	// Timeout bounds one tool call; DefaultTimeout when zero.
	Timeout time.Duration
}

// Connector is one of the two Atlassian connector apps (jira or
// confluence); both share the same vendor, options and client. Safe for
// concurrent use: it holds no per-call state and builds one client per
// call.
type Connector struct {
	app       string
	tokens    TokenSourceFunc
	sites     SiteSourceFunc
	transport http.RoundTripper
	baseURL   string
	bounds    connectors.Bounds
	timeout   time.Duration
}

// New builds the connector for app (JiraApp or ConfluenceApp).
func New(app string, opts Options) (*Connector, error) {
	if app != JiraApp && app != ConfluenceApp {
		return nil, fmt.Errorf("atlassian: unknown app %q (want %s or %s)", app, JiraApp, ConfluenceApp)
	}
	if opts.Tokens == nil {
		return nil, errors.New("atlassian: Options.Tokens is required")
	}
	if opts.Sites == nil {
		return nil, errors.New("atlassian: Options.Sites is required")
	}
	base := opts.BaseURL
	if base == "" {
		base = DefaultAPIBase
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("atlassian: BaseURL %q must be an absolute http(s) URL", opts.BaseURL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	bounds := opts.Bounds
	if bounds.MaxPageSize <= 0 {
		bounds.MaxPageSize = connectors.DefaultMaxPageSize
	}
	if bounds.MaxPageSize > maxPageSize {
		bounds.MaxPageSize = maxPageSize
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
	return &Connector{app: app, tokens: opts.Tokens, sites: opts.Sites, transport: transport, baseURL: u.String(), bounds: bounds, timeout: timeout}, nil
}

// App implements connectors.Connector.
func (c *Connector) App() string { return c.app }

// Tools implements connectors.Connector. Handlers are nil: Call dispatches
// by name (see connectors.Connector).
func (c *Connector) Tools() []connectors.Tool {
	return append(c.readTools(), c.writeTools()...)
}

// session is what a handler runs with: the authenticated client for the
// connection's site and the site itself (for links).
type session struct {
	*client
	site Site
}

// handler runs one tool against an authenticated session.
type handler func(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error)

// Call implements connectors.Connector: dispatches by name, resolves the
// connection's site and token, runs the tool under the timeout and maps
// failures (5xx and network to Unavailable for reads, 429 to
// RateLimited, the rest to *Error).
func (c *Connector) Call(ctx context.Context, call connectors.Call) (connectors.Result, error) {
	app, name := splitName(call.Tool)
	if app != "" && app != c.app {
		return connectors.Result{}, fmt.Errorf("%w: %q", connectors.ErrUnknownTool, call.Tool)
	}
	run, ok := c.readHandlers()[name]
	write := false
	if !ok {
		run, ok = c.writeHandlers()[name]
		write = true
	}
	if !ok {
		return connectors.Result{}, fmt.Errorf("%w: %q", connectors.ErrUnknownTool, call.Tool)
	}
	if write && call.OperationID == "" {
		return connectors.Result{}, ErrMissingOperation
	}
	if call.Account == "" {
		return connectors.Result{}, &Error{Class: ClassNoAccount, Message: "no connected Atlassian account: connect one on the portal (Connections)"}
	}
	if call.Args == nil {
		call.Args = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	s, err := c.session(ctx, call)
	if err != nil {
		return connectors.Result{}, err
	}
	res, err := run(ctx, s, call)
	if err != nil {
		var e *Error
		// Reads report an unreachable Atlassian as Unavailable; a write
		// never does (its error says whether the outcome is known).
		if !write && errors.As(err, &e) && e.Class == ClassUnavailable {
			return connectors.Result{Unavailable: true}, nil
		}
		return connectors.Result{}, err
	}
	return res, nil
}

// session resolves the connection's site and token (one call to each
// source: a refresh happens in the token source when needed) and builds
// the client that sends the token.
func (c *Connector) session(ctx context.Context, call connectors.Call) (*session, error) {
	site, err := c.sites(ctx, call.Principal.UserID, call.Account)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "resolve site: this connection is not bound to an Atlassian site; reconnect it on the portal (Connections)", Err: err}
	}
	if site.CloudID == "" {
		return nil, &Error{Class: ClassVendorError, Message: "resolve site: this connection is not bound to an Atlassian site; reconnect it on the portal (Connections)"}
	}
	tok, err := c.tokens(ctx, call.Principal.UserID, call.Account).Token()
	if err != nil {
		return nil, classify(c.app, "authenticate", err)
	}
	httpClient := &http.Client{Transport: &oauth2.Transport{Source: oauth2.StaticTokenSource(tok), Base: c.transport}}
	return &session{client: &client{http: httpClient, base: c.baseURL, cloudID: site.CloudID}, site: site}, nil
}

// classify maps a client error for this connector's app.
func (c *Connector) classify(action string, err error) error { return classify(c.app, action, err) }

// splitName splits "app.tool" into its parts ("" app when there is no dot).
func splitName(tool string) (app, name string) {
	if i := strings.IndexByte(tool, '.'); i >= 0 {
		return tool[:i], tool[i+1:]
	}
	return "", tool
}
