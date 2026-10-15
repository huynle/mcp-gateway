package microsoft

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
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// TokenSourceFunc returns the oauth2.TokenSource of one of userID's
// connections (connections.Service.TokenSource has this signature). The
// connector calls it once per tool call with Call.Principal.UserID and
// Call.Account and never keeps the token.
type TokenSourceFunc func(ctx context.Context, userID, connectionID string) oauth2.TokenSource

// DefaultTimeout bounds one tool call's Graph requests.
const DefaultTimeout = 30 * time.Second

// Options configures New. Tokens is required; the rest is optional.
type Options struct {
	// Tokens supplies the connection's token source per call.
	Tokens TokenSourceFunc
	// Accounts, when set, lets Call compare the account's granted scopes
	// with the tool's RequiredScopes before any request (scopes.go). The
	// connections service implements it; nil skips the check and Graph
	// decides.
	Accounts connectors.AccountSource
	// HTTPClient is the base client Graph requests go through;
	// http.DefaultClient when nil.
	HTTPClient *http.Client
	// BaseURL is the Graph root with a trailing slash
	// (graph.DefaultBaseURL by default).
	BaseURL string
	// Bounds caps page size (at most maxTop) and result size for every
	// tool; zero fields take the package defaults.
	Bounds connectors.Bounds
	// Timeout bounds one tool call; DefaultTimeout when zero.
	Timeout time.Duration
}

// Connector is the Microsoft 365 connector. Safe for concurrent use: it
// holds no per-call state and builds one graph client per call.
type Connector struct {
	tokens   TokenSourceFunc
	accounts connectors.AccountSource
	http     *http.Client
	baseURL  string
	bounds   connectors.Bounds
	timeout  time.Duration
}

// New builds a Microsoft connector.
func New(opts Options) (*Connector, error) {
	if opts.Tokens == nil {
		return nil, errors.New("microsoft: Options.Tokens is required")
	}
	base := opts.BaseURL
	if base == "" {
		base = graph.DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("microsoft: BaseURL %q must be an absolute http(s) URL", opts.BaseURL)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	bounds := opts.Bounds
	if bounds.MaxPageSize <= 0 {
		bounds.MaxPageSize = connectors.DefaultMaxPageSize
	}
	if bounds.MaxPageSize > maxTop {
		bounds.MaxPageSize = maxTop
	}
	if bounds.MaxResultBytes <= 0 {
		bounds.MaxResultBytes = connectors.DefaultMaxResultBytes
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Connector{tokens: opts.Tokens, accounts: opts.Accounts, http: httpClient, baseURL: u.String(), bounds: bounds, timeout: timeout}, nil
}

// App implements connectors.Connector.
func (c *Connector) App() string { return App }

// Tools implements connectors.Connector. Handlers are nil: Call dispatches
// by name (see connectors.Connector).
func (c *Connector) Tools() []connectors.Tool { return append(c.readTools(), c.writeTools()...) }

// handler runs one tool against an authenticated client.
type handler func(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error)

// Call implements connectors.Connector: dispatches by name, refuses a
// tool whose scopes the account has not granted, fetches the
// connection's token, runs the tool under the timeout and maps failures
// (5xx and network to Unavailable for reads, throttles to RateLimited,
// the rest to *Error).
func (c *Connector) Call(ctx context.Context, call connectors.Call) (connectors.Result, error) {
	name := shortName(call.Tool)
	run, ok := c.handlers()[name]
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
		return connectors.Result{}, &Error{Class: ClassNoAccount, Message: "no connected Microsoft account: connect one on the portal (Connections)"}
	}
	if call.Args == nil {
		call.Args = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := c.checkScopes(ctx, name, call); err != nil {
		return connectors.Result{}, err
	}
	client, err := c.client(ctx, call)
	if err != nil {
		return connectors.Result{}, err
	}
	res, err := run(ctx, client, call)
	if err != nil {
		// Reads report an unreachable Graph as Unavailable; a write never
		// does (its error says whether the outcome is known).
		if !write && classOf(err) == ClassUnavailable {
			return connectors.Result{Unavailable: true}, nil
		}
		return connectors.Result{}, err
	}
	return res, nil
}

// checkScopes refuses the call when the account source knows the account
// and its granted scopes do not cover the tool's RequiredScopes. An
// unknown account (the pipeline resolved it elsewhere) or a lookup
// failure is not a refusal: Graph decides then.
func (c *Connector) checkScopes(ctx context.Context, name string, call connectors.Call) error {
	if c.accounts == nil {
		return nil
	}
	var tool *connectors.Tool
	for _, t := range c.Tools() {
		if t.Name == name {
			tool = &t
			break
		}
	}
	if tool == nil || len(tool.RequiredScopes) == 0 {
		return nil
	}
	owned, err := c.accounts.ListAccounts(ctx, call.Principal.UserID, App)
	if err != nil {
		return nil //nolint:nilerr // the account stage already answered for lookups; Graph decides
	}
	for _, a := range owned {
		if a.ID != call.Account || len(a.Scopes) == 0 {
			continue
		}
		missing := missingScopes(a.Scopes, tool.RequiredScopes)
		if len(missing) == 0 {
			return nil
		}
		msg := fmt.Sprintf("this Microsoft account has not granted %s", strings.Join(missing, ", "))
		teams := false
		for _, m := range missing {
			teams = teams || WorkOnlyScope(m)
		}
		if teams {
			msg += ": " + personalAccountsLackMessage + "; a work account can grant them on the portal (/connections, grant more access)"
		} else {
			msg += ": grant it on the portal (/connections, grant more access)"
		}
		return &Error{Class: ClassScopeRequired, Message: msg}
	}
	return nil
}

// client fetches the connection's token source (one Token() call per
// request happens in the graph client: a refresh happens there when
// needed) and builds a graph client over it.
func (c *Connector) client(ctx context.Context, call connectors.Call) (*graph.Client, error) {
	src := c.tokens(ctx, call.Principal.UserID, call.Account)
	// Fetch once up front so a dead connection is reported as
	// reconnect_required before any request, and reuse that token for
	// the call's requests.
	tok, err := src.Token()
	if err != nil {
		return nil, classify("authenticate", err)
	}
	client, err := graph.New(graph.Options{HTTPClient: c.http, BaseURL: c.baseURL, Token: oauth2.StaticTokenSource(tok)})
	if err != nil {
		return nil, fmt.Errorf("microsoft: client: %w", err)
	}
	return client, nil
}

// shortName strips the "microsoft." prefix.
func shortName(tool string) string {
	if i := strings.IndexByte(tool, '.'); i >= 0 {
		return tool[i+1:]
	}
	return tool
}
