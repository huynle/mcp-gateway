package slack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	goslack "github.com/slack-go/slack"
	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// TokenSourceFunc returns the oauth2.TokenSource of one of userID's
// connections (connections.Service.TokenSource has this signature). The
// connector calls it once per tool call with Call.Principal.UserID and
// Call.Account and never keeps the token.
type TokenSourceFunc func(ctx context.Context, userID, connectionID string) oauth2.TokenSource

// DefaultTimeout bounds one tool call's Slack requests.
const DefaultTimeout = 30 * time.Second

// Options configures New. Tokens is required; the rest is optional.
type Options struct {
	// Tokens supplies the connection's token source per call.
	Tokens TokenSourceFunc
	// HTTPClient is the base client Slack requests go through (its
	// Transport is reused; the token travels as slack-go's form field);
	// http.DefaultTransport when nil.
	HTTPClient *http.Client
	// BaseURL is the Web API root with a trailing slash:
	// https://slack.com/api/ (default).
	BaseURL string
	// Bounds caps page size (at most 100, the smallest of the Slack
	// maximums the tools use) and result size for every tool; zero fields
	// take the package defaults.
	Bounds connectors.Bounds
	// Timeout bounds one tool call; DefaultTimeout when zero.
	Timeout time.Duration
	// MarkerReconcile opts post_message and reply_in_thread into marker
	// reconciliation (the operation id attached as message metadata and
	// searched for afterwards). Off by default: the two writes then
	// declare reconciliation none and an unknown outcome goes straight
	// to unresolved. cmd/gateway sets it from the vendor app's
	// marker_reconcile extra at start-up.
	MarkerReconcile bool
	// Accounts, when set, is asked for the account's granted scopes so
	// list_conversations lists by default only the conversation types the
	// account may read (asking Slack for a type without its scope fails
	// the whole listing with missing_scope). cmd/gateway passes the
	// connections service; without it the default is public and private
	// channels.
	Accounts connectors.AccountSource
}

// Connector is the Slack connector. Safe for concurrent use: it holds no
// per-call state beyond the identity-resolution cache (identity.go) and
// builds one slack-go client per call. It implements
// connectors.IdentityResolver.
type Connector struct {
	tokens    TokenSourceFunc
	transport http.RoundTripper
	baseURL   string
	bounds    connectors.Bounds
	timeout   time.Duration
	marker    bool
	accounts  connectors.AccountSource
	names     *nameCache
}

// New builds a Slack connector.
func New(opts Options) (*Connector, error) {
	if opts.Tokens == nil {
		return nil, errors.New("slack: Options.Tokens is required")
	}
	base := opts.BaseURL
	if base == "" {
		base = DefaultAPIBase
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("slack: BaseURL %q must be an absolute http(s) URL", opts.BaseURL)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	bounds := opts.Bounds
	if bounds.MaxPageSize <= 0 {
		bounds.MaxPageSize = connectors.DefaultMaxPageSize
	}
	if bounds.MaxPageSize > maxLimit {
		bounds.MaxPageSize = maxLimit
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
	return &Connector{tokens: opts.Tokens, transport: transport, baseURL: u.String(), bounds: bounds, timeout: timeout, marker: opts.MarkerReconcile, accounts: opts.Accounts,
		names: newNameCache(IdentityCacheTTL, IdentityCacheMax)}, nil
}

// App implements connectors.Connector.
func (c *Connector) App() string { return App }

// Tools implements connectors.Connector. Handlers are nil: Call dispatches
// by name (see connectors.Connector).
func (c *Connector) Tools() []connectors.Tool {
	tools := slices.Concat(c.readTools(), c.writeTools(), c.channelTools(), c.messageTools(), c.fileTools(), c.profileTools(), c.conversationTools())
	for i := range tools {
		tools[i].OptionalScopes = slices.Clone(optionalScopes[tools[i].Name])
	}
	return tools
}

// optionalScopes are the user scopes tools use when the account granted
// them and work without (connectors.Tool.OptionalScopes): direct and
// group messages for the conversation readers, opening a DM for the two
// message writes, private channels for the channel tools. Grant more
// access on /connections requests them; the scope stage ignores them.
var optionalScopes = func() map[string][]string {
	m := map[string][]string{
		ToolListConversations:  {ScopeIMRead, ScopeMpIMRead},
		ToolReadChannelHistory: {ScopeIMHistory, ScopeMpIMHistory},
		ToolGetThread:          {ScopeIMHistory, ScopeMpIMHistory},
		ToolPostMessage:        {ScopeIMWrite},
		ToolReplyInThread:      {ScopeIMWrite},
	}
	for _, name := range []string{
		ToolCreateChannel, ToolRenameChannel, ToolArchiveChannel, ToolUnarchiveChannel, ToolSetChannelTopic,
		ToolSetChannelPurpose, ToolJoinChannel, ToolLeaveChannel, ToolInviteToChannel, ToolRemoveFromChannel,
	} {
		m[name] = []string{ScopeGroupsWrite}
	}
	return m
}()

// handler runs one tool against an authenticated client.
type handler func(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error)

// Call implements connectors.Connector: dispatches by name, fetches the
// connection's token, runs the tool under the timeout and maps failures
// (5xx and network to Unavailable for reads, rate limits to RateLimited,
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
		return connectors.Result{}, &Error{Class: ClassNoAccount, Message: "no connected Slack account: connect one on the portal (Connections)"}
	}
	if call.Args == nil {
		call.Args = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	api, err := c.client(ctx, call)
	if err != nil {
		return connectors.Result{}, err
	}
	res, err := run(ctx, api, call)
	if err != nil {
		// Reads report an unreachable Slack as Unavailable; a write never
		// does (its error says whether the outcome is known).
		if !write && classOf(err) == ClassUnavailable {
			return connectors.Result{Unavailable: true}, nil
		}
		return connectors.Result{}, err
	}
	return res, nil
}

// client fetches the connection's token (one call to the token source:
// a refresh happens there when needed) and builds a slack-go client
// that sends it.
func (c *Connector) client(ctx context.Context, call connectors.Call) (*goslack.Client, error) {
	tok, err := c.tokens(ctx, call.Principal.UserID, call.Account).Token()
	if err != nil {
		return nil, classify("authenticate", err)
	}
	return c.clientFor(tok.AccessToken), nil
}

// clientFor builds a slack-go client for token over the connector's
// transport and API root.
func (c *Connector) clientFor(token string) *goslack.Client {
	httpClient := &http.Client{Transport: &userAgentTransport{base: c.transport}}
	return goslack.New(token, goslack.OptionAPIURL(c.baseURL), goslack.OptionHTTPClient(httpClient))
}

// userAgentTransport stamps the gateway's User-Agent on every request.
type userAgentTransport struct{ base http.RoundTripper }

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", userAgent)
	return t.base.RoundTrip(r)
}

// shortName strips the "slack." prefix.
func shortName(tool string) string {
	if i := strings.IndexByte(tool, '.'); i >= 0 {
		return tool[i+1:]
	}
	return tool
}
