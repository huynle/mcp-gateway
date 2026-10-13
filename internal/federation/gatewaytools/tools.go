// Package gatewaytools is the built-in "gateway" app: MCP tools that let a
// user's own MCP client (OpenCode, Claude, ...) list, inspect, detect, add,
// refresh and delete the user's MCP servers on this gateway (Brain task
// 99b5yzdb, plan ax0w46sh, decision bnneszc1).
//
// The tools exist for a user only while the user may add MCP servers AND
// switched "Gateway management tools" on in My account (Gate, evaluated
// per request with a short cache); otherwise they are hidden and a call is
// answered exactly like an unknown tool. Policy: the gateway layer of the
// compiled Cedar set (internal/policy) lets every user call them without a
// role grant; reads and add_server allow, delete_server needs an approval.
//
// Nothing that needs a human happens over MCP: secrets (API keys, bearer
// tokens, header values, shared credentials), signing in to a server
// (OAuth) and approving a server's tools happen in the browser, at the
// portal links the tools return. There is no tool to approve a review,
// publish a server, edit the network allow list or create a tunnel token,
// and add_server refuses any argument that looks like a secret.
package gatewaytools

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	isettings "github.com/huynle/mcp-gateway/internal/settings"
	"github.com/huynle/mcp-gateway/internal/store"
)

// App is the tools' app: every tool is "gateway.<name>". The name is
// reserved for user-added servers (connector.ReservedNames).
const App = policy.GatewayApp

// Tool names.
const (
	ToolListServers      = "list_servers"
	ToolGetServer        = "get_server"
	ToolDetectAuth       = "detect_auth"
	ToolAddServer        = "add_server"
	ToolRefreshServer    = "refresh_server"
	ToolConnectLink      = "connect_link"
	ToolDeleteServer     = policy.GatewayConfirmTool
	ToolGetRateLimits    = "get_rate_limits"
	ToolSetMyRateLimit   = "set_my_rate_limit"
	ToolSetOrgRateLimits = "set_org_rate_limits"
	ToolSetAppRateLimit  = "set_app_rate_limit"
	ToolSetUserRateLimit = "set_user_rate_limit"
)

// Servers is the user-scoped server data (fedportal.NewStore: every call
// runs as the user, so row-level security decides visibility).
type Servers interface {
	ListVisibleServers(ctx context.Context, userID string) ([]store.MCPServer, error)
	GetServer(ctx context.Context, userID, serverID string) (*store.MCPServer, error)
	// DeleteServer is owner-only (store.ErrNotFound otherwise).
	DeleteServer(ctx context.Context, userID, serverID string) error
	ListConnections(ctx context.Context, userID string) ([]store.MCPUserConnection, error)
	CredentialInfo(ctx context.Context, userID, serverID string) (fedportal.CredentialInfo, error)
	ListTunnels(ctx context.Context, userID string) ([]store.MCPTunnel, error)
}

// Snapshots is the part of *snapshot.Service the tools use. There is no
// Approve: the tools never approve a review.
type Snapshots interface {
	Refresh(ctx context.Context, a snapshot.Actor, serverID string, sess snapshot.Session) (*snapshot.Record, snapshot.Diff, error)
	Latest(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
	Current(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
}

// Detector is auth detection (*auth.Service.Detect, through netguard).
type Detector interface {
	Detect(ctx context.Context, serverURL string) (*auth.DetectResult, error)
}

// Manager is the part of *connector.Manager the tools use: CreateServer
// checks the add-server permission and the name rules; ServerChanged
// reloads the gateway's tools after a delete.
type Manager interface {
	CreateServer(ctx context.Context, s *store.MCPServer) error
	ServerChanged(ctx context.Context, serverID string) error
}

// URLChecker refuses user-supplied addresses netguard would never dial
// (*netguard.Guard.CheckURL: scheme, user info, blocked literal hosts
// unless allow-listed). Names are checked again at dial time.
type URLChecker interface {
	CheckURL(ctx context.Context, u *url.URL) error
}

// Deps are the Connector's collaborators; all but Gate and Log are
// required. BaseURL is GATEWAY_BASE_URL (absolute portal links).
type Deps struct {
	Servers   Servers
	Snapshots Snapshots
	Detector  Detector
	Manager   Manager
	// Clients opens an upstream session as the caller, the same factory
	// the portal's Refresh uses.
	Clients  fedportal.ClientFactory
	URLCheck URLChecker
	// Gate, when set, is checked again inside every call (defense in
	// depth behind the Decider wrapper): closed means "unknown tool".
	Gate    *Gate
	BaseURL string
	Log     *slog.Logger
	Rates   RateSettings
}

type RateSettings interface {
	Snapshot(ctx context.Context) isettings.Snapshot
	Limits(ctx context.Context, userID, app string) (int, int)
	IsAdmin(ctx context.Context, userID string) bool
	SetSelf(ctx context.Context, userID string, limit *int) error
	SetOrg(ctx context.Context, actor string, user, app int) error
	SetApp(ctx context.Context, actor, app string, limit *int) error
	SetUserAdmin(ctx context.Context, actor, user string, limit *int) error
}

// Connector is the gateway app.
type Connector struct {
	d    Deps
	base string
	log  *slog.Logger
}

// New builds the connector.
func New(d Deps) (*Connector, error) {
	if d.Servers == nil || d.Snapshots == nil || d.Detector == nil || d.Manager == nil || d.Clients == nil || d.URLCheck == nil {
		return nil, errors.New("gateway tools: Servers, Snapshots, Detector, Manager, Clients and URLCheck are required")
	}
	if strings.TrimSpace(d.BaseURL) == "" {
		return nil, errors.New("gateway tools: the base URL is required (portal links)")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Connector{d: d, base: strings.TrimRight(d.BaseURL, "/"), log: d.Log}, nil
}

// App implements connectors.Connector.
func (c *Connector) App() string { return App }

// Register adds the tools to reg. Unlike connectors.RegisterConnector it
// adds no gateway.list_accounts: the one account is the gateway's own.
func (c *Connector) Register(reg *connectors.Registry) error {
	for _, t := range c.Tools() {
		t.Handler = c.Call
		if err := reg.Register(t); err != nil {
			return err
		}
	}
	return nil
}

// Wording shared by the descriptions.
const (
	browserNote = " Secrets (API keys, tokens, header values), signing in to a server and approving its tools happen in the browser at the links returned; never ask the user to paste a secret into the chat."
	serverArg   = `"server":{"type":"string","description":"The server's name or ID.","minLength":1,"maxLength":63}`
)

func schema(props string, required ...string) json.RawMessage {
	req := ""
	if len(required) > 0 {
		req = `,"required":["` + strings.Join(required, `","`) + `"]`
	}
	return json.RawMessage(`{"type":"object","properties":{` + props + `},"additionalProperties":false` + req + `}`)
}

// serverIdentity is the audit/policy identity of a call naming a server:
// the argument when it is a server name or ID, else "invalid" (so an
// arbitrary value never reaches an audit row).
func serverIdentity(key string) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		s, _ := args[key].(string)
		if !serverNameRE.MatchString(s) && !uuidRE.MatchString(s) {
			s = "invalid"
		}
		return map[string]string{"server": s}
	}
}

func hostIdentity(args map[string]any) map[string]string {
	raw, _ := args["url"].(string)
	host := "invalid"
	if u, err := url.Parse(raw); err == nil && hostRE.MatchString(u.Hostname()) {
		host = u.Hostname()
	}
	return map[string]string{"host": host}
}

func serverIDResult(res connectors.Result) map[string]string {
	if m, ok := res.Content.(map[string]any); ok {
		if id, ok := m["server_id"].(string); ok {
			return map[string]string{"server_id": id}
		}
	}
	return nil
}

// Tools implements connectors.Connector.
func (c *Connector) Tools() []connectors.Tool {
	bounds := connectors.Bounds{MaxResultBytes: connectors.DefaultMaxResultBytes}
	write := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	out := []connectors.Tool{
		{
			App: App, Name: ToolListServers, Kind: connectors.KindRead, Bounds: bounds,
			Description: "List the MCP servers you can use on this gateway (yours and those published to you): name, address host, " +
				"audience, status, credential mode, your connection state, whether a tool review is pending, the number of approved tools, " +
				"and portal links." + browserNote,
			InputSchema:      schema(""),
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"app": App} },
		},
		{
			App: App, Name: ToolGetServer, Kind: connectors.KindRead, Bounds: bounds,
			Description: "Show one MCP server you can use, with the next steps to make its tools available and the portal links for each " +
				"(connect, enter your credential, review its tools)." + browserNote,
			InputSchema:      schema(serverArg, "server"),
			ResourceIdentity: serverIdentity("server"),
		},
		{
			App: App, Name: ToolDetectAuth, Kind: connectors.KindRead, Bounds: bounds,
			Description: "Detect how an MCP server at an https URL authenticates (none, OAuth with dynamic client registration or a " +
				"client metadata document, API key, bearer token, headers) and which scopes it asks for, before adding it. The request goes " +
				"through the gateway's network guard; private and internal addresses are refused." + browserNote,
			InputSchema:      schema(`"url":{"type":"string","description":"The server's https URL.","maxLength":2048}`, "url"),
			ResourceIdentity: hostIdentity,
		},
		{
			App: App, Name: ToolAddServer, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write, ResultIDs: serverIDResult,
			Description: "Add an MCP server to this gateway for yourself. It starts private and with every tool disabled: nothing is usable " +
				"until you refresh it (gateway.refresh_server) and approve its tools on the review page in the browser. This tool never " +
				"takes a secret: no API key, token, password or header value; arguments that look like one are refused. Credentials are " +
				"entered in the browser at the returned links (your own on the server page, a shared one on its settings page)." + browserNote,
			InputSchema: schema(`"name":{"type":"string","description":"Short lower-case name (a-z, 0-9, - and _; at most 63); it becomes the prefix of the server's tools.","pattern":"^[a-z0-9_-]{1,63}$"},`+
				`"url":{"type":"string","description":"The server's https URL, or tunnel://<your tunnel id>/<path> for a server behind one of your tunnels.","maxLength":2048},`+
				`"auth_kind":{"type":"string","enum":["oauth","api_key","bearer","headers","none"],"description":"How the server authenticates (see gateway.detect_auth)."},`+
				`"credential_mode":{"type":"string","enum":["per_user","shared"],"description":"per_user: every user brings their own credential; shared: one credential you set in the browser for everyone (not for oauth)."},`+
				`"api_key_in":{"type":"string","enum":["header","query"],"description":"api_key only: send the key in a header (default) or a query parameter."},`+
				`"api_key_name":{"type":"string","description":"api_key only: the header or query parameter name (default header X-API-Key). A name, never the key."},`+
				`"static_header_names":{"type":"array","items":{"type":"string"},"maxItems":50,"description":"Names of extra request headers whose values each user enters in the browser. Names only, never values."}`,
				"name", "url", "auth_kind", "credential_mode"),
			ResourceIdentity: serverIdentity("name"),
		},
		{
			App: App, Name: ToolRefreshServer, Kind: connectors.KindRead, Bounds: bounds,
			Description: "Rediscover the tools, resources and prompts of an MCP server you own, with your credential, and store them as a " +
				"pending snapshot for review. Returns what changed (added, changed, removed) and the review link. It never approves anything: " +
				"new and changed tools stay disabled until you approve them on the review page in the browser." + browserNote,
			InputSchema:      schema(serverArg, "server"),
			ResourceIdentity: serverIdentity("server"),
		},
		{
			App: App, Name: ToolConnectLink, Kind: connectors.KindRead, Bounds: bounds,
			Description: "Get the portal link where you connect (or reconnect) to an MCP server: the sign-in for OAuth servers, the " +
				"credential form for API key, bearer and header servers." + browserNote,
			InputSchema:      schema(serverArg, "server"),
			ResourceIdentity: serverIdentity("server"),
		},
		{
			App: App, Name: ToolDeleteServer, Kind: connectors.KindWrite, Bounds: bounds, Reconcile: write, ResultIDs: serverIDResult,
			Description: "Delete an MCP server you own: its tools disappear for everyone and all connections to it are deleted. Every call " +
				"needs your approval first (the gateway answers \"approval required\" with a link; approve in the browser, then retry with " +
				"approval_id)." + browserNote,
			InputSchema:      schema(serverArg, "server"),
			ResourceIdentity: serverIdentity("server"),
		},
	}
	if c.d.Rates != nil {
		out = append(out, c.rateTools(bounds, write)...)
	}
	return out
}

// Call implements connectors.Connector.
func (c *Connector) Call(ctx context.Context, call connectors.Call) (connectors.Result, error) {
	user := call.Principal.UserID
	if c.d.Gate != nil && !c.d.Gate.Active(ctx, user) {
		return connectors.Result{}, mcp.ErrToolNotFound(call.Tool)
	}
	name, ok := strings.CutPrefix(call.Tool, App+".")
	if !ok {
		return connectors.Result{}, connectors.ErrUnknownTool
	}
	args := call.Args
	if args == nil {
		args = map[string]any{}
	}
	switch name {
	case ToolListServers:
		return c.listServers(ctx, user, args)
	case ToolGetServer:
		return c.getServer(ctx, user, args)
	case ToolDetectAuth:
		return c.detectAuth(ctx, user, args)
	case ToolAddServer:
		return c.addServer(ctx, user, args)
	case ToolRefreshServer:
		return c.refreshServer(ctx, user, args)
	case ToolConnectLink:
		return c.connectLink(ctx, user, args)
	case ToolDeleteServer:
		return c.deleteServer(ctx, user, args)
	case ToolGetRateLimits:
		return c.getRateLimits(ctx, user, args)
	case ToolSetMyRateLimit:
		return c.setMyRateLimit(ctx, user, args)
	case ToolSetOrgRateLimits:
		return c.setOrgRateLimits(ctx, user, args)
	case ToolSetAppRateLimit:
		return c.setAppRateLimit(ctx, user, args)
	case ToolSetUserRateLimit:
		return c.setUserRateLimit(ctx, user, args)
	}
	return connectors.Result{}, connectors.ErrUnknownTool
}

// link is an absolute portal link.
func (c *Connector) link(path string) string { return c.base + path }
