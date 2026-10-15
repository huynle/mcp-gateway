package gatewaytools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// serverView is one server as list_servers and get_server show it: its
// non-secret settings, the caller's state and portal links.
type serverView struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	URLHost        string            `json:"url_host"`
	Owner          bool              `json:"owner"`
	Audience       string            `json:"audience"`
	Status         string            `json:"status"`
	LastErrorClass string            `json:"last_error_class,omitempty"`
	AuthKind       string            `json:"auth_kind"`
	CredentialMode string            `json:"credential_mode"`
	Connection     string            `json:"connection"`
	PendingReview  bool              `json:"pending_review"`
	ApprovedTools  int               `json:"approved_tools"`
	Links          map[string]string `json:"links"`
}

// serverDetail is get_server's answer.
type serverDetail struct {
	serverView
	APIKeyPlacement string     `json:"api_key_placement,omitempty"`
	Scopes          []string   `json:"scopes,omitempty"`
	StaticHeaders   []string   `json:"static_header_names,omitempty"`
	PerUserHeaders  []string   `json:"per_user_header_names,omitempty"`
	ApprovedVersion int        `json:"approved_version,omitempty"`
	LatestVersion   int        `json:"latest_version,omitempty"`
	NextSteps       []nextStep `json:"next_steps"`
}

// nextStep is one thing to do before the server's tools are usable.
type nextStep struct {
	Step string `json:"step"`
	Link string `json:"link,omitempty"`
	Note string `json:"note"`
}

// snapState is what the snapshots say about a server for the caller.
type snapState struct {
	approved, latest int // versions; 0 = none
	enabled          int
}

func (c *Connector) snapState(ctx context.Context, user, serverID string) snapState {
	var st snapState
	a := snapshot.Actor{UserID: user}
	if cur, err := c.d.Snapshots.Current(ctx, a, serverID); err == nil {
		st.approved = cur.Version
		for _, rv := range cur.Review {
			if rv.Enabled {
				st.enabled++
			}
		}
	}
	if latest, err := c.d.Snapshots.Latest(ctx, a, serverID); err == nil {
		st.latest = latest.Version
	}
	return st
}

func (s snapState) pending() bool { return s.latest != 0 && s.latest != s.approved }

// connectionOf finds the caller's connection to serverID.
func connectionOf(conns []store.MCPUserConnection, serverID string) *store.MCPUserConnection {
	for i := range conns {
		if conns[i].ServerID == serverID {
			return &conns[i]
		}
	}
	return nil
}

// view renders s for user.
func (c *Connector) view(ctx context.Context, user string, s *store.MCPServer, conn *store.MCPUserConnection, tunnels map[string]string) (serverView, snapState) {
	st := c.snapState(ctx, user, s.ID)
	label, needed := fedportal.ConnectionState(s, conn)
	v := serverView{
		ID: s.ID, Name: s.Name, URLHost: urlHost(s.URL, tunnels), Owner: s.OwnerUserID == user, Audience: s.Audience, Status: s.Status,
		AuthKind: s.AuthKind, CredentialMode: s.CredentialMode, Connection: label, PendingReview: st.pending(), ApprovedTools: st.enabled,
		Links: map[string]string{"server": c.link(fedportal.ServerPath(s.ID))},
	}
	if s.LastErrorClass != nil {
		v.LastErrorClass = *s.LastErrorClass
	}
	if v.Owner {
		v.Links["review"] = c.link(fedportal.ReviewPath(s.ID))
		v.Links["settings"] = c.link(fedportal.EditPath(s.ID))
	}
	if needed {
		v.Links["connect"] = c.connectLinkOf(s)
	}
	return v, st
}

// connectLinkOf is where the caller connects to s: the OAuth sign-in, or
// the credential form on the server page.
func (c *Connector) connectLinkOf(s *store.MCPServer) string {
	if s.CredentialMode == store.MCPCredentialPerUser && s.AuthKind == store.MCPAuthOAuth {
		return c.link(fedportal.ConnectPath(s.ID))
	}
	return c.link(fedportal.ConnectionPath(s.ID))
}

// urlHost is the address host, or the tunnel's name for tunnel servers.
func urlHost(raw string, tunnels map[string]string) string {
	if id, _, err := tunnel.ParseURL(raw); err == nil {
		if n, ok := tunnels[id]; ok {
			return "tunnel " + n
		}
		return "tunnel"
	}
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return ""
}

func (c *Connector) tunnelNames(ctx context.Context, user string) map[string]string {
	out := map[string]string{}
	ts, err := c.d.Servers.ListTunnels(ctx, user)
	if err != nil {
		c.log.Warn("list tunnels", "event", "gateway_tools.tunnels_failed", "error", err.Error())
		return out
	}
	for _, t := range ts {
		out[t.ID] = t.Name
	}
	return out
}

// errServerNotFound is the one answer for a server that does not exist,
// that the caller cannot see, or (owner-only tools) that the caller does
// not own: the caller learns nothing about other users' servers.
func errServerNotFound(arg string, ownerOnly bool) error {
	if !serverNameRE.MatchString(arg) && !uuidRE.MatchString(arg) {
		arg = "?"
	}
	if ownerOnly {
		return fail("server_not_found", "no server %q that you own; gateway.list_servers lists yours", arg)
	}
	return fail("server_not_found", "no server %q visible to you; gateway.list_servers lists them", arg)
}

// findServer resolves the "server" argument (name or ID) among the
// servers user can see; ownerOnly also requires ownership.
func (c *Connector) findServer(ctx context.Context, user string, args map[string]any, ownerOnly bool) (*store.MCPServer, error) {
	if err := checkArgs(args, "server"); err != nil {
		return nil, err
	}
	arg, err := requiredString(args, "server")
	if err != nil {
		return nil, err
	}
	return c.lookupServer(ctx, user, arg, ownerOnly)
}

// lookupServer resolves a server name or ID among the servers user can
// see; ownerOnly also requires ownership.
func (c *Connector) lookupServer(ctx context.Context, user, arg string, ownerOnly bool) (*store.MCPServer, error) {
	var s *store.MCPServer
	var err error
	switch {
	case uuidRE.MatchString(arg):
		s, err = c.d.Servers.GetServer(ctx, user, arg)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errServerNotFound(arg, ownerOnly)
		}
		if err != nil {
			return nil, fmt.Errorf("gateway tools: load server: %w", err)
		}
	case serverNameRE.MatchString(arg):
		list, err := c.d.Servers.ListVisibleServers(ctx, user)
		if err != nil {
			return nil, fmt.Errorf("gateway tools: list servers: %w", err)
		}
		i := slices.IndexFunc(list, func(s store.MCPServer) bool { return s.Name == arg })
		if i < 0 {
			return nil, errServerNotFound(arg, ownerOnly)
		}
		s = &list[i]
	default:
		return nil, errServerNotFound(arg, ownerOnly)
	}
	if ownerOnly && s.OwnerUserID != user {
		return nil, errServerNotFound(arg, ownerOnly)
	}
	return s, nil
}

func (c *Connector) listServers(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	if err := checkArgs(args); err != nil {
		return connectors.Result{}, err
	}
	servers, err := c.d.Servers.ListVisibleServers(ctx, user)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("gateway tools: list servers: %w", err)
	}
	conns, err := c.d.Servers.ListConnections(ctx, user)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("gateway tools: list connections: %w", err)
	}
	tunnels := c.tunnelNames(ctx, user)
	out := make([]serverView, 0, len(servers))
	for i := range servers {
		v, _ := c.view(ctx, user, &servers[i], connectionOf(conns, servers[i].ID), tunnels)
		out = append(out, v)
	}
	return connectors.Result{Content: map[string]any{
		"servers":     out,
		"add_server":  c.link("/servers/new"),
		"servers_url": c.link("/servers"),
	}, Empty: len(out) == 0}, nil
}

func (c *Connector) getServer(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	s, err := c.findServer(ctx, user, args, false)
	if err != nil {
		return connectors.Result{}, err
	}
	d, err := c.detail(ctx, user, s)
	if err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: d}, nil
}

// detail renders get_server's answer (also add_server's).
func (c *Connector) detail(ctx context.Context, user string, s *store.MCPServer) (serverDetail, error) {
	conns, err := c.d.Servers.ListConnections(ctx, user)
	if err != nil {
		return serverDetail{}, fmt.Errorf("gateway tools: list connections: %w", err)
	}
	conn := connectionOf(conns, s.ID)
	v, st := c.view(ctx, user, s, conn, c.tunnelNames(ctx, user))
	d := serverDetail{serverView: v, ApprovedVersion: st.approved, LatestVersion: st.latest}
	var ac authConfig
	_ = json.Unmarshal(s.AuthConfig, &ac)
	d.Scopes = ac.Scopes
	if s.AuthKind == store.MCPAuthAPIKey {
		switch {
		case ac.APIKey != nil && ac.APIKey.Query != "":
			d.APIKeyPlacement = "query parameter " + ac.APIKey.Query
		case ac.APIKey != nil && ac.APIKey.Header != "":
			d.APIKeyPlacement = "header " + ac.APIKey.Header
		default:
			d.APIKeyPlacement = "header " + auth.DefaultAPIKeyHeader
		}
	}
	var hc headerConfig
	_ = json.Unmarshal(s.HeaderConfig, &hc)
	for k := range hc.Static {
		d.StaticHeaders = append(d.StaticHeaders, k)
	}
	slices.Sort(d.StaticHeaders)
	d.PerUserHeaders = hc.PerUser
	var info fedportal.CredentialInfo
	if v.Owner {
		if info, err = c.d.Servers.CredentialInfo(ctx, user, s.ID); err != nil {
			return serverDetail{}, fmt.Errorf("gateway tools: credential info: %w", err)
		}
	}
	d.NextSteps = c.nextSteps(s, conn, v, st, info)
	return d, nil
}

// nextSteps says what is left before the server's tools are usable, each
// with its portal link.
func (c *Connector) nextSteps(s *store.MCPServer, conn *store.MCPUserConnection, v serverView, st snapState, info fedportal.CredentialInfo) []nextStep {
	steps := []nextStep{}
	if v.Owner && s.CredentialMode == store.MCPCredentialShared && fedportal.SecretKind(s.AuthKind) && !info.SharedSecret {
		steps = append(steps, nextStep{Step: "set_shared_credential", Link: c.link(fedportal.EditPath(s.ID)),
			Note: "The shared credential is set in the browser on the server's settings page; nobody can use the server until it is."})
	}
	if _, needed := fedportal.ConnectionState(s, conn); needed && (conn == nil || conn.Status != store.MCPConnectionActive) {
		switch {
		case s.CredentialMode == store.MCPCredentialPerUser && s.AuthKind == store.MCPAuthOAuth:
			steps = append(steps, nextStep{Step: "connect", Link: c.link(fedportal.ConnectPath(s.ID)),
				Note: "Open the link in the browser to sign in to the server (OAuth)."})
		default:
			steps = append(steps, nextStep{Step: "enter_credential", Link: c.link(fedportal.ConnectionPath(s.ID)),
				Note: "Enter your credential (API key, bearer token or header values) in the browser on the server page."})
		}
	}
	if s.Status != store.MCPServerActive {
		steps = append(steps, nextStep{Step: "inactive", Link: c.link(fedportal.ServerPath(s.ID)),
			Note: "The server is " + s.Status + "; its tools are not available."})
	}
	switch {
	case v.Owner && st.latest == 0:
		steps = append(steps, nextStep{Step: "refresh", Note: "Call gateway.refresh_server to discover the server's tools (after connecting, if needed)."})
	case st.pending() && v.Owner && s.Audience == store.MCPAudiencePrivate:
		steps = append(steps, nextStep{Step: "review", Link: c.link(fedportal.ReviewPath(s.ID)),
			Note: "Review and approve the server's tools in the browser; nothing is enabled until you do."})
	case st.pending():
		steps = append(steps, nextStep{Step: "await_review", Note: "A tool review is pending; an admin approves published servers."})
	}
	if len(steps) == 0 {
		note := "Ready: the approved tools appear as " + s.Name + ".<tool> in your tool list."
		if st.enabled == 0 {
			note = "No tools are enabled; enable them on the review page in the browser."
		}
		steps = append(steps, nextStep{Step: "ready", Link: c.link(fedportal.ReviewPath(s.ID)), Note: note})
	}
	return steps
}

func (c *Connector) connectLink(ctx context.Context, user string, args map[string]any) (connectors.Result, error) {
	s, err := c.findServer(ctx, user, args, false)
	if err != nil {
		return connectors.Result{}, err
	}
	conns, err := c.d.Servers.ListConnections(ctx, user)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("gateway tools: list connections: %w", err)
	}
	label, needed := fedportal.ConnectionState(s, connectionOf(conns, s.ID))
	out := map[string]any{"server": s.Name, "server_id": s.ID, "connection": label}
	switch {
	case !needed && s.AuthKind == store.MCPAuthNone:
		out["link"], out["note"] = c.link(fedportal.ServerPath(s.ID)), "The server needs no connection."
	case !needed:
		out["link"], out["note"] = c.link(fedportal.ServerPath(s.ID)),
			"The server uses a shared credential; there is nothing to connect. Its owner sets the credential in the browser."
	case s.CredentialMode == store.MCPCredentialPerUser && s.AuthKind == store.MCPAuthOAuth:
		out["link"], out["note"] = c.connectLinkOf(s), "Open the link in the browser to sign in to the server (OAuth)."
	default:
		out["link"], out["note"] = c.connectLinkOf(s), "Enter your credential in the browser on the server page; never paste it into the chat."
	}
	return connectors.Result{Content: out}, nil
}

// authConfig and headerConfig are the non-secret settings
// internal/federation/auth reads from mcp_servers (the portal's shape).
type authConfig struct {
	Scopes []string      `json:"scopes,omitempty"`
	APIKey *apiKeyConfig `json:"api_key,omitempty"`
}

type apiKeyConfig struct {
	Header string `json:"header,omitempty"`
	Query  string `json:"query,omitempty"`
}

type headerConfig struct {
	Static  map[string]string `json:"static,omitempty"`
	PerUser []string          `json:"per_user,omitempty"`
}
