package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Store is the persistence the Manager needs. NewPostgresStore is the
// production implementation; its comments say which scope each call runs
// in (system = WithJobs, user = WithUser, so row-level security applies).
type Store interface {
	// ListServers returns every server (system).
	ListServers(ctx context.Context) ([]store.MCPServer, error)
	// GetServer returns one server (system); store.ErrNotFound when gone.
	GetServer(ctx context.Context, id string) (*store.MCPServer, error)
	// VisibleServerIDs returns the servers userID may use: their own and
	// those published to a role they hold (user scope, the source of
	// truth for visibility).
	VisibleServerIDs(ctx context.Context, userID string) ([]string, error)
	// UserConnection returns userID's credential row for the server (user
	// scope); store.ErrNotFound when there is none.
	UserConnection(ctx context.Context, userID, serverID string) (*store.MCPUserConnection, error)
	// AnchorAccount returns the id of the v1 connections row that stands
	// for userID's use of the server (created on first use, revived when
	// revoked) with the given label: approvals, ledger operations and
	// audit rows reference it.
	AnchorAccount(ctx context.Context, userID string, server *store.MCPServer, label string) (string, error)
	// CreateServer inserts a private server owned by s.OwnerUserID (user
	// scope).
	CreateServer(ctx context.Context, s *store.MCPServer) error
	// UpdateServer rewrites a server's editable settings as userID (user
	// scope: only the owner may).
	UpdateServer(ctx context.Context, userID string, s *store.MCPServer) error
}

// Snapshots is the part of *snapshot.Service the Manager uses.
type Snapshots interface {
	Current(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
	Allowed(ctx context.Context, a snapshot.Actor, serverID, tool string, args map[string]any) (snapshot.Tool, snapshot.Kind, error)
}

// Credentials is the part of *auth.Service the Manager uses.
type Credentials interface {
	ForUser(ctx context.Context, server *store.MCPServer, userID string) (auth.Authorizer, error)
}

// Tunnels is the part of *tunnel.Service the Manager uses.
type Tunnels interface {
	Authorize(ctx context.Context, ownerID, tunnelID string) error
	HTTPClient(base *http.Client) *http.Client
}

// AddServerPermission says whether a user may add MCP servers
// (*permissions.Service: admin, or a role with "May add MCP servers").
type AddServerPermission interface {
	CanAddServers(ctx context.Context, userID string) bool
}

// Defaults.
const (
	// DefaultVisibilityTTL bounds how long a user's visible servers are
	// cached. ServerChanged drops the cache at once; role assignment
	// changes are seen within the TTL (calls re-check through RLS anyway).
	DefaultVisibilityTTL = 10 * time.Second
	// DefaultReloadInterval is how often Run reloads every server (other
	// replicas' changes, missed hooks).
	DefaultReloadInterval = time.Minute
)

// Options configure New. Registry, Store, Snapshots, Credentials and
// HTTPClient are required.
type Options struct {
	Registry    *connectors.Registry
	Store       Store
	Snapshots   Snapshots
	Credentials Credentials
	// Permissions gates CreateServer (decision bnneszc1).
	Permissions AddServerPermission
	// Tunnels serves tunnel:// servers; nil refuses them
	// (tunnel_unavailable).
	Tunnels Tunnels
	// HTTPClient is netguard's client: every non-tunnel upstream request
	// goes through it.
	HTTPClient *http.Client
	// BaseURL is GATEWAY_BASE_URL; connect hints point at
	// BaseURL/servers/<id>.
	BaseURL string
	// CredentialLinks is GATEWAY_CREDENTIAL_LINKS_ENABLED: credential
	// problems the caller can fix answer -32042 with a link under BaseURL
	// (credlinks.go). Off: every answer is what it was before the flag.
	CredentialLinks bool
	// UpstreamElicitation is GATEWAY_UPSTREAM_ELICITATION_ENABLED: upstream
	// URL elicitations are relayed through Elicitations and the /elicit
	// interstitial under BaseURL (relay.go). Off, or without Elicitations:
	// no client declares the capability and every answer is what it was.
	UpstreamElicitation bool
	// Elicitations stores relayed elicitations (*elicit.Service).
	Elicitations Elicitations
	// Version is reported to upstream servers as the client version.
	Version string
	// Timeout bounds each upstream operation (client default when 0).
	Timeout time.Duration
	// CallTimeout bounds tools/call only (Timeout when 0;
	// GATEWAY_FEDERATION_CALL_TIMEOUT). The HTTPClient's transport must
	// not cut it first: Wire raises netguard's and the tunnel's response
	// header timeouts to match (upstreamHeaderTimeout).
	CallTimeout time.Duration
	// VisibilityTTL: DefaultVisibilityTTL when 0.
	VisibilityTTL time.Duration
	// OnChange runs after every ServerChanged (cmd/gateway invalidates the
	// compiled policy: the owner layer of private servers).
	OnChange func()
	// OnCall receives each upstream operation's class and latency.
	OnCall func(client.CallInfo)
	Log    *slog.Logger
	// Now is the clock (tests); default time.Now.
	Now func() time.Time
}

// Manager puts user-added MCP servers into the gateway: it keeps the
// registry's server apps in step with the approved snapshots, decides
// which users may see them, supplies their accounts and runs their tool
// calls upstream (call.go).
type Manager struct {
	o   Options
	log *slog.Logger

	loadMu sync.Mutex // one Load at a time

	mu   sync.RWMutex
	apps map[string]*entry // by app (server name)

	visMu sync.Mutex
	vis   map[string]visEntry // by user
}

// entry is a loaded server: its row and approved snapshot as of the last
// load (resources.go lists the snapshot's resources, templates and
// prompts).
type entry struct {
	server  store.MCPServer
	snap    *snapshot.Snapshot
	content *snapshot.ContentReview // nil: approved before the toggles, all enabled
	// upstream maps each registered tool name to its upstream name.
	upstream map[string]string
}

type visEntry struct {
	ids map[string]bool
	at  time.Time
}

// New builds a Manager. Nothing is loaded until Load.
func New(o Options) (*Manager, error) {
	switch {
	case o.Registry == nil:
		return nil, errors.New("federation: registry is required")
	case o.Store == nil:
		return nil, errors.New("federation: store is required")
	case o.Snapshots == nil:
		return nil, errors.New("federation: snapshots are required")
	case o.Credentials == nil:
		return nil, errors.New("federation: credentials are required")
	case o.Permissions == nil:
		return nil, errors.New("federation: the add-server permission check is required")
	case o.HTTPClient == nil:
		return nil, errors.New("federation: the netguard HTTP client is required")
	}
	if o.VisibilityTTL <= 0 {
		o.VisibilityTTL = DefaultVisibilityTTL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &Manager{o: o, log: o.Log, apps: map[string]*entry{}, vis: map[string]visEntry{}}, nil
}

// Load reads every active server with an approved snapshot (as the
// system: the loader serves all users) and makes the registry's server
// apps exactly those servers' enabled tools. Servers with reserved names,
// none approved, or another status get no tools. A server whose snapshot
// cannot be read this time keeps what it had. The errors of individual
// servers are joined; the rest still loads.
func (m *Manager) Load(ctx context.Context) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	servers, err := m.o.Store.ListServers(ctx)
	if err != nil {
		return fmt.Errorf("federation: list servers: %w", err)
	}
	m.mu.RLock()
	prev := m.apps
	m.mu.RUnlock()
	next := map[string]*entry{}
	var errs []error
	for _, s := range servers {
		if s.Status != store.MCPServerActive {
			continue
		}
		if err := ValidateServerName(s.Name); err != nil {
			m.log.Warn("federated server skipped: name not allowed", "event", "federation.server_skipped", "server_id", s.ID, "reason", err.Error())
			continue
		}
		rec, err := m.o.Snapshots.Current(ctx, snapshot.System(), s.ID)
		switch {
		case errors.Is(err, snapshot.ErrNoSnapshot):
			continue
		case err != nil:
			errs = append(errs, fmt.Errorf("federation: server %s: snapshot: %w", s.ID, err))
			if old, ok := prev[s.Name]; ok && old.server.ID == s.ID {
				next[s.Name] = old
			}
			continue
		}
		tools, skipped, upstream := buildToolsNamed(&s, rec, m.handlerFor(s.ID))
		if len(skipped) > 0 {
			m.log.Warn("federated tools skipped (name collision, unusable name or schema)", "event", "federation.tools_skipped",
				"server", s.Name, "server_id", s.ID, "count", len(skipped))
		}
		if err := m.o.Registry.AddServerTools(s.Name, tools); err != nil {
			errs = append(errs, fmt.Errorf("federation: server %s: register: %w", s.ID, err))
			continue
		}
		next[s.Name] = &entry{server: s, snap: rec.Snapshot, content: rec.Content, upstream: upstream}
	}
	for _, app := range m.o.Registry.ServerApps() {
		if _, ok := next[app]; !ok {
			m.o.Registry.RemoveServerTools(app)
		}
	}
	m.mu.Lock()
	m.apps = next
	m.mu.Unlock()
	m.log.Debug("federated servers loaded", "event", "federation.loaded", "servers", len(next))
	return errors.Join(errs...)
}

// ServerChanged is the hook the servers portal (and admin pages) call
// after creating, editing, publishing, unpublishing, disabling or
// deleting a server, approving or changing a snapshot review, or changing
// a server's credentials: it reloads the server apps, drops the
// visibility cache and runs Options.OnChange (the policy's owner layer).
// serverID is for the log; every server is reloaded.
func (m *Manager) ServerChanged(ctx context.Context, serverID string) error {
	m.dropVisibility()
	err := m.Load(ctx)
	if m.o.OnChange != nil {
		m.o.OnChange()
	}
	if err != nil {
		m.log.Error("federated servers reload failed", "event", "federation.reload_failed", "server_id", serverID,
			"error", observability.RedactError(err))
	}
	return err
}

// Run reloads every interval (DefaultReloadInterval when 0) until ctx
// ends, so changes made on another replica arrive without a restart.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultReloadInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.dropVisibility()
			if err := m.Load(ctx); err != nil && ctx.Err() == nil {
				m.log.Error("federated servers reload failed", "event", "federation.reload_failed", "error", observability.RedactError(err))
			}
		}
	}
}

// CreateServer checks that s.OwnerUserID may add MCP servers
// (permissions.ErrNotPermitted otherwise; defense in depth behind the
// portal, decision bnneszc1), validates the name (ValidateServerName:
// reserved built-in names are refused), stores the private server for
// s.OwnerUserID and reloads. The gateway.* tools create servers through it.
func (m *Manager) CreateServer(ctx context.Context, s *store.MCPServer) error {
	if !m.o.Permissions.CanAddServers(ctx, s.OwnerUserID) {
		m.log.Info("server create refused: not permitted", "event", "federation.create_refused", "user_id", s.OwnerUserID)
		return permissions.ErrNotPermitted
	}
	if err := ValidateServerName(s.Name); err != nil {
		return err
	}
	if err := m.o.Store.CreateServer(ctx, s); err != nil {
		return err
	}
	_ = m.ServerChanged(ctx, s.ID)
	return nil
}

// UpdateServer validates the (possibly new) name, stores the server's
// editable settings as userID and reloads. A published server's address
// and sign-in settings cannot change on this (request) path:
// store.ErrMCPServerLocked (schema 17, decision q7vbxlyk point 3).
func (m *Manager) UpdateServer(ctx context.Context, userID string, s *store.MCPServer) error {
	if err := ValidateServerName(s.Name); err != nil {
		return err
	}
	if err := m.o.Store.UpdateServer(ctx, userID, s); err != nil {
		return err
	}
	_ = m.ServerChanged(ctx, s.ID)
	return nil
}

// entry returns the loaded server of app.
func (m *Manager) entry(app string) (*entry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.apps[app]
	return e, ok
}

// canSee reports whether userID may use serverID, from a per-user cache
// of VisibleServerIDs. Errors fail closed.
func (m *Manager) canSee(ctx context.Context, userID, serverID string) bool {
	if userID == "" {
		return false
	}
	now := m.o.Now()
	m.visMu.Lock()
	v, ok := m.vis[userID]
	m.visMu.Unlock()
	if !ok || now.Sub(v.at) >= m.o.VisibilityTTL {
		ids, err := m.o.Store.VisibleServerIDs(ctx, userID)
		if err != nil {
			m.log.Error("visible servers lookup failed; federated tools hidden", "event", "federation.visibility_failed",
				"user_id", userID, "error", observability.RedactError(err))
			return false
		}
		v = visEntry{ids: make(map[string]bool, len(ids)), at: now}
		for _, id := range ids {
			v.ids[id] = true
		}
		m.visMu.Lock()
		m.vis[userID] = v
		m.visMu.Unlock()
	}
	return v.ids[serverID]
}

func (m *Manager) dropVisibility() {
	m.visMu.Lock()
	m.vis = map[string]visEntry{}
	m.visMu.Unlock()
}

// Visibility wraps base (the policy visibility) for server apps: a
// federated tool is visible only to users who may use its server (owner
// of a private server, or holder of a role it is published to) and then
// only when base also says so. Built-in tools are base's alone.
func (m *Manager) Visibility(base mcp.Visibility) mcp.Visibility {
	return visibility{m: m, base: base}
}

type visibility struct {
	m    *Manager
	base mcp.Visibility
}

func (v visibility) Visible(ctx context.Context, p *tokens.Principal, tool connectors.Tool) bool {
	if !v.m.o.Registry.IsServerApp(tool.App) {
		return v.base.Visible(ctx, p, tool)
	}
	if p == nil || !v.m.serverToolUsable(ctx, p.UserID, tool) {
		return false
	}
	return v.base.Visible(ctx, p, tool)
}

// Accounts wraps fallback (the connections table) for server apps: a user
// who may use the server gets one account, the anchor connection of their
// use of it. Per-user credential servers (other than auth kind none)
// need the user's own credential row first: without one, or with a
// revoked one, there is no account (the account stage answers
// no_account); a row that needs reconnecting still yields the account,
// so the call can say "reconnect". Labels: personal for per-user
// credentials, company for shared or no credentials.
func (m *Manager) Accounts(fallback connectors.AccountSource) connectors.AccountSource {
	return accounts{m: m, fallback: fallback}
}

type accounts struct {
	m        *Manager
	fallback connectors.AccountSource
}

func (a accounts) ListAccounts(ctx context.Context, userID, app string) ([]connectors.Account, error) {
	if !a.m.o.Registry.IsServerApp(app) {
		if a.fallback == nil {
			return nil, nil
		}
		return a.fallback.ListAccounts(ctx, userID, app)
	}
	e, ok := a.m.entry(app)
	if !ok || !a.m.canSee(ctx, userID, e.server.ID) {
		return nil, nil
	}
	s := e.server
	label := store.AccountCompany
	if s.CredentialMode == store.MCPCredentialPerUser && s.AuthKind != store.MCPAuthNone {
		c, err := a.m.o.Store.UserConnection(ctx, userID, s.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("federation: connection of %s: %w", s.Name, err)
		case c.Status == store.MCPConnectionRevoked:
			return nil, nil
		}
		label = store.AccountPersonal
	}
	id, err := a.m.o.Store.AnchorAccount(ctx, userID, &s, label)
	if err != nil {
		return nil, fmt.Errorf("federation: account for %s: %w", s.Name, err)
	}
	return []connectors.Account{{ID: id, Label: connectors.AccountLabel(label), DisplayName: s.Name, App: app}}, nil
}
