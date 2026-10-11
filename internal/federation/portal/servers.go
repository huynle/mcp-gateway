package portal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// authConfig and headerConfig mirror the non-secret settings
// internal/federation/auth reads from mcp_servers.auth_config and
// header_config.
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

func parseAuthConfig(raw json.RawMessage) authConfig {
	var c authConfig
	_ = json.Unmarshal(raw, &c)
	return c
}

func parseHeaderConfig(raw json.RawMessage) headerConfig {
	var c headerConfig
	_ = json.Unmarshal(raw, &c)
	return c
}

// connState is the caller's connection to a server as shown on the pages.
type connState struct {
	Label string
	Class string // css class: active, needs_reconnect, revoked, none
	// Needed: the server takes a credential from each user.
	Needed bool
}

// needsUserCredential: every user brings their own credential (per-user
// mode with an auth kind other than none) or values for per-user headers.
func needsUserCredential(s *store.MCPServer) bool {
	if len(parseHeaderConfig(s.HeaderConfig).PerUser) > 0 {
		return true
	}
	return s.CredentialMode == store.MCPCredentialPerUser && slices.Contains(
		[]string{store.MCPAuthOAuth, store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders}, s.AuthKind)
}

func connectionState(s *store.MCPServer, conn *store.MCPUserConnection) connState {
	if !needsUserCredential(s) {
		if s.AuthKind == store.MCPAuthNone {
			return connState{Label: "no connection needed", Class: "none"}
		}
		return connState{Label: "shared credential", Class: "company"}
	}
	switch {
	case conn == nil || conn.Status == store.MCPConnectionRevoked:
		return connState{Label: "needs connect", Class: "revoked", Needed: true}
	case conn.Status == store.MCPConnectionNeedsReconnect:
		return connState{Label: "needs reconnect", Class: "needs_reconnect", Needed: true}
	default:
		return connState{Label: "connected", Class: "active", Needed: true}
	}
}

// serverRow is one server on the list page.
type serverRow struct {
	ID, Name, URL  string
	Mine           bool
	Published      bool
	Status         string
	ErrorClass     string
	AuthKind       string
	CredentialMode string
	Conn           connState
	PendingReview  bool
}

type tunnelRow struct {
	ID, Name   string
	Online     bool
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

// newTunnel is a tunnel just created: its token is shown on this response
// only.
type newTunnel struct {
	ID, Name, Token, Command, EnvCommand string
}

type listData struct {
	Title     string
	Caller    caller
	Mine      []serverRow
	Shared    []serverRow
	Tunnels   []tunnelRow
	NewTunnel *newTunnel
	Notice    string
	Error     string
}

func (p *Portal) list(w http.ResponseWriter, r *http.Request, c caller) {
	data, err := p.loadList(r.Context(), c)
	if err != nil {
		p.fail(w, r, "list servers", err)
		return
	}
	switch q := r.URL.Query(); {
	case q.Get("deleted") != "":
		data.Notice = "Server deleted."
	case q.Get("revoked") != "":
		data.Notice = "Tunnel revoked."
	}
	p.render(w, r, http.StatusOK, "servers.html", data)
}

func (p *Portal) loadList(ctx context.Context, c caller) (listData, error) {
	data := listData{Title: "Servers", Caller: c}
	servers, err := p.d.Store.ListVisibleServers(ctx, c.UserID)
	if err != nil {
		return data, err
	}
	conns, err := p.d.Store.ListConnections(ctx, c.UserID)
	if err != nil {
		return data, err
	}
	byServer := make(map[string]*store.MCPUserConnection, len(conns))
	for i := range conns {
		byServer[conns[i].ServerID] = &conns[i]
	}
	tunnels, err := p.d.Store.ListTunnels(ctx, c.UserID)
	if err != nil {
		return data, err
	}
	names := map[string]string{}
	for _, t := range tunnels {
		names[t.ID] = t.Name
		if t.RevokedAt == nil {
			data.Tunnels = append(data.Tunnels, tunnelRow{ID: t.ID, Name: t.Name, Online: p.d.Tunnels.Online(t.ID), CreatedAt: t.CreatedAt, LastSeenAt: t.LastSeenAt})
		}
	}
	for i := range servers {
		s := &servers[i]
		row := serverRow{
			ID: s.ID, Name: s.Name, URL: displayURL(s.URL, names), Mine: s.OwnerUserID == c.UserID,
			Published: s.Audience == store.MCPAudiencePublished, Status: s.Status, AuthKind: s.AuthKind,
			CredentialMode: s.CredentialMode, Conn: connectionState(s, byServer[s.ID]),
			PendingReview: p.pendingReview(ctx, c, s.ID),
		}
		if s.LastErrorClass != nil {
			row.ErrorClass = *s.LastErrorClass
		}
		if row.Mine {
			data.Mine = append(data.Mine, row)
		} else {
			data.Shared = append(data.Shared, row)
		}
	}
	return data, nil
}

// pendingReview: the newest snapshot is not the approved one.
func (p *Portal) pendingReview(ctx context.Context, c caller, serverID string) bool {
	latest, err := p.d.Snapshots.Latest(ctx, c.snapActor(), serverID)
	if err != nil {
		if !errors.Is(err, snapshot.ErrNoSnapshot) {
			p.log.Warn("latest snapshot", "event", "federation.portal_snapshot_failed", "server_id", serverID, "error", err.Error())
		}
		return false
	}
	current, err := p.d.Snapshots.Current(ctx, c.snapActor(), serverID)
	return err != nil || current.Version != latest.Version
}

// displayURL shows a tunnel URL as the tunnel's name.
func displayURL(raw string, tunnelNames map[string]string) string {
	if !tunnel.IsTunnelURL(raw) {
		return raw
	}
	id, path, err := tunnel.ParseURL(raw)
	if err != nil {
		return raw
	}
	if n, ok := tunnelNames[id]; ok {
		return "tunnel “" + n + "” " + path
	}
	return "tunnel " + path
}
