package portal

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// serverView is a server's non-secret settings as the pages show them.
type serverView struct {
	ID, Name, URL  string
	Owner          bool
	Published      bool
	Status         string
	ErrorClass     string
	AuthKind       string
	CredentialMode string
	APIKeyPlace    string
	Scopes         []string
	StaticHeaders  []string // names only
	PerUserHeaders []string
}

func (p *Portal) view(ctx context.Context, c caller, s *store.MCPServer) serverView {
	v := serverView{
		ID: s.ID, Name: s.Name, URL: s.URL, Owner: s.OwnerUserID == c.UserID, Published: s.Audience == store.MCPAudiencePublished,
		Status: s.Status, AuthKind: s.AuthKind, CredentialMode: s.CredentialMode,
	}
	if tunnel.IsTunnelURL(s.URL) {
		names := map[string]string{}
		if v.Owner {
			if ts, err := p.d.Store.ListTunnels(ctx, c.UserID); err == nil {
				for _, t := range ts {
					names[t.ID] = t.Name
				}
			}
		}
		v.URL = displayURL(s.URL, names)
	}
	if s.LastErrorClass != nil {
		v.ErrorClass = *s.LastErrorClass
	}
	ac := parseAuthConfig(s.AuthConfig)
	v.Scopes = ac.Scopes
	if s.AuthKind == store.MCPAuthAPIKey {
		switch {
		case ac.APIKey != nil && ac.APIKey.Query != "":
			v.APIKeyPlace = "query parameter " + ac.APIKey.Query
		case ac.APIKey != nil && ac.APIKey.Header != "":
			v.APIKeyPlace = "header " + ac.APIKey.Header
		default:
			v.APIKeyPlace = "header " + auth.DefaultAPIKeyHeader
		}
	}
	hc := parseHeaderConfig(s.HeaderConfig)
	for k := range hc.Static {
		v.StaticHeaders = append(v.StaticHeaders, k)
	}
	slices.Sort(v.StaticHeaders)
	v.PerUserHeaders = hc.PerUser
	return v
}

// snapshotSummary is the approved snapshot in one line.
type snapshotSummary struct {
	Version   int
	Tools     int
	Enabled   int
	Resources int
	Prompts   int
}

type detailData struct {
	Title  string
	Caller caller
	Server serverView
	Conn   connState
	// Connected: the caller has a connection row (Disconnect applies).
	Connected bool
	// OAuth: connect through the authorization server.
	OAuth bool
	// CredentialField: the caller's own credential field (api_key, bearer,
	// headers), or "" when the server takes none from users.
	CredentialField string
	Info            CredentialInfo
	Current         *snapshotSummary
	// Approval is the approved snapshot's approval modes (nil when none
	// is approved), with the edit form for the owner of a private server.
	Approval      *ApprovalView
	PendingReview bool
	Notice        string
	Error         string
}

func (p *Portal) detail(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	data, err := p.loadDetail(r.Context(), c, s)
	if err != nil {
		p.fail(w, r, "server detail", err)
		return
	}
	switch q := r.URL.Query(); {
	case q.Get("created") != "":
		data.Notice = "Server added. Refresh it to discover its tools, then review them."
	case q.Get("saved") != "":
		data.Notice = "Saved."
	case q.Get("connected") != "":
		data.Notice = "Credential saved."
	case q.Get("disconnected") != "":
		data.Notice = "Disconnected. Your credential for this server was deleted."
	case q.Get("approved") != "":
		data.Notice = "Review saved. Enabled tools are available through the gateway."
	case q.Get("modes") != "":
		data.Notice = "Approval modes saved."
	}
	p.render(w, r, http.StatusOK, "server.html", data)
}

func (p *Portal) loadDetail(ctx context.Context, c caller, s *store.MCPServer) (detailData, error) {
	d := detailData{Title: s.Name, Caller: c, Server: p.view(ctx, c, s)}
	conns, err := p.d.Store.ListConnections(ctx, c.UserID)
	if err != nil {
		return d, err
	}
	var conn *store.MCPUserConnection
	for i := range conns {
		if conns[i].ServerID == s.ID {
			conn = &conns[i]
		}
	}
	d.Conn = connectionState(s, conn)
	d.Connected = conn != nil
	if s.CredentialMode == store.MCPCredentialPerUser {
		d.OAuth = s.AuthKind == store.MCPAuthOAuth
		if secretKind(s.AuthKind) {
			d.CredentialField = s.AuthKind
		}
	}
	if d.Server.Owner {
		if d.Info, err = p.d.Store.CredentialInfo(ctx, c.UserID, s.ID); err != nil {
			return d, err
		}
	}
	if cur, err := p.d.Snapshots.Current(ctx, c.snapActor(), s.ID); err == nil {
		sum := &snapshotSummary{Version: cur.Version}
		if cur.Snapshot != nil {
			sum.Tools, sum.Resources, sum.Prompts = len(cur.Snapshot.Tools), len(cur.Snapshot.Resources)+len(cur.Snapshot.ResourceTemplates), len(cur.Snapshot.Prompts)
		}
		for _, rv := range cur.Review {
			if rv.Enabled {
				sum.Enabled++
			}
		}
		d.Current = sum
		d.Approval = BuildApprovalView(cur)
		switch {
		case canApprove(c, s):
			d.Approval.Action, d.Approval.CSRFToken = "/servers/"+s.ID+"/approval", c.CSRFToken
		case s.Audience == store.MCPAudiencePublished:
			d.Approval.Note = "An admin sets the approval modes of a published server."
		}
	} else if !errors.Is(err, snapshot.ErrNoSnapshot) {
		return d, err
	}
	d.PendingReview = p.pendingReview(ctx, c, s.ID)
	return d, nil
}

// renderDetailError shows the detail page with an error message.
func (p *Portal) renderDetailError(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer, status int, msg string) {
	data, err := p.loadDetail(r.Context(), c, s)
	if err != nil {
		p.fail(w, r, "server detail", err)
		return
	}
	data.Error = msg
	p.render(w, r, status, "server.html", data)
}

// setCredential stores the caller's own API key / bearer token / headers
// and values of the server's per-user headers.
func (p *Portal) setCredential(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	var cred auth.Credential
	if s.CredentialMode == store.MCPCredentialPerUser {
		switch s.AuthKind {
		case store.MCPAuthAPIKey:
			cred.APIKey = strings.TrimSpace(r.PostForm.Get("api_key"))
		case store.MCPAuthBearer:
			cred.Bearer = strings.TrimSpace(r.PostForm.Get("bearer"))
		case store.MCPAuthHeaders:
			h, err := parseHeaderLines(r.PostForm.Get("headers"), false)
			if err != nil {
				var ue *userError
				_ = errors.As(err, &ue)
				p.renderDetailError(w, r, c, s, http.StatusUnprocessableEntity, ue.msg)
				return
			}
			cred.Headers = h
		}
	}
	for _, name := range parseHeaderConfig(s.HeaderConfig).PerUser {
		if v := strings.TrimSpace(r.PostForm.Get("header:" + name)); v != "" {
			if cred.Headers == nil {
				cred.Headers = map[string]string{}
			}
			cred.Headers[name] = v
		}
	}
	err := p.d.Auth.SetUserCredential(r.Context(), c.UserID, s.ID, cred)
	switch {
	case errors.Is(err, store.ErrNotFound):
		p.notFound(w, r)
		return
	case err != nil:
		var ue *userError
		if errors.As(credentialError(err), &ue) {
			p.renderDetailError(w, r, c, s, http.StatusUnprocessableEntity, ue.msg)
			return
		}
		p.fail(w, r, "set credential", err)
		return
	}
	http.Redirect(w, r, "/servers/"+s.ID+"?connected=1", http.StatusSeeOther)
}

func (p *Portal) disconnect(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	if err := p.d.Auth.Disconnect(r.Context(), c.UserID, s.ID); err != nil {
		p.fail(w, r, "disconnect", err)
		return
	}
	http.Redirect(w, r, "/servers/"+s.ID+"?disconnected=1", http.StatusSeeOther)
}

// refresh rediscovers the server's capabilities with the caller's
// credential and stores a pending snapshot (owner only).
func (p *Portal) refresh(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	ctx := r.Context()
	sess, err := p.d.ClientFactory.Open(ctx, s, c.UserID)
	var rec *snapshot.Record
	if err == nil {
		rec, _, err = p.d.Snapshots.Refresh(ctx, c.snapActor(), s.ID, sess)
		if cerr := sess.Close(); cerr != nil {
			p.log.Debug("close upstream session", "server_id", s.ID, "error", cerr.Error())
		}
	}
	if err != nil {
		p.log.Info("refresh failed", "event", "federation.portal_refresh_failed", "user_id", c.UserID, "server_id", s.ID, "error", err.Error())
		p.renderDetailError(w, r, c, s, http.StatusBadGateway, "Refresh failed: "+sessionMessage(err))
		return
	}
	p.log.Info("server refreshed", "event", "federation.server_refreshed", "user_id", c.UserID, "server_id", s.ID,
		"skipped", len(rec.Skipped))
	if len(rec.Skipped) > 0 {
		// The skipped list is not stored: show it with the review now.
		p.renderReviewSkipped(w, r, c, s, http.StatusOK, "", rec.Skipped)
		return
	}
	http.Redirect(w, r, "/servers/"+s.ID+"/review", http.StatusSeeOther)
}

// sessionMessage is the user-facing, class-level text of a failure to
// open or use an upstream session (never upstream text).
func sessionMessage(err error) string {
	var te *tunnel.Error
	if errors.As(err, &te) && te.Class == tunnel.ClassOffline {
		return "The tunnel is offline: start `mcp-gateway tunnel` next to the server."
	}
	switch {
	case errors.Is(err, auth.ErrNotConnected):
		return "Connect to the server first."
	case errors.Is(err, auth.ErrNeedsReconnect):
		return "Your connection to the server expired: reconnect."
	case errors.Is(err, auth.ErrNotConfigured):
		return "The server's credentials are not set up yet."
	case errors.Is(err, auth.ErrSharedCredentialRejected):
		return "The server rejected the shared credential."
	case errors.Is(err, auth.ErrUnsupported):
		return "This server's authentication setup is not supported."
	case errors.Is(err, snapshot.ErrInvalidSnapshot):
		return "The server listed an unusable capability set (empty or duplicate names)."
	case errors.Is(err, snapshot.ErrReviewNotAllowed):
		return "Only the server's owner (while private) or an admin can do this."
	}
	var ce *client.Error
	if errors.As(err, &ce) {
		return upstreamMessage(ce.Class)
	}
	return "The request to the server failed."
}
