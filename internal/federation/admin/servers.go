package admin

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// serverRow is one server as the pages show it.
type serverRow struct {
	ID             string
	Name           string
	Owner          string
	OwnerUserID    string
	Host           string
	URL            string
	Audience       string
	Roles          []string
	CredentialMode string
	AuthKind       string
	Status         string
	LastError      string
	Shared         bool
	Connections    int64
	Pending        bool
	Latest         int
	Approved       int
}

// hostOf shows only the host of an https URL, "tunnel" for a tunnel URL.
func hostOf(raw string) string {
	if tunnel.IsTunnelURL(raw) {
		return "tunnel"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid URL)"
	}
	return u.Host
}

func roleNames(ids []string, byID map[string]string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := byID[id]; ok {
			out = append(out, n)
		} else {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func rowOf(s *Server, roles map[string]string) serverRow {
	row := serverRow{
		ID: s.ID, Name: s.Name, Owner: s.OwnerName, OwnerUserID: s.OwnerUserID, Host: hostOf(s.URL), URL: s.URL,
		Audience: s.Audience, Roles: roleNames(s.PublishedRoleIDs, roles), CredentialMode: s.CredentialMode,
		AuthKind: s.AuthKind, Status: s.Status, Shared: s.HasSharedCredential, Connections: s.UserConnectionCount,
		Pending: s.PendingReview(), Latest: s.LatestVersion, Approved: s.ApprovedVersion,
	}
	if row.Owner == "" {
		row.Owner = s.OwnerUserID
	}
	if s.LastErrorClass != nil {
		row.LastError = *s.LastErrorClass
	}
	return row
}

func (a *Admin) roleMap(r *http.Request) (map[string]string, []Role, error) {
	roles, err := a.d.Roles.ListRoles(r.Context())
	if err != nil {
		return nil, nil, err
	}
	m := make(map[string]string, len(roles))
	for _, ro := range roles {
		m[ro.ID] = ro.Name
	}
	return m, roles, nil
}

// --- list and review queue ----------------------------------------------------------

type listData struct {
	Title    string
	Caller   caller
	Servers  []serverRow
	Status   string
	Pending  bool
	Statuses []string
	Queue    bool
}

var statuses = []string{store.MCPServerActive, store.MCPServerDisabled, store.MCPServerError}

func (a *Admin) list(w http.ResponseWriter, r *http.Request, c caller) {
	status := r.URL.Query().Get("status")
	if !slices.Contains(statuses, status) {
		status = ""
	}
	pending := r.URL.Query().Get("pending") != ""
	a.renderList(w, r, c, listData{Title: "MCP servers", Status: status, Pending: pending})
}

func (a *Admin) reviews(w http.ResponseWriter, r *http.Request, c caller) {
	a.renderList(w, r, c, listData{Title: "Servers waiting for review", Pending: true, Queue: true})
}

func (a *Admin) renderList(w http.ResponseWriter, r *http.Request, c caller, data listData) {
	servers, err := a.d.Store.ListServers(r.Context())
	if err != nil {
		a.fail(w, r, "list servers", err)
		return
	}
	roles, _, err := a.roleMap(r)
	if err != nil {
		a.fail(w, r, "list roles", err)
		return
	}
	data.Caller, data.Statuses = c, statuses
	for i := range servers {
		s := &servers[i]
		if data.Status != "" && s.Status != data.Status {
			continue
		}
		if data.Pending && !s.PendingReview() {
			continue
		}
		data.Servers = append(data.Servers, rowOf(s, roles))
	}
	a.render(w, r, http.StatusOK, "servers.html", data)
}

// --- detail ---------------------------------------------------------------------------

type roleOption struct {
	ID      string
	Name    string
	Checked bool
}

type detailData struct {
	Title          string
	Caller         caller
	Server         serverRow
	Roles          []roleOption
	StaticClientID string
	SharedForm     bool // the server takes a shared credential of its kind
	StaticForm     bool // the server uses OAuth
	Notice         string
	Error          string
}

var notices = map[string]string{
	"published":   "Published. Grant its tools to the roles in the role editor: published servers' tools are hidden until a role allows them.",
	"unpublished": "Unpublished: the server is private to its owner again.",
	"credential":  "Shared credential saved.",
	"client":      "Static OAuth client saved.",
	"disabled":    "Server disabled: its tools are no longer offered.",
	"enabled":     "Server enabled.",
	"reviewed":    "Review saved.",
}

func (a *Admin) detail(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	a.renderDetail(w, r, c, s, http.StatusOK, notices[r.URL.Query().Get("done")], "")
}

func sharedKind(kind string) bool {
	return kind == store.MCPAuthAPIKey || kind == store.MCPAuthBearer || kind == store.MCPAuthHeaders
}

func (a *Admin) renderDetail(w http.ResponseWriter, r *http.Request, c caller, s *Server, status int, notice, errMsg string) {
	byID, roles, err := a.roleMap(r)
	if err != nil {
		a.fail(w, r, "list roles", err)
		return
	}
	clientID, err := a.d.Store.StaticClientID(r.Context(), s.ID)
	if err != nil {
		a.fail(w, r, "static client", err)
		return
	}
	data := detailData{
		Title: "Server " + s.Name, Caller: c, Server: rowOf(s, byID), StaticClientID: clientID,
		SharedForm: s.CredentialMode == store.MCPCredentialShared && sharedKind(s.AuthKind),
		StaticForm: s.AuthKind == store.MCPAuthOAuth, Notice: notice, Error: errMsg,
	}
	for _, ro := range roles {
		data.Roles = append(data.Roles, roleOption{ID: ro.ID, Name: ro.Name, Checked: slices.Contains(s.PublishedRoleIDs, ro.ID)})
	}
	a.render(w, r, status, "server.html", data)
}

func (a *Admin) done(w http.ResponseWriter, r *http.Request, s *Server, what string) {
	http.Redirect(w, r, "/admin/servers/"+s.ID+"?done="+what, http.StatusSeeOther)
}

// --- publishing -----------------------------------------------------------------------

func (a *Admin) publish(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	byID, _, err := a.roleMap(r)
	if err != nil {
		a.fail(w, r, "list roles", err)
		return
	}
	var ids []string
	for _, id := range r.PostForm["roles"] {
		if _, ok := byID[id]; !ok {
			a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", "Choose roles from the list.")
			return
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", "Choose at least one role. To make the server private again, use Unpublish.")
		return
	}
	if err := a.d.Store.SetPublishedRoles(r.Context(), s.ID, ids); err != nil {
		a.fail(w, r, "publish", err)
		return
	}
	res := serverResource(s)
	res["roles"] = truncate(strings.Join(roleNames(ids, byID), ","), 128)
	a.record(r.Context(), c, "mcp_server.published", res)
	a.changed(r.Context(), s.ID)
	a.done(w, r, s, "published")
}

func (a *Admin) unpublish(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	if err := a.d.Store.SetPublishedRoles(r.Context(), s.ID, nil); err != nil {
		a.fail(w, r, "unpublish", err)
		return
	}
	a.record(r.Context(), c, "mcp_server.unpublished", serverResource(s))
	a.changed(r.Context(), s.ID)
	a.done(w, r, s, "unpublished")
}

// truncate caps s at n bytes on a rune boundary (audit values are bounded).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// --- credentials -----------------------------------------------------------------------

// credentialMessage is the fixed, secret-free text of a refused credential.
func credentialMessage(err error) (string, bool) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredential):
		return "The credential is not valid: it must not be empty, too long or contain control characters.", true
	case errors.Is(err, auth.ErrUnsupported):
		return "This server's authentication setup does not support that credential.", true
	case errors.Is(err, auth.ErrForbidden):
		return "Not allowed to change this server's credentials.", true
	}
	return "", false
}

func (a *Admin) setSharedCredential(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	if s.CredentialMode != store.MCPCredentialShared || !sharedKind(s.AuthKind) {
		a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "",
			"This server does not use a shared API key, bearer token or headers. Its owner chooses the credential mode on the server's settings.")
		return
	}
	var cred auth.Credential
	switch s.AuthKind {
	case store.MCPAuthAPIKey:
		cred.APIKey = strings.TrimSpace(r.PostForm.Get("api_key"))
	case store.MCPAuthBearer:
		cred.Bearer = strings.TrimSpace(r.PostForm.Get("bearer"))
	case store.MCPAuthHeaders:
		h, err := fedportal.ParseSecretHeaderLines(r.PostForm.Get("headers"))
		if err != nil {
			msg, ok := fedportal.UserMessage(err)
			if !ok {
				msg = "Header lines must look like “Name: value”."
			}
			a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", msg)
			return
		}
		cred.Headers = h
	}
	if cred.APIKey == "" && cred.Bearer == "" && len(cred.Headers) == 0 {
		a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", "Enter the new shared credential.")
		return
	}
	if err := a.d.Auth.SetSharedCredential(r.Context(), c.authActor(), s.ID, cred); err != nil {
		if msg, ok := credentialMessage(err); ok {
			a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", msg)
			return
		}
		a.fail(w, r, "set shared credential", err)
		return
	}
	res := serverResource(s)
	res["auth_kind"] = s.AuthKind
	a.record(r.Context(), c, "mcp_server.shared_credential_set", res)
	a.changed(r.Context(), s.ID)
	a.done(w, r, s, "credential")
}

func (a *Admin) setStaticClient(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	if s.AuthKind != store.MCPAuthOAuth {
		a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", "Only OAuth servers use an OAuth client.")
		return
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	secret := strings.TrimSpace(r.PostForm.Get("client_secret"))
	issuer := strings.TrimSpace(r.PostForm.Get("issuer"))
	if clientID == "" {
		a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", "Enter the client ID.")
		return
	}
	if issuer != "" {
		if u, err := url.Parse(issuer); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", "The issuer must be an https URL.")
			return
		}
	}
	if err := a.d.Auth.SetStaticClient(r.Context(), c.authActor(), s.ID, clientID, secret, issuer); err != nil {
		if msg, ok := credentialMessage(err); ok {
			a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", msg)
			return
		}
		a.fail(w, r, "set static client", err)
		return
	}
	a.record(r.Context(), c, "mcp_server.static_client_set", serverResource(s))
	a.changed(r.Context(), s.ID)
	a.done(w, r, s, "client")
}

// --- status and delete -----------------------------------------------------------------

func (a *Admin) setStatus(w http.ResponseWriter, r *http.Request, c caller, s *Server, status, action, notice string) {
	if err := a.d.Store.SetStatus(r.Context(), s.ID, status); err != nil {
		a.fail(w, r, "set status", err)
		return
	}
	a.record(r.Context(), c, action, serverResource(s))
	a.changed(r.Context(), s.ID)
	a.done(w, r, s, notice)
}

func (a *Admin) disable(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	a.setStatus(w, r, c, s, store.MCPServerDisabled, "mcp_server.disabled", "disabled")
}

func (a *Admin) enable(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	a.setStatus(w, r, c, s, store.MCPServerActive, "mcp_server.enabled", "enabled")
}

func (a *Admin) delete(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	if strings.TrimSpace(r.PostForm.Get("confirm")) != s.Name {
		a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", "Type the server's name to confirm the deletion.")
		return
	}
	if err := a.d.Store.DeleteServer(r.Context(), s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.fail(w, r, "delete server", err)
		return
	}
	a.record(r.Context(), c, "mcp_server.deleted", serverResource(s))
	a.changed(r.Context(), s.ID)
	http.Redirect(w, r, "/admin/servers", http.StatusSeeOther)
}

// --- refresh ------------------------------------------------------------------------------

// refresh rediscovers the server with the shared credential (shared mode)
// or the owner's own connection (per-user mode), as the owner would, and
// stores a pending snapshot for the admin review.
func (a *Admin) refresh(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	ctx := r.Context()
	sess, err := a.d.ClientFactory.Open(ctx, &s.MCPServer, s.OwnerUserID)
	if err == nil {
		_, _, err = a.d.Snapshots.Refresh(ctx, c.snapActor(), s.ID, sess)
		if cerr := sess.Close(); cerr != nil {
			a.log.Debug("close upstream session", "server_id", s.ID, "error", cerr.Error())
		}
	}
	if err != nil {
		a.log.Info("admin refresh failed", "event", "federation.admin_refresh_failed", "user_id", c.UserID, "server_id", s.ID,
			"error", err.Error())
		a.renderDetail(w, r, c, s, http.StatusBadGateway, "", "Refresh failed: "+refreshMessage(err))
		return
	}
	a.record(ctx, c, "mcp_server.refreshed", serverResource(s))
	http.Redirect(w, r, "/admin/servers/"+s.ID+"/review", http.StatusSeeOther)
}

// refreshMessage explains a failed admin refresh (class-level; the
// credential-related cases name what is missing).
func refreshMessage(err error) string {
	switch {
	case errors.Is(err, auth.ErrNotConnected), errors.Is(err, auth.ErrNotConfigured):
		return "there is no shared credential and the owner has not connected their own account. Ask the owner to connect on the server's page, or (shared mode) set a shared credential here."
	case errors.Is(err, auth.ErrNeedsReconnect):
		return "the owner's connection to the server expired. Ask the owner to reconnect, or (shared mode) set a shared credential here."
	}
	return fedportal.SessionMessage(err)
}
