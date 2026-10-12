package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ErrDuplicate: the allow-list already has the pattern (Store.AddAllowHost).
var ErrDuplicate = errors.New("admin: duplicate allow-list entry")

// Server is a row of the admin_mcp_servers view (no secrets) plus the
// owner's display name and the latest / approved snapshot versions.
type Server struct {
	store.MCPServer
	OwnerName           string
	HasSharedCredential bool
	PublishedRoleIDs    []string
	UserConnectionCount int64
	// LatestVersion is the newest snapshot's version, ApprovedVersion the
	// approved one's; 0 means none.
	LatestVersion   int
	ApprovedVersion int
}

// PendingReview: the newest snapshot is not the approved one.
func (s Server) PendingReview() bool {
	return s.LatestVersion > 0 && s.LatestVersion != s.ApprovedVersion
}

// Tunnel is a row of the admin_mcp_tunnels view (no token hash) plus the
// owner's display name.
type Tunnel struct {
	ID          string
	OwnerUserID string
	OwnerName   string
	Name        string
	CreatedAt   time.Time
	LastSeenAt  *time.Time
	RevokedAt   *time.Time
}

// Role is a role a server can be published to.
type Role struct{ ID, Name string }

// Store is what the admin pages read and write. Every call is an admin
// action (NewStore runs them through WithJobs, decision 17iv8p3b); lookups
// of a missing row return store.ErrNotFound.
type Store interface {
	ListServers(ctx context.Context) ([]Server, error)
	GetServer(ctx context.Context, id string) (*Server, error)
	// StaticClientID is the server's static OAuth client ID ("" when none).
	StaticClientID(ctx context.Context, serverID string) (string, error)
	// SetPublishedRoles replaces the roles the server is published to: a
	// non-empty set publishes it (audience published), an empty one makes
	// it private again.
	SetPublishedRoles(ctx context.Context, serverID string, roleIDs []string) error
	SetStatus(ctx context.Context, serverID, status string) error
	// UpdateAddress changes the server's URL. On a published server the
	// approved snapshot is withdrawn in the same transaction (schema 17):
	// tools, resources and prompts disappear until an admin approves a
	// snapshot again.
	UpdateAddress(ctx context.Context, serverID, rawURL string) error
	DeleteServer(ctx context.Context, serverID string) error
	ListTunnels(ctx context.Context) ([]Tunnel, error)
	GetTunnel(ctx context.Context, id string) (*Tunnel, error)
	ListAllowHosts(ctx context.Context) ([]store.NetguardAllowHost, error)
	// AddAllowHost stores an entry (ErrDuplicate for a known pattern) and
	// writes the stored row back into h.
	AddAllowHost(ctx context.Context, h *store.NetguardAllowHost) error
	// DeleteAllowHost removes an entry and returns it.
	DeleteAllowHost(ctx context.Context, id string) (*store.NetguardAllowHost, error)
}

// Roles lists the roles servers can be published to, by name.
type Roles interface {
	ListRoles(ctx context.Context) ([]Role, error)
}

// Snapshots is the part of *snapshot.Service the pages use; they always
// pass an admin actor.
type Snapshots interface {
	Refresh(ctx context.Context, a snapshot.Actor, serverID string, sess snapshot.Session) (*snapshot.Record, snapshot.Diff, error)
	Latest(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
	Current(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
	Approve(ctx context.Context, a snapshot.Actor, serverID string, version int, d snapshot.ReviewDecisions) (*snapshot.Record, error)
}

// Auth is the part of *auth.Service the pages use.
type Auth interface {
	SetSharedCredential(ctx context.Context, actor auth.Actor, serverID string, c auth.Credential) error
	SetStaticClient(ctx context.Context, actor auth.Actor, serverID, clientID, clientSecret, issuer string) error
}

// Tunnels is the part of *tunnel.Service the pages use.
type Tunnels interface {
	Revoke(ctx context.Context, ownerUserID, tunnelID string) error
	Online(id string) bool
}

// Hook is told after a server was published, unpublished, disabled,
// enabled, deleted, reviewed, given credentials or a new address, so the gateway's tool
// registry and visibility follow (*connector.Manager satisfies it). A
// failure is logged; the connector's periodic reload catches up.
type Hook interface {
	ServerChanged(ctx context.Context, serverID string) error
}

// Invalidator drops a cached allow list (*netguard.CachedAllowList).
type Invalidator interface{ Invalidate() }

// Identity resolves the caller of a page: the session's user ID (empty
// when not signed in), its CSRF token and whether the user is an admin.
type Identity func(r *http.Request) (userID, csrfToken string, isAdmin bool)

// Deps are the admin pages' collaborators. Store, Roles, Snapshots, Auth,
// Tunnels, ClientFactory, Identity and Audit are required; Hook and
// AllowList default to no-ops and Log to slog.Default().
type Deps struct {
	Store     Store
	Roles     Roles
	Snapshots Snapshots
	Auth      Auth
	Tunnels   Tunnels
	// ClientFactory opens upstream sessions for Refresh (the servers
	// portal's fedportal.NewClientFactory).
	ClientFactory fedportal.ClientFactory
	Hook          Hook
	AllowList     Invalidator
	Identity      Identity
	Audit         audit.Recorder
	Log           *slog.Logger
}

//go:embed templates/*.html
var templateFS embed.FS

// Admin serves the admin pages for user-added MCP servers. Routes (Mount):
//
//	GET  /admin/servers                           every server; ?status=, ?pending=1
//	GET  /admin/servers/reviews                   servers with a snapshot waiting for review
//	GET  /admin/servers/{id}                      details and the admin forms
//	POST /admin/servers/{id}/publish              publish to the posted roles (replaces the set)
//	POST /admin/servers/{id}/unpublish            back to private
//	POST /admin/servers/{id}/shared-credential    set / replace the shared credential (write-only)
//	POST /admin/servers/{id}/static-client        set / replace the static OAuth client (secret write-only)
//	POST /admin/servers/{id}/address              change the URL (https); a published server needs a re-review
//	POST /admin/servers/{id}/disable              status disabled
//	POST /admin/servers/{id}/enable               status active
//	POST /admin/servers/{id}/delete               delete (confirm = the server's name)
//	POST /admin/servers/{id}/refresh              rediscover with the shared credential or the owner's connection
//	GET  /admin/servers/{id}/review               pending snapshot vs approved
//	POST /admin/servers/{id}/review               approve as admin
//	GET  /admin/tunnels                           every tunnel with its online state
//	POST /admin/tunnels/{id}/revoke               revoke any tunnel
//	GET  /admin/network/allow-hosts               SSRF allow-list
//	POST /admin/network/allow-hosts               add a host or CIDR
//	POST /admin/network/allow-hosts/{id}/delete   remove an entry
//
// Mount them with portal.MountAdmin. The module checks again: a caller
// who is not a signed-in admin gets the 404 page (before any CSRF check,
// so the route is not revealed), POSTs need the CSRF token (403), and
// every response is Cache-Control: no-store. Every change is audited
// with the admin as the user (ResourceIdentity "action" names the event).
type Admin struct {
	d   Deps
	log *slog.Logger
	tpl *template.Template
}

// NewAdmin builds the pages. It panics when a required dependency is
// missing (a wiring error).
func NewAdmin(d Deps) *Admin {
	if d.Store == nil || d.Roles == nil || d.Snapshots == nil || d.Auth == nil || d.Tunnels == nil ||
		d.ClientFactory == nil || d.Identity == nil || d.Audit == nil {
		panic("federation admin: Store, Roles, Snapshots, Auth, Tunnels, ClientFactory, Identity and Audit are required")
	}
	if d.Hook == nil {
		d.Hook = noopHook{}
	}
	if d.AllowList == nil {
		d.AllowList = noopInvalidator{}
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	tpl := template.Must(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
		"join":    strings.Join,
	}).ParseFS(templateFS, "templates/*.html"))
	tpl = template.Must(tpl.ParseFS(fedportal.ReviewTemplateFS, fedportal.ReviewTemplate))
	return &Admin{d: d, log: d.Log, tpl: tpl}
}

type noopHook struct{}

func (noopHook) ServerChanged(context.Context, string) error { return nil }

type noopInvalidator struct{}

func (noopInvalidator) Invalidate() {}

// Mount registers the routes through mountAdmin (portal.MountAdmin).
func (a *Admin) Mount(mountAdmin func(pattern string, h http.Handler)) {
	mountAdmin("GET /admin/servers", a.admin(a.list))
	mountAdmin("GET /admin/servers/reviews", a.admin(a.reviews))
	mountAdmin("GET /admin/servers/{id}", a.server(a.detail))
	mountAdmin("POST /admin/servers/{id}/publish", a.server(a.publish))
	mountAdmin("POST /admin/servers/{id}/unpublish", a.server(a.unpublish))
	mountAdmin("POST /admin/servers/{id}/shared-credential", a.server(a.setSharedCredential))
	mountAdmin("POST /admin/servers/{id}/static-client", a.server(a.setStaticClient))
	mountAdmin("POST /admin/servers/{id}/address", a.server(a.changeAddress))
	mountAdmin("POST /admin/servers/{id}/disable", a.server(a.disable))
	mountAdmin("POST /admin/servers/{id}/enable", a.server(a.enable))
	mountAdmin("POST /admin/servers/{id}/delete", a.server(a.delete))
	mountAdmin("POST /admin/servers/{id}/refresh", a.server(a.refresh))
	mountAdmin("GET /admin/servers/{id}/review", a.server(a.review))
	mountAdmin("POST /admin/servers/{id}/review", a.server(a.approve))
	mountAdmin("GET /admin/tunnels", a.admin(a.tunnels))
	mountAdmin("POST /admin/tunnels/{id}/revoke", a.admin(a.revokeTunnel))
	mountAdmin("GET /admin/network/allow-hosts", a.admin(a.allowHosts))
	mountAdmin("POST /admin/network/allow-hosts", a.admin(a.addAllowHost))
	mountAdmin("POST /admin/network/allow-hosts/{id}/delete", a.admin(a.deleteAllowHost))
}

// caller is the signed-in admin as handlers and templates see them.
type caller struct {
	UserID    string
	CSRFToken string
}

func (c caller) snapActor() snapshot.Actor { return snapshot.Actor{UserID: c.UserID, Admin: true} }
func (c caller) authActor() auth.Actor     { return auth.Actor{UserID: c.UserID, Admin: true} }

type handler func(w http.ResponseWriter, r *http.Request, c caller)

type serverHandler func(w http.ResponseWriter, r *http.Request, c caller, s *Server)

// maxFormBytes bounds a form body.
const maxFormBytes = 1 << 20

// admin resolves the caller: anyone but a signed-in admin gets the 404
// page; then no-store and, for state-changing requests, the CSRF check.
func (a *Admin) admin(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		userID, csrfToken, isAdmin := a.d.Identity(r)
		if userID == "" || !isAdmin {
			a.notFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "the form could not be read", http.StatusBadRequest)
				return
			}
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				token = r.PostForm.Get("_csrf")
			}
			if csrfToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(csrfToken)) != 1 {
				http.Error(w, "invalid or missing CSRF token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		h(w, r, caller{UserID: userID, CSRFToken: csrfToken})
	})
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// server loads the {id} server; an unknown or malformed ID is the 404 page.
func (a *Admin) server(h serverHandler) http.Handler {
	return a.admin(func(w http.ResponseWriter, r *http.Request, c caller) {
		id := r.PathValue("id")
		if !uuidRE.MatchString(id) {
			a.notFound(w, r)
			return
		}
		s, err := a.d.Store.GetServer(r.Context(), id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			a.notFound(w, r)
			return
		case err != nil:
			a.fail(w, r, "load server", err)
			return
		}
		h(w, r, c, s)
	})
}

// --- rendering -------------------------------------------------------------------

func (a *Admin) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := nav.Execute(a.tpl, r, &buf, name, data); err != nil {
		a.fail(w, r, "render "+name, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

type messageData struct {
	Title   string
	Message string
}

// notFound renders the same page as an unknown address.
func (a *Admin) notFound(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, http.StatusNotFound, "message.html", messageData{Title: "Page not found", Message: "There is no page at this address."})
}

func (a *Admin) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	a.log.Error("admin servers page failed", "event", "federation.admin_failed", "what", what, "path", r.URL.Path,
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}

// changed tells the hook, detached from the request's cancellation.
func (a *Admin) changed(ctx context.Context, serverID string) {
	if err := a.d.Hook.ServerChanged(context.WithoutCancel(ctx), serverID); err != nil {
		a.log.Warn("server change not applied yet; periodic reload will retry", "event", "federation.server_changed_failed",
			"server_id", serverID, "error", observability.RedactError(err))
	}
}

// record audits an admin change (no secrets: only names, IDs and counts).
// A failure is logged, never returned: the change is already committed.
func (a *Admin) record(ctx context.Context, c caller, action string, resource map[string]string) {
	res := map[string]string{"action": action}
	for k, v := range resource {
		res[k] = v
	}
	ev := audit.Event{
		Time:             time.Now(),
		UserID:           c.UserID,
		ResourceIdentity: res,
		Decision:         "allow",
		Outcome:          "succeeded",
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if err := a.d.Audit.Record(ctx, ev); err != nil {
		a.log.Error("audit event not recorded", "event", "federation.admin_audit_failed", "action", action,
			"error", observability.RedactError(err))
	}
	a.log.Info("admin changed federation settings", "event", action, "actor_user_id", c.UserID, "server_id", resource["server_id"])
}

func serverResource(s *Server) map[string]string {
	return map[string]string{"server_id": s.ID, "server": s.Name, "owner_user_id": s.OwnerUserID}
}
