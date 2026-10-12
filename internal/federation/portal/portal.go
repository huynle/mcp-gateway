package portal

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

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ErrNameTaken: another server already has the name (Store.CreateServer).
var ErrNameTaken = errors.New("portal: server name taken")

// Store is the data the pages read and write, always as the signed-in user
// (row-level security). Server lookups return store.ErrNotFound for a
// server the user cannot see. NewStore adapts a *store.Store.
type Store interface {
	// ListVisibleServers: the user's own servers and those published to a
	// role they hold.
	ListVisibleServers(ctx context.Context, userID string) ([]store.MCPServer, error)
	GetServer(ctx context.Context, userID, serverID string) (*store.MCPServer, error)
	// CreateServer inserts a private server owned by userID and writes the
	// stored row back into s. ErrNameTaken for a duplicate name.
	CreateServer(ctx context.Context, userID string, s *store.MCPServer) error
	// UpdateServer and DeleteServer are owner-only (ErrNotFound otherwise).
	UpdateServer(ctx context.Context, userID string, s *store.MCPServer) error
	DeleteServer(ctx context.Context, userID, serverID string) error
	// ListConnections: the user's own per-server connections (no secrets
	// are read by the pages).
	ListConnections(ctx context.Context, userID string) ([]store.MCPUserConnection, error)
	// CredentialInfo: which owner-only credentials the server has (zero
	// for a server the user does not own).
	CredentialInfo(ctx context.Context, userID, serverID string) (CredentialInfo, error)
	// ListTunnels: the user's tunnels, revoked ones included.
	ListTunnels(ctx context.Context, userID string) ([]store.MCPTunnel, error)
}

// CredentialInfo says which owner-only credentials a server has, never
// their values.
type CredentialInfo struct {
	SharedSecret   bool
	SharedKeys     []string
	StaticClient   bool
	StaticClientID string
}

// Snapshots is the part of *snapshot.Service the pages use.
type Snapshots interface {
	Refresh(ctx context.Context, a snapshot.Actor, serverID string, sess snapshot.Session) (*snapshot.Record, snapshot.Diff, error)
	Diff(ctx context.Context, a snapshot.Actor, serverID string) (snapshot.Diff, error)
	Latest(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
	Current(ctx context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error)
	Approve(ctx context.Context, a snapshot.Actor, serverID string, version int, d snapshot.ReviewDecisions) (*snapshot.Record, error)
}

// Auth is the part of *auth.Service the pages use.
type Auth interface {
	Detect(ctx context.Context, serverURL string) (*auth.DetectResult, error)
	SetSharedCredential(ctx context.Context, actor auth.Actor, serverID string, c auth.Credential) error
	SetUserCredential(ctx context.Context, userID, serverID string, c auth.Credential) error
	SetStaticClient(ctx context.Context, actor auth.Actor, serverID, clientID, clientSecret, issuer string) error
	Disconnect(ctx context.Context, userID, serverID string) error
}

// Tunnels is the part of *tunnel.Service the pages use.
type Tunnels interface {
	CreateTunnel(ctx context.Context, ownerUserID, name string) (*store.MCPTunnel, string, error)
	Revoke(ctx context.Context, ownerUserID, tunnelID string) error
	Online(id string) bool
}

// Session is an open upstream session (*client.Session satisfies it).
type Session interface {
	snapshot.Session
	ReadResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error)
	GetPrompt(ctx context.Context, name string, args map[string]string) (*mcp.GetPromptResult, error)
	Close() error
}

// ClientFactory opens an upstream session to server with userID's
// credential (per-user connection or the shared credential), through the
// SSRF-safe transport or the server's tunnel. NewClientFactory builds one
// from the federation services.
type ClientFactory interface {
	Open(ctx context.Context, server *store.MCPServer, userID string) (Session, error)
}

// ToolsChanged is told after a server was created, edited or deleted, or
// its approved snapshot changed, so the gateway's tool registry can
// reload it. Calls are best-effort and must not block for long.
type ToolsChanged interface {
	ServerChanged(ctx context.Context, serverID string)
}

type noopHook struct{}

func (noopHook) ServerChanged(context.Context, string) {}

// AddServerPermission says whether a user may add MCP servers (admin, or a
// role with "May add MCP servers"; *permissions.Service). It fails closed.
type AddServerPermission interface {
	CanAddServers(ctx context.Context, userID string) bool
}

// Identity resolves the caller of a page: the session's user ID (empty when
// not signed in), its CSRF token (echoed by every form) and whether the
// user is an admin.
type Identity func(r *http.Request) (userID, csrfToken string, isAdmin bool)

// Deps are the Portal's collaborators. Store, Snapshots, Auth, Tunnels,
// ClientFactory, Permissions and Identity are required; Hook defaults to a no-op and
// Log to slog.Default(). BaseURL is the gateway's public URL (shown in the
// tunnel command).
type Deps struct {
	Store         Store
	Snapshots     Snapshots
	Auth          Auth
	Tunnels       Tunnels
	ClientFactory ClientFactory
	Hook          ToolsChanged
	Permissions   AddServerPermission
	Identity      Identity
	Log           *slog.Logger
	BaseURL       string
}

//go:embed templates/*.html
var templateFS embed.FS

// Portal serves the servers pages for signed-in users. Routes (Mount):
//
//	GET  /servers                          my servers, servers published to me, my tunnels
//	GET  /servers/new                      add-server form
//	POST /servers/new                      action=detect (re-render) | action=create
//	POST /servers/tunnels                  create a tunnel (token shown once)
//	POST /servers/tunnels/revoke           revoke a tunnel (form field id)
//	GET  /servers/{id}                     details, my connection, refresh
//	POST /servers/{id}/credential          my API key / bearer / header values
//	POST /servers/{id}/disconnect          delete my connection
//	POST /servers/{id}/refresh             owner: rediscover with my credential -> review
//	GET  /servers/{id}/review              pending snapshot vs approved
//	POST /servers/{id}/review              approve with per-tool decisions
//	GET  /servers/{id}/resources           approved resources, templates, prompts
//	POST /servers/{id}/resources/read      live read of one listed resource
//	GET  /servers/{id}/prompts/{name}      prompt with its argument form
//	POST /servers/{id}/prompts/{name}      live get prompt preview
//	GET  /servers/{id}/edit                owner: edit form
//	POST /servers/{id}/edit                owner: save
//	POST /servers/{id}/delete              owner: delete
//
// The OAuth connect routes (GET /servers/{id}/connect, GET
// /servers/oauth/callback) belong to internal/federation/auth and are
// mounted by the gateway; the pages only link to them.
//
// Every route answers 401 without a user, checks the CSRF token on POST
// (403), sets Cache-Control: no-store, and answers a server the user cannot
// see (or an owner-only page of someone else's server) with the 404 page.
// Adding a server (GET and POST /servers/new, detect included) and moving
// one to a new address need the add-server permission (Permissions; Brain
// decision bnneszc1): without it the Add server button is hidden and the
// form answers 403. Servers a user already owns keep working.
type Portal struct {
	d   Deps
	log *slog.Logger
	tpl *template.Template
}

// NewPortal builds the pages. It panics when a required dependency is
// missing (a wiring error).
func NewPortal(d Deps) *Portal {
	if d.Store == nil || d.Snapshots == nil || d.Auth == nil || d.Tunnels == nil || d.ClientFactory == nil || d.Permissions == nil || d.Identity == nil {
		panic("federation portal: Store, Snapshots, Auth, Tunnels, ClientFactory, Permissions and Identity are required")
	}
	if d.Hook == nil {
		d.Hook = noopHook{}
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	d.BaseURL = strings.TrimRight(d.BaseURL, "/")
	tpl := template.Must(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
		"join":    strings.Join,
		"dname":   snapshot.DisplayName,
		"dtitle":  snapshot.DisplayTitle,
		"ddesc":   snapshot.DisplayDescription,
	}).ParseFS(templateFS, "templates/*.html"))
	return &Portal{d: d, log: d.Log, tpl: tpl}
}

// Mount registers the routes through mountUser (portal.MountUser: behind
// the portal's signed-in check and, for POST, its CSRF check; this package
// checks both again).
func (p *Portal) Mount(mountUser func(pattern string, h http.Handler)) {
	mountUser("GET /servers", p.user(p.list))
	mountUser("GET /servers/new", p.user(p.adder(p.newForm)))
	mountUser("POST /servers/new", p.user(p.adder(p.create)))
	mountUser("POST /servers/tunnels", p.user(p.createTunnel))
	mountUser("POST /servers/tunnels/revoke", p.user(p.revokeTunnel))
	mountUser("GET /servers/{id}", p.server(p.detail))
	mountUser("POST /servers/{id}/credential", p.server(p.setCredential))
	mountUser("POST /servers/{id}/disconnect", p.server(p.disconnect))
	mountUser("POST /servers/{id}/refresh", p.owner(p.refresh))
	mountUser("GET /servers/{id}/review", p.server(p.review))
	mountUser("POST /servers/{id}/review", p.server(p.approve))
	mountUser("GET /servers/{id}/resources", p.server(p.resources))
	mountUser("POST /servers/{id}/resources/read", p.server(p.readResource))
	mountUser("GET /servers/{id}/prompts/{name}", p.server(p.prompt))
	mountUser("POST /servers/{id}/prompts/{name}", p.server(p.prompt))
	mountUser("GET /servers/{id}/edit", p.owner(p.editForm))
	mountUser("POST /servers/{id}/edit", p.owner(p.save))
	mountUser("POST /servers/{id}/delete", p.owner(p.delete))
}

// caller is the signed-in user as the handlers and templates see them.
type caller struct {
	UserID    string
	CSRFToken string
	IsAdmin   bool
}

func (c caller) snapActor() snapshot.Actor { return snapshot.Actor{UserID: c.UserID} }

type handler func(w http.ResponseWriter, r *http.Request, c caller)

type serverHandler func(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer)

// maxFormBytes bounds a form body.
const maxFormBytes = 1 << 20

// user resolves the caller (401 without one), sets no-store and checks the
// CSRF token of state-changing requests (403).
func (p *Portal) user(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, csrfToken, isAdmin := p.d.Identity(r)
		if userID == "" {
			http.Error(w, "sign in to manage your servers", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
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
		h(w, r, caller{UserID: userID, CSRFToken: csrfToken, IsAdmin: isAdmin})
	})
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// server loads the {id} server as the caller; one the caller cannot see is
// the 404 page.
func (p *Portal) server(h serverHandler) http.Handler {
	return p.user(func(w http.ResponseWriter, r *http.Request, c caller) {
		id := r.PathValue("id")
		if !uuidRE.MatchString(id) {
			p.notFound(w, r)
			return
		}
		s, err := p.d.Store.GetServer(r.Context(), c.UserID, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			p.notFound(w, r)
			return
		case err != nil:
			p.fail(w, r, "load server", err)
			return
		}
		h(w, r, c, s)
	})
}

// mayAddMessage is shown wherever adding a server is refused.
const mayAddMessage = "Your roles do not allow adding MCP servers. Ask an admin for a role that may add MCP servers. Servers you already added keep working."

// adder is user for the add-server form: a caller without the add-server
// permission gets the 403 page (after the CSRF check, so a forged request
// is still refused as forged).
func (p *Portal) adder(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, c caller) {
		if !p.d.Permissions.CanAddServers(r.Context(), c.UserID) {
			p.log.Info("add server refused", "event", "federation.portal_add_refused", "user_id", c.UserID)
			p.render(w, r, http.StatusForbidden, "message.html", messageData{Title: "Adding servers needs permission", Message: mayAddMessage})
			return
		}
		h(w, r, c)
	}
}

// owner is server for owner-only pages: anyone else gets the 404 page.
func (p *Portal) owner(h serverHandler) http.Handler {
	return p.server(func(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
		if s.OwnerUserID != c.UserID {
			p.notFound(w, r)
			return
		}
		h(w, r, c, s)
	})
}

// --- rendering -------------------------------------------------------------------

func (p *Portal) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := nav.Execute(p.tpl, r, &buf, name, data); err != nil {
		p.fail(w, r, "render "+name, err)
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

// notFound renders the same page the portal shows for an unknown address,
// so a server the caller cannot see is indistinguishable from none.
func (p *Portal) notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p.render(w, r, http.StatusNotFound, "message.html", messageData{Title: "Page not found", Message: "There is no page at this address."})
}

func (p *Portal) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.log.Error("servers page failed", "event", "federation.portal_failed", "what", what, "path", r.URL.Path,
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}

func (p *Portal) changed(ctx context.Context, serverID string) {
	p.d.Hook.ServerChanged(context.WithoutCancel(ctx), serverID)
}
