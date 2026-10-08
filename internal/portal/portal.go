package portal

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Portal serves the web UI and the sign-in routes.
type Portal struct {
	svc *identity.Service
	log *slog.Logger
	tpl *templates
}

// New builds the portal over the identity service. It installs the portal's
// error page as the service's sign-in error renderer.
func New(svc *identity.Service, log *slog.Logger) (*Portal, error) {
	if log == nil {
		log = slog.Default()
	}
	tpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	p := &Portal{svc: svc, log: log, tpl: tpl}
	svc.SetErrorHandler(func(w http.ResponseWriter, r *http.Request, status int, message string) {
		p.errorPage(w, r, status, "Sign-in failed", message)
	})
	return p, nil
}

// Handler returns the portal routes, wrapped in the session middleware and
// the CSRF check:
//
//	GET  /                         redirect to /account or /signin
//	GET  /signin                   provider buttons
//	GET  /account                  my account
//	GET  /admin/users              admin: list users
//	POST /admin/users/{id}/disable admin
//	POST /admin/users/{id}/enable  admin
//	POST /admin/users/{id}/role    admin: replace the user's role
//	/auth/...                      identity.Service.Handler
//	GET  /static/...               embedded assets
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.home)
	mux.HandleFunc("GET /signin", p.signIn)
	mux.Handle("GET /account", p.requireUser(http.HandlerFunc(p.account)))
	// Role gating runs before the CSRF check so a non-admin's POST is the
	// same 404 as an unknown page rather than a 403 that reveals the route.
	mux.Handle("GET /admin/users", p.requireAdmin(http.HandlerFunc(p.adminUsers)))
	mux.Handle("POST /admin/users/{id}/disable", p.requireAdmin(p.csrf(http.HandlerFunc(p.adminDisable))))
	mux.Handle("POST /admin/users/{id}/enable", p.requireAdmin(p.csrf(http.HandlerFunc(p.adminEnable))))
	mux.Handle("POST /admin/users/{id}/role", p.requireAdmin(p.csrf(http.HandlerFunc(p.adminSetRole))))
	// Sign-out is a POST and therefore behind the CSRF check as well.
	mux.Handle("/auth/", p.csrf(p.svc.Handler()))
	mux.Handle("GET /static/", p.static())
	mux.HandleFunc("/", p.notFound)
	return p.svc.Middleware(mux)
}

// static serves the embedded assets without directory listings.
func (p *Portal) static() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			p.notFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.StripPrefix("/static/", files).ServeHTTP(w, r)
	})
}

// requireUser redirects anonymous requests to the sign-in page, carrying
// the current path as return_to.
func (p *Portal) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity.PrincipalFrom(r.Context()) == nil {
			http.Redirect(w, r, "/signin?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// requireAdmin is requireUser plus the admin role; a signed-in non-admin
// gets the same 404 as an unknown page (decision 7datr7x4).
func (p *Portal) requireAdmin(next http.Handler) http.Handler {
	return p.requireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !identity.PrincipalFrom(r.Context()).IsAdmin() {
			p.notFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// --- pages -----------------------------------------------------------------

func (p *Portal) home(w http.ResponseWriter, r *http.Request) {
	if identity.PrincipalFrom(r.Context()) != nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

// signInProvider is one button on the sign-in page.
type signInProvider struct {
	DisplayName string
	StartURL    string
}

type signInData struct {
	Providers []signInProvider
}

func (p *Portal) signIn(w http.ResponseWriter, r *http.Request) {
	if identity.PrincipalFrom(r.Context()) != nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	returnTo := identity.SafeReturnTo(r.URL.Query().Get("return_to"))
	var data signInData
	for _, prov := range p.svc.Providers() {
		data.Providers = append(data.Providers, signInProvider{
			DisplayName: prov.DisplayName,
			StartURL:    "/auth/" + prov.Name + "/start?return_to=" + url.QueryEscape(returnTo),
		})
	}
	p.render(w, r, http.StatusOK, "signin.html", data)
}

func (p *Portal) account(w http.ResponseWriter, r *http.Request) {
	p.render(w, r, http.StatusOK, "account.html", nil)
}

type adminUsersData struct {
	Users []identity.UserSummary
	Roles []store.Role
}

func (p *Portal) adminUsers(w http.ResponseWriter, r *http.Request) {
	data, err := p.loadAdminUsers(r)
	if err != nil {
		p.serverError(w, r, err)
		return
	}
	p.render(w, r, http.StatusOK, "admin_users.html", data)
}

func (p *Portal) loadAdminUsers(r *http.Request) (adminUsersData, error) {
	users, err := p.svc.ListUsers(r.Context())
	if err != nil {
		return adminUsersData{}, err
	}
	roles, err := p.svc.ListRoles(r.Context())
	if err != nil {
		return adminUsersData{}, err
	}
	return adminUsersData{Users: users, Roles: roles}, nil
}

func (p *Portal) adminDisable(w http.ResponseWriter, r *http.Request) {
	actor := identity.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	if id == actor.UserID {
		p.errorPage(w, r, http.StatusBadRequest, "Not allowed", "You cannot disable your own account.")
		return
	}
	p.adminAction(w, r, id, p.svc.DisableUser(r.Context(), actor.UserID, id))
}

func (p *Portal) adminEnable(w http.ResponseWriter, r *http.Request) {
	actor := identity.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	p.adminAction(w, r, id, p.svc.EnableUser(r.Context(), actor.UserID, id))
}

func (p *Portal) adminSetRole(w http.ResponseWriter, r *http.Request) {
	actor := identity.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	role := strings.TrimSpace(r.FormValue("role"))
	if role == "" {
		p.errorPage(w, r, http.StatusBadRequest, "Not allowed", "Choose a role.")
		return
	}
	err := p.svc.SetUserRole(r.Context(), actor.UserID, id, role)
	if errors.Is(err, store.ErrNotFound) {
		p.errorPage(w, r, http.StatusBadRequest, "Not allowed", "That role does not exist.")
		return
	}
	p.adminAction(w, r, id, err)
}

// adminAction finishes a user action: 404 for an unknown user, the updated
// row for htmx requests, a redirect to the list otherwise.
func (p *Portal) adminAction(w http.ResponseWriter, r *http.Request, userID string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		p.notFound(w, r)
		return
	case err != nil:
		p.serverError(w, r, err)
		return
	}
	if r.Header.Get("HX-Request") != "true" {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	data, err := p.loadAdminUsers(r)
	if err != nil {
		p.serverError(w, r, err)
		return
	}
	for _, u := range data.Users {
		if u.ID == userID {
			row := userRow{Principal: identity.PrincipalFrom(r.Context()), User: u, Roles: data.Roles}
			if err := p.tpl.render(w, http.StatusOK, "admin_users.html", "user_row", row); err != nil {
				p.log.Error("render failed", "event", "portal.render_failed", "template", "user_row", "error", err)
			}
			return
		}
	}
	p.notFound(w, r)
}

// --- rendering ---------------------------------------------------------------

func (p *Portal) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	err := p.tpl.render(w, status, name, "", page{Principal: identity.PrincipalFrom(r.Context()), Data: data})
	if err != nil {
		p.log.Error("render failed", "event", "portal.render_failed", "template", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

type errorData struct {
	Title, Message, Back string
}

func (p *Portal) errorPage(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	w.Header().Set("Cache-Control", "no-store")
	p.render(w, r, status, "error.html", errorData{Title: title, Message: message, Back: "/"})
}

func (p *Portal) notFound(w http.ResponseWriter, r *http.Request) {
	p.errorPage(w, r, http.StatusNotFound, "Page not found", "There is no page at this address.")
}

func (p *Portal) serverError(w http.ResponseWriter, r *http.Request, err error) {
	p.log.Error("portal request failed", "event", "portal.request_failed", "path", r.URL.Path, "error", err)
	p.errorPage(w, r, http.StatusInternalServerError, "Something went wrong", "The request could not be completed. Try again.")
}
