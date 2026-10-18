package portal

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/portal/static"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Portal serves the web UI and the sign-in routes.
type Portal struct {
	svc          *identity.Service
	log          *slog.Logger
	tpl          *templates
	mounts       []mount
	gatewayTools GatewayTools // nil: no "Gateway management tools" section
	rateSettings RateSettings // nil: no durable rate-limit settings UI
	lifecycle    Account      // nil: no data export / account deletion
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
//	POST /account/gateway-tools    my "Gateway management tools" switch (SetGatewayTools)
//	POST /account/rate-limit       my optional lower personal ceiling
//	POST /account/export           download my data (SetAccount)
//	GET|POST /account/delete       delete my account (SetAccount)
//	GET  /account/deleted          after the deletion (anonymous)
//	GET  /admin/users              admin: list users
//	POST /admin/users/{id}/disable admin
//	POST /admin/users/{id}/enable  admin
//	POST /admin/users/{id}/role    admin: replace the user's role
//	GET|POST /admin/users/{id}/delete admin: delete the user (SetAccount)
//	/auth/...                      identity.Service.Handler
//	GET  /static/...               embedded assets
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, m := range p.mounts {
		// Gating wraps the CSRF check (same order as the built-in admin
		// routes below): a non-admin's POST is the 404 of an unknown page,
		// not a 403 that reveals the route.
		h := m.handler
		if m.csrf {
			h = p.csrf(h)
		}
		if m.admin {
			h = p.requireAdmin(h)
		} else {
			h = p.requireUser(h)
		}
		mux.Handle(m.pattern, h)
	}
	mux.HandleFunc("GET /{$}", p.home)
	mux.HandleFunc("GET /signin", p.signIn)
	mux.Handle("GET /account", p.requireUser(http.HandlerFunc(p.account)))
	if p.gatewayTools != nil {
		mux.Handle("POST /account/gateway-tools", p.requireUser(p.csrf(http.HandlerFunc(p.setGatewayTools))))
	}
	if p.rateSettings != nil {
		mux.Handle("POST /account/rate-limit", p.requireUser(p.csrf(http.HandlerFunc(p.setMyRateLimit))))
		mux.Handle("GET /admin/settings", p.requireAdmin(http.HandlerFunc(p.adminSettings)))
		mux.Handle("GET /admin/settings/rate-limits", p.requireAdmin(http.HandlerFunc(p.adminRateLimits)))
		mux.Handle("POST /admin/settings/rate-limits/org", p.requireAdmin(p.csrf(http.HandlerFunc(p.setOrgRateLimits))))
		mux.Handle("POST /admin/settings/rate-limits/app", p.requireAdmin(p.csrf(http.HandlerFunc(p.setAppRateLimit))))
		mux.Handle("POST /admin/settings/rate-limits/user", p.requireAdmin(p.csrf(http.HandlerFunc(p.setUserRateLimit))))
	}
	if p.lifecycle != nil {
		p.mountLifecycle(mux)
	}
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
	return SecurityHeaders(p.svc.Middleware(withNav(mux)))
}

// withNav attaches the shared nav data (package nav) for the signed-in
// principal, so every page, the portal's and the mounted modules', renders
// the same bar. The admin flag is Principal.IsAdmin, the check
// requireAdmin applies to /admin/* (decision 7datr7x4).
func withNav(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pr := identity.PrincipalFrom(r.Context()); pr != nil {
			r = r.WithContext(nav.WithData(r.Context(), nav.Data{
				SignedIn: true, IsAdmin: pr.IsAdmin(), CSRFToken: pr.CSRFToken, DisplayName: pr.DisplayName,
			}))
		}
		next.ServeHTTP(w, r)
	})
}

// CSP is the Content-Security-Policy every portal response carries:
// same-origin everything, the embedded htmx (script-src 'self'; htmx
// needs no eval for the attributes the templates use), inline <style>
// blocks and the few inline onsubmit confirmations the templates still
// have ('unsafe-inline' on script-src and style-src; moving those to
// hx-confirm would let script-src drop it), no plugins, no framing, no
// <base> hijack. form-action is deliberately absent: the connect and
// sign-in forms submit to a same-origin route that answers with a
// redirect to the vendor or identity provider, and Chrome applies
// form-action to such redirects. Handlers that need a stricter set (the
// OAuth consent page) overwrite the header.
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"

// SecurityHeaders sets the browser hardening headers on every response
// before the handler runs (so a handler may override them): no framing
// (clickjacking), no MIME sniffing, no Referer leaking the URL (ids of
// approvals, tokens and operations live in paths and queries), and the
// CSP baseline. Applied to the whole portal, including error pages and
// the static assets.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", CSP)
		next.ServeHTTP(w, r)
	})
}

// mount is an extra route registered by another module before Handler runs.
type mount struct {
	pattern string
	handler http.Handler
	admin   bool
	csrf    bool
}

// MountUser registers an extra route behind the signed-in check (and the
// CSRF check for non-GET methods). Call before Handler.
func (p *Portal) MountUser(pattern string, h http.Handler) {
	p.mounts = append(p.mounts, mount{pattern: pattern, handler: h, csrf: !strings.HasPrefix(pattern, "GET ")})
}

// MountAdmin registers an extra route behind the admin check: non-admins get
// the portal's 404. The CSRF check applies to non-GET methods. Call before
// Handler.
func (p *Portal) MountAdmin(pattern string, h http.Handler) {
	p.mounts = append(p.mounts, mount{pattern: pattern, handler: h, admin: true, csrf: !strings.HasPrefix(pattern, "GET ")})
}

// static serves the embedded assets without directory listings.
func (p *Portal) static() http.Handler {
	files := http.FileServer(http.FS(static.FS))
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

type adminUsersData struct {
	Users     []identity.UserSummary
	Roles     []store.Role
	Deletable bool
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
	return adminUsersData{Users: users, Roles: roles, Deletable: p.lifecycle != nil}, nil
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
			row := userRow{Principal: identity.PrincipalFrom(r.Context()), User: u, Roles: data.Roles, Deletable: data.Deletable}
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
	err := p.tpl.render(w, status, name, "", page{Principal: identity.PrincipalFrom(r.Context()), Nav: nav.FromRequest(r), Data: data})
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
