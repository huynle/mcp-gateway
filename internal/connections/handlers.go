package connections

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/portal/nav"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Identity resolves the caller of a portal page: the session's user ID
// (empty when not signed in), its CSRF token (echoed by every form) and
// whether the user is an admin. The portal module supplies it so this
// package never touches sessions.
type Identity func(r *http.Request) (userID, csrfToken string, isAdmin bool)

//go:embed templates/*.html
var templateFS embed.FS

// Portal serves the connection pages.
//
// User pages (MountUser, behind the portal's signed-in and CSRF checks):
//
//	GET  /connections                     per vendor: connected accounts (label, name,
//	                                      scopes, status, reconnect / disconnect /
//	                                      grant more access) and connect buttons
//	POST /connections/{id}/disconnect     revoke at the vendor, delete the tokens
//
// Connect flow (MountConnect, behind the signed-in check; GET only):
//
//	GET  /connect/{vendor}/start?variant=&scopes=&return_to=
//	GET  /connect/{vendor}/callback       the vendor's redirect target
//
// Admin pages (MountAdmin; admins only, the portal's 404 for everyone
// else; CSRF on POST):
//
//	GET  /admin/vendor-apps                        every vendor and variant, configured or not
//	GET  /admin/vendor-apps/{vendor}               editor (default variant)
//	POST /admin/vendor-apps/{vendor}
//	GET  /admin/vendor-apps/{vendor}/{variant}     editor (google internal|external)
//	POST /admin/vendor-apps/{vendor}/{variant}
//
// The client secret is write-only: the editor never renders it.
type Portal struct {
	svc *Service
	who Identity
	log *slog.Logger
	tpl *template.Template
}

// NewPortal builds the pages over svc.
func NewPortal(svc *Service, who Identity, log *slog.Logger) *Portal {
	if log == nil {
		log = slog.Default()
	}
	tpl := template.Must(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
		"join":    func(s []string) string { return strings.Join(s, " ") },
		"title":   titleCase,
	}).ParseFS(templateFS, "templates/*.html"))
	return &Portal{svc: svc, who: who, log: log, tpl: tpl}
}

// MountUser registers the user pages through mount (portal.MountUser).
func (p *Portal) MountUser(mount func(pattern string, handler http.Handler)) {
	mount("GET /connections", p.withUser(p.list))
	mount("POST /connections/{id}/disconnect", p.withUser(p.disconnect))
}

// MountConnect registers the connect flow routes through mount
// (portal.MountUser: the callback needs the session to bind the flow to
// the user).
func (p *Portal) MountConnect(mount func(pattern string, handler http.Handler)) {
	mount("GET /connect/{vendor}/start", p.withUser(p.start))
	mount("GET /connect/{vendor}/callback", p.withUser(p.callback))
}

// MountAdmin registers the admin pages through mount (portal.MountAdmin).
func (p *Portal) MountAdmin(mount func(pattern string, handler http.Handler)) {
	mount("GET /admin/vendor-apps", p.admin(p.adminList))
	mount("GET /admin/vendor-apps/{vendor}", p.admin(p.adminEdit))
	mount("POST /admin/vendor-apps/{vendor}", p.admin(p.adminSave))
	mount("GET /admin/vendor-apps/{vendor}/{variant}", p.admin(p.adminEdit))
	mount("POST /admin/vendor-apps/{vendor}/{variant}", p.admin(p.adminSave))
}

// caller is the signed-in user as the templates see them.
type caller struct {
	UserID    string
	CSRFToken string
	IsAdmin   bool
}

type handler func(w http.ResponseWriter, r *http.Request, c caller)

func (p *Portal) withUser(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, csrfToken, isAdmin := p.who(r)
		if userID == "" {
			http.Error(w, "sign in to manage your connections", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r, caller{UserID: userID, CSRFToken: csrfToken, IsAdmin: isAdmin})
	})
}

// admin refuses anyone who is not a signed-in admin with a plain 404: the
// pages do not exist for them (decision 7datr7x4).
func (p *Portal) admin(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, csrfToken, isAdmin := p.who(r)
		if userID == "" || !isAdmin {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r, caller{UserID: userID, CSRFToken: csrfToken, IsAdmin: true})
	})
}

// --- user pages ----------------------------------------------------------------

// vendorSection is one vendor on the connections page.
type vendorSection struct {
	Vendor      string
	Apps        []VendorApp // enabled variants
	Connections []Info
}

type listData struct {
	Title   string
	Caller  caller
	Vendors []vendorSection
	Notice  string
	Error   string
}

func (p *Portal) list(w http.ResponseWriter, r *http.Request, c caller) {
	byVendor, order, err := p.svc.EnabledApps(r.Context())
	if err != nil {
		p.fail(w, r, "list vendor apps", err)
		return
	}
	conns, err := p.svc.Connections(r.Context(), c.UserID)
	if err != nil {
		p.fail(w, r, "list connections", err)
		return
	}
	data := listData{Title: "Connections", Caller: c}
	for _, v := range order {
		sec := vendorSection{Vendor: v, Apps: byVendor[v]}
		for _, cn := range conns {
			if cn.Vendor == v && cn.Status != store.ConnectionRevoked {
				sec.Connections = append(sec.Connections, cn)
			}
		}
		data.Vendors = append(data.Vendors, sec)
	}
	q := r.URL.Query()
	switch {
	case q.Get("connected") != "":
		data.Notice = "Account connected."
	case q.Get("disconnected") != "":
		data.Notice = "Account disconnected. Its tokens were deleted."
	}
	data.Error = flowErrorMessage(q.Get("error"))
	p.render(w, r, http.StatusOK, "connections.html", data)
}

func (p *Portal) disconnect(w http.ResponseWriter, r *http.Request, c caller) {
	err := p.svc.Disconnect(r.Context(), c.UserID, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound) || isBadUUID(err):
		http.Error(w, "no such connection", http.StatusNotFound)
		return
	case err != nil:
		p.fail(w, r, "disconnect", err)
		return
	}
	http.Redirect(w, r, "/connections?disconnected=1", http.StatusSeeOther)
}

// --- connect flow --------------------------------------------------------------

func (p *Portal) start(w http.ResponseWriter, r *http.Request, c caller) {
	q := r.URL.Query()
	redirect, err := p.svc.Start(r.Context(), StartRequest{
		UserID: c.UserID, Vendor: r.PathValue("vendor"), Variant: q.Get("variant"),
		Scopes: SplitScopes(q.Get("scopes")), ReturnTo: safeReturnTo(q.Get("return_to")),
	})
	switch {
	case errors.Is(err, ErrNotConfigured):
		http.Error(w, "this vendor is not configured", http.StatusNotFound)
		return
	case err != nil:
		p.fail(w, r, "start connect flow", err)
		return
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (p *Portal) callback(w http.ResponseWriter, r *http.Request, c caller) {
	q := r.URL.Query()
	info, err := p.svc.Callback(r.Context(), CallbackRequest{
		UserID: c.UserID, Vendor: r.PathValue("vendor"), State: q.Get("state"), Code: q.Get("code"),
		Error: q.Get("error"), ErrorDescription: q.Get("error_description"),
	})
	var class string
	switch {
	case err == nil:
		http.Redirect(w, r, "/connections?connected="+url.QueryEscape(info.ID), http.StatusSeeOther)
		return
	case errors.Is(err, ErrPersonalRefused):
		class = "personal_refused"
	case errors.Is(err, ErrVendorDenied):
		class = "vendor_denied"
	case errors.Is(err, ErrFlowInvalid):
		class = "flow_invalid"
	case errors.Is(err, ErrNotConfigured):
		class = "not_configured"
	default:
		p.fail(w, r, "finish connect flow", err)
		return
	}
	http.Redirect(w, r, "/connections?error="+class, http.StatusSeeOther)
}

// flowErrorMessage turns the error class carried in the query string into
// the sentence the connections page shows.
func flowErrorMessage(class string) string {
	switch class {
	case "personal_refused":
		return "That is a personal account and your role does not allow personal accounts for this app. Connect a company account instead, or ask an admin."
	case "vendor_denied":
		return "The vendor did not authorize the connection. Nothing was stored."
	case "flow_invalid":
		return "The connection could not be completed (the request was stale or did not match). Start again."
	case "not_configured":
		return "This vendor is not configured yet. Ask an admin."
	}
	return ""
}

// safeReturnTo accepts only same-origin paths.
func safeReturnTo(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.Contains(s, "\\") {
		return ""
	}
	return s
}

// --- admin pages ---------------------------------------------------------------

// adminRow is one vendor/variant on the admin list.
type adminRow struct {
	Vendor     string
	Variant    string
	Path       string
	Configured bool
	Enabled    bool
	ClientID   string
	UpdatedAt  time.Time
}

type adminListData struct {
	Title  string
	Caller caller
	Rows   []adminRow
}

func (p *Portal) adminList(w http.ResponseWriter, r *http.Request, c caller) {
	apps, err := p.svc.VendorApps(r.Context())
	if err != nil {
		p.fail(w, r, "list vendor apps", err)
		return
	}
	byKey := map[string]VendorApp{}
	for _, a := range apps {
		byKey[a.Vendor+"/"+a.Variant] = a
	}
	data := adminListData{Title: "Vendor apps", Caller: c}
	seen := map[string]bool{}
	add := func(vendor, variant string) {
		key := vendor + "/" + variant
		if seen[key] {
			return
		}
		seen[key] = true
		row := adminRow{Vendor: vendor, Variant: variant, Path: adminPath(vendor, variant)}
		if a, ok := byKey[key]; ok {
			row.Configured, row.Enabled, row.ClientID, row.UpdatedAt = true, a.Enabled, a.ClientID, a.UpdatedAt
		}
		data.Rows = append(data.Rows, row)
	}
	for _, v := range Vendors {
		for _, variant := range Variants(v) {
			add(v, variant)
		}
	}
	var extra []string
	for key := range byKey {
		if !seen[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	for _, key := range extra {
		vendor, variant, _ := strings.Cut(key, "/")
		add(vendor, variant)
	}
	p.render(w, r, http.StatusOK, "admin_vendor_apps.html", data)
}

func adminPath(vendor, variant string) string {
	if vendor == VendorGoogle {
		return "/admin/vendor-apps/" + vendor + "/" + variant
	}
	return "/admin/vendor-apps/" + vendor
}

// adminFormData is the editor; no secret value is ever part of it.
type adminFormData struct {
	Title        string
	Caller       caller
	App          VendorApp
	Path         string
	ExtraText    string
	ScopesText   string
	RedirectURL  string
	ExtraSecrets []secretField
	Error        string
	Saved        bool
}

// secretField is one write-only extra secret input of the editor.
type secretField struct {
	Key, Label, Hint string
	Stored           bool
}

// secretFields describes the vendor's extra secrets for the editor.
func secretFields(app VendorApp) []secretField {
	var out []secretField
	for _, key := range ExtraSecretKeys(app.Vendor) {
		f := secretField{Key: key, Stored: slices.Contains(app.SecretKeys, key)}
		switch key {
		case SecretSlackBotToken:
			f.Label, f.Hint = "Bot User OAuth token", "xoxb-…; the approval notifier DMs with it; needed for Slack approvals"
		case SecretSlackSigningSecret:
			f.Label, f.Hint = "Signing secret", "Basic Information → App Credentials; verifies /slack/interactions"
		default:
			f.Label, f.Hint = key, "optional"
		}
		out = append(out, f)
	}
	return out
}

func (p *Portal) adminEdit(w http.ResponseWriter, r *http.Request, c caller) {
	vendor, variant := normalizeKey(r.PathValue("vendor"), r.PathValue("variant"))
	if !KnownVendor(vendor) || !contains(Variants(vendor), variant) {
		http.NotFound(w, r)
		return
	}
	app, err := p.svc.VendorApp(r.Context(), vendor, variant)
	switch {
	case errors.Is(err, store.ErrNotFound):
		app = Defaults(vendor, variant)
	case err != nil:
		p.fail(w, r, "load vendor app", err)
		return
	}
	p.render(w, r, http.StatusOK, "admin_vendor_app.html", p.formData(c, app, r.URL.Query().Get("saved") == "1", ""))
}

func (p *Portal) formData(c caller, app VendorApp, saved bool, errMsg string) adminFormData {
	var extra []string
	for k, v := range app.Extra {
		extra = append(extra, k+"="+v)
	}
	sort.Strings(extra)
	return adminFormData{
		Title: titleCase(app.Vendor) + " app", Caller: c, App: app, Path: adminPath(app.Vendor, app.Variant),
		ExtraText: strings.Join(extra, "\n"), ScopesText: strings.Join(app.Scopes, "\n"),
		RedirectURL: p.svc.RedirectURL(app.Vendor), ExtraSecrets: secretFields(app), Error: errMsg, Saved: saved,
	}
}

func (p *Portal) adminSave(w http.ResponseWriter, r *http.Request, c caller) {
	vendor, variant := normalizeKey(r.PathValue("vendor"), r.PathValue("variant"))
	if !KnownVendor(vendor) || !contains(Variants(vendor), variant) {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	app := VendorApp{
		Vendor: vendor, Variant: variant,
		ClientID: f.Get("client_id"), ClientSecret: f.Get("client_secret"),
		AuthURL: f.Get("auth_url"), TokenURL: f.Get("token_url"), UserInfoURL: f.Get("userinfo_url"), RevokeURL: f.Get("revoke_url"),
		Scopes: SplitScopes(f.Get("scopes")), Extra: parseExtra(f.Get("extra")), Enabled: f.Get("enabled") != "",
		Secrets: map[string]string{},
	}
	for _, key := range ExtraSecretKeys(vendor) {
		app.Secrets[key] = f.Get(key)
	}
	saved, err := p.svc.SaveVendorApp(r.Context(), c.UserID, app)
	switch {
	case errors.Is(err, ErrInvalidVendorApp):
		app.ClientSecret, app.Secrets = "", nil
		if existing, lookErr := p.svc.VendorApp(r.Context(), vendor, variant); lookErr == nil {
			app.HasSecret, app.SecretKeys = existing.HasSecret, existing.SecretKeys
		}
		p.render(w, r, http.StatusBadRequest, "admin_vendor_app.html", p.formData(c, app, false, userMessage(err)))
		return
	case err != nil:
		p.fail(w, r, "save vendor app", err)
		return
	}
	http.Redirect(w, r, adminPath(saved.Vendor, saved.Variant)+"?saved=1", http.StatusSeeOther)
}

// parseExtra reads "key=value" lines.
func parseExtra(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(k) == "" {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// userMessage strips the sentinel prefix from a validation error.
func userMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), ErrInvalidVendorApp.Error()+": ")
	if msg == "" {
		return "The form is invalid."
	}
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}

func titleCase(s string) string {
	switch s {
	case VendorGitHub:
		return "GitHub"
	case "":
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// isBadUUID recognises PostgreSQL's complaint about an id that is not a
// uuid (invalid_text_representation, 22P02): for the portal that is "no
// such connection", not a server error.
func isBadUUID(err error) bool {
	return err != nil && strings.Contains(err.Error(), "22P02")
}

// --- rendering ---------------------------------------------------------------

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

func (p *Portal) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.log.Error("connections page failed", "event", "connections.page_failed", "what", what, "path", r.URL.Path,
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}
