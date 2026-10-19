// Package nav is the portal's shared page shell (Brain tasks cku0a6fa and
// the ui-theme work): one navigation bar and one <head> for every module
// that renders portal pages (portal, tokens, approvals, ledger,
// connections, authserver, policy, audit, federation). A module adds
// Partial to its template set with Setup (or Add) and its layout renders
//
//	<head>{{template "page.head"}}<title>…</title></head>
//	<body>{{template "nav" navData}}<main>…</main></body>
//
// so the link set, the stylesheet, the theme script and the theme toggle
// are defined once and are the same on every page. navtest.AssertShell
// checks a rendered page against this shell.
//
// The data comes from the request context: the portal's session
// middleware stores it with WithData (from the signed-in principal, so the
// admin flag is the same server-side check that gates /admin/*), and
// handlers read it with FromRequest. A request without it renders as
// anonymous: the brand, the theme toggle and no links. Apart from the
// asset package (internal/portal/static) this package imports nothing of
// the gateway, so any module can use it without an import cycle.
package nav

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/huynle/mcp-gateway/internal/portal/static"
)

// Link is one entry of the bar.
type Link struct {
	Href  string
	Label string
}

// Item is a Link as rendered: Current marks the page being shown.
type Item struct {
	Link
	Current bool
}

// UserLinks are shown to every signed-in user, in order.
var UserLinks = []Link{
	{"/account", "My account"},
	{"/tokens", "Tokens"},
	{"/connections", "Connections"},
	{"/servers", "Servers"},
	{"/approvals", "Approvals"},
	{"/operations", "Operations"},
	{"/harnesses", "Harnesses"},
	{"/activity", "Activity"},
}

// AdminLinks are added for admins only.
var AdminLinks = []Link{
	{"/admin/settings", "Settings"},
	{"/admin/users", "Users"},
	{"/admin/roles", "Roles"},
	{"/admin/servers", "All servers"},
	{"/admin/audit", "Audit"},
	{"/admin/vendor-apps", "Vendor apps"},
}

// Data is what the partial renders.
type Data struct {
	// SignedIn shows the links and the sign-out form; without it the bar
	// is the brand only.
	SignedIn bool
	// IsAdmin adds AdminLinks (only together with SignedIn).
	IsAdmin bool
	// CSRFToken is echoed by the sign-out form.
	CSRFToken string
	// DisplayName is shown next to the sign-out button when set.
	DisplayName string
	// Active is the request path; the matching link is marked current.
	Active string
}

// UserItems is UserLinks for the template, or nothing when signed out.
func (d Data) UserItems() []Item {
	if !d.SignedIn {
		return nil
	}
	return d.items(UserLinks)
}

// AdminItems is AdminLinks for the template, or nothing unless the user
// is a signed-in admin.
func (d Data) AdminItems() []Item {
	if !d.SignedIn || !d.IsAdmin {
		return nil
	}
	return d.items(AdminLinks)
}

func (d Data) items(links []Link) []Item {
	out := make([]Item, len(links))
	for i, l := range links {
		out[i] = Item{Link: l, Current: d.Active == l.Href || strings.HasPrefix(d.Active, l.Href+"/")}
	}
	return out
}

// Partial defines the shared page shell every portal page is built on:
//
//   - "page.head": the contents of <head> before the <title> (meta tags,
//     the shared stylesheet, the theme script, htmx). Each layout writes
//     <head>{{template "page.head"}}<title>…</title></head>, so every page
//     loads the same assets by their versioned URLs (package static).
//     theme.js is render-blocking on purpose: it sets <html data-theme>
//     from localStorage before the first paint, so a stored choice never
//     flashes the other palette.
//   - "nav": the page header with the brand, the links, the theme toggle
//     and the sign-out form.
//   - "footer": the links to the public Privacy Policy, Terms of Service
//     and Support pages (package portal); layouts render it after </main>.
//
// Neither has inline script or style (CSP). The toggle is rendered hidden
// and theme.js reveals it: without JavaScript there is no dead control and
// the page follows the system colour scheme.
const Partial = `{{define "page.head"}}<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="color-scheme" content="light dark">
  <script src="{{asset "theme.js"}}"></script>
  <link rel="stylesheet" href="{{asset "portal.css"}}">
  <script src="{{asset "htmx.min.js"}}" defer></script>
{{- end}}

{{define "theme.toggle"}}<div class="theme-toggle" role="group" aria-label="Color theme" data-theme-toggle hidden>
      <button type="button" class="theme-choice" data-theme-choice="light" aria-pressed="false" title="Light theme">Light</button>
      <button type="button" class="theme-choice" data-theme-choice="system" aria-pressed="true" title="Follow the system setting">System</button>
      <button type="button" class="theme-choice" data-theme-choice="dark" aria-pressed="false" title="Dark theme">Dark</button>
    </div>{{end}}

{{define "nav"}}<header class="site-header">
  <a class="brand" href="/">MCP Gateway</a>
  {{- if .SignedIn}}
  <nav class="site-nav" aria-label="Main">
    {{- range .UserItems}}
    <a href="{{.Href}}"{{if .Current}} aria-current="page"{{end}}>{{.Label}}</a>
    {{- end}}
    {{- range .AdminItems}}
    <a class="admin" href="{{.Href}}"{{if .Current}} aria-current="page"{{end}}>{{.Label}}</a>
    {{- end}}
  </nav>
  {{- end}}
  <div class="who">
    {{template "theme.toggle"}}
    {{- if .SignedIn}}
    {{- if .DisplayName}}
    <span class="who-name">{{.DisplayName}}</span>
    {{- end}}
    <form method="post" action="/auth/signout">
      <input type="hidden" name="_csrf" value="{{.CSRFToken}}">
      <button class="btn" type="submit">Sign out</button>
    </form>
    {{- end}}
  </div>
</header>{{end}}

{{define "footer"}}<footer class="site-footer">
  <nav aria-label="Legal">
    <a href="/privacy">Privacy Policy</a>
    <a href="/terms">Terms of Service</a>
    <a href="/support">Support</a>
    <a href="/cli">Install CLI</a>
  </nav>
</footer>{{end}}`

// AssetFuncName is the template function Add registers: {{asset "x.css"}}
// is static.URL("x.css"), the asset's path with its content-hash query.
const AssetFuncName = "asset"

// Add parses Partial into t's template set (call it before the set is
// executed) and returns t, so it chains: template.Must(nav.Add(t)).
func Add(t *template.Template) (*template.Template, error) {
	if _, err := t.Funcs(template.FuncMap{AssetFuncName: static.URL}).New("nav.partial").Parse(Partial); err != nil {
		return nil, err
	}
	return t, nil
}

type ctxKey struct{}

// WithData attaches the nav data for the request's user to ctx.
func WithData(ctx context.Context, d Data) context.Context {
	return context.WithValue(ctx, ctxKey{}, d)
}

// FromRequest returns the nav data the portal attached (the zero Data,
// i.e. anonymous, when none) with Active set to the request path.
func FromRequest(r *http.Request) Data {
	d, _ := r.Context().Value(ctxKey{}).(Data)
	d.Active = r.URL.Path
	return d
}

// FuncName is the template function modules call to get the request's nav
// data: {{template "nav" navData}}.
const FuncName = "navData"

// Funcs is the placeholder FuncMap entry a module adds when it parses its
// template set (functions must exist at parse time). It renders the
// anonymous bar; For binds the real data per request.
func Funcs() template.FuncMap {
	return template.FuncMap{FuncName: func() Data { return Data{} }}
}

// Setup adds the placeholder function and the partial to a module's
// template set: call Setup on template.New("") before ParseFS.
func Setup(t *template.Template) *template.Template {
	return template.Must(Add(t.Funcs(Funcs())))
}

// For returns a clone of t whose navData returns r's nav data. t itself must
// never be executed (html/template refuses to clone an executed set), so
// modules keep a pristine set and execute only the clones.
func For(t *template.Template, r *http.Request) (*template.Template, error) {
	c, err := t.Clone()
	if err != nil {
		return nil, err
	}
	d := FromRequest(r)
	return c.Funcs(template.FuncMap{FuncName: func() Data { return d }}), nil
}

// Execute renders name from a per-request clone of t (see For). It is the
// drop-in for t.ExecuteTemplate in module render helpers.
func Execute(t *template.Template, r *http.Request, w io.Writer, name string, data any) error {
	return ExecuteData(t, FromRequest(r), w, name, data)
}

// ExecuteData is Execute with explicit nav data, for pages rendered where no
// request is at hand (e.g. error pages, which show the anonymous bar).
func ExecuteData(t *template.Template, d Data, w io.Writer, name string, data any) error {
	c, err := t.Clone()
	if err != nil {
		return err
	}
	return c.Funcs(template.FuncMap{FuncName: func() Data { return d }}).ExecuteTemplate(w, name, data)
}
