// Package nav is the portal's shared page shell (Brain tasks cku0a6fa and
// the ui-theme and ui-redesign work): one sidebar navigation and one <head>
// for every module that renders portal pages (portal, tokens, approvals,
// ledger, connections, authserver, policy, audit, secrets, machines,
// federation). A module adds Partial to its template set with Setup (or
// Add) and its layout renders
//
//	<head>{{template "page.head"}}<title>…</title></head>
//	<body>{{template "nav" navData}}<main>…</main>{{template "footer"}}</body>
//
// so the link set, the stylesheet, the theme script and the theme toggle
// are defined once and are the same on every page. navtest.AssertShell
// checks a rendered page against this shell.
//
// Signed in, "nav" renders a grouped sidebar (Groups, plus Admin for
// admins) with the user block, the theme toggle and sign-out at its foot,
// and a top bar with a menu button that opens the sidebar as a drawer on
// narrow screens (a checkbox and labels: no script needed). Signed out it
// renders a slim top bar with the brand and the theme toggle.
//
// The data comes from the request context: the portal's session
// middleware stores it with WithData (from the signed-in principal, so the
// admin flag is the same server-side check that gates /admin/*), and
// handlers read it with FromRequest. A request without it renders as
// anonymous. Apart from the asset package (internal/portal/static) this
// package imports nothing of the gateway, so any module can use it without
// an import cycle.
package nav

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/huynle/mcp-gateway/internal/portal/static"
)

// Link is one entry of the sidebar. Icon names an icon of Icon.
type Link struct {
	Href  string
	Label string
	Icon  string
}

// Item is a Link as rendered: Current marks the page being shown.
type Item struct {
	Link
	Current bool
}

// Group is a labelled section of the sidebar. An empty Label renders the
// links without a heading.
type Group struct {
	Label string
	Links []Link
}

// GroupItems is a Group as rendered.
type GroupItems struct {
	Label string
	Items []Item
}

// Groups are shown to every signed-in user, in order.
var Groups = []Group{
	{"", []Link{
		{"/account", "My account", "account"},
	}},
	{"Access", []Link{
		{"/tokens", "Tokens", "tokens"},
		{"/harnesses", "Harnesses", "harnesses"},
		{"/machines", "Machines", "machines"},
	}},
	{"Integrations", []Link{
		{"/connections", "Connections", "connections"},
		{"/servers", "Servers", "servers"},
		{"/secrets", "Secrets", "secrets"},
	}},
	{"Activity", []Link{
		{"/approvals", "Approvals", "approvals"},
		{"/operations", "Operations", "operations"},
		{"/activity", "Activity", "activity"},
	}},
}

// AdminGroup is added for admins only.
var AdminGroup = Group{"Admin", []Link{
	{"/admin/settings", "Settings", "settings"},
	{"/admin/users", "Users", "users"},
	{"/admin/roles", "Roles", "roles"},
	{"/admin/servers", "All servers", "allservers"},
	{"/admin/machines", "All machines", "allmachines"},
	{"/admin/insights", "Insights", "insights"},
	{"/admin/audit", "Audit", "audit"},
	{"/admin/vendor-apps", "Vendor apps", "vendorapps"},
}}

// UserLinks are the links of Groups in order; AdminLinks those of
// AdminGroup.
var (
	UserLinks  = flatten(Groups)
	AdminLinks = AdminGroup.Links
)

func flatten(gs []Group) []Link {
	var out []Link
	for _, g := range gs {
		out = append(out, g.Links...)
	}
	return out
}

// Data is what the partial renders.
type Data struct {
	// SignedIn shows the links and the sign-out form; without it the bar
	// is the brand only.
	SignedIn bool
	// IsAdmin adds AdminGroup (only together with SignedIn).
	IsAdmin bool
	// CSRFToken is echoed by the sign-out form.
	CSRFToken string
	// DisplayName is shown in the user block when set.
	DisplayName string
	// Active is the request path; the matching link is marked current.
	Active string
	// Notifications adds NotificationsLink after My account: Web Push is
	// on, so My account has the "Notifications" section (and the
	// approvals page offers to turn it on).
	Notifications bool
}

// NotificationsLink opens My account's "Notifications" section. Shown
// only when Data.Notifications is set.
var NotificationsLink = Link{"/account#notifications", "Notifications", "bell"}

// NavGroups is Groups, plus AdminGroup for admins, for the template;
// nothing when signed out.
func (d Data) NavGroups() []GroupItems {
	if !d.SignedIn {
		return nil
	}
	gs := Groups
	if d.IsAdmin {
		gs = append(append([]Group(nil), Groups...), AdminGroup)
	}
	out := make([]GroupItems, len(gs))
	for i, g := range gs {
		links := g.Links
		if i == 0 && d.Notifications {
			links = append(append([]Link(nil), links...), NotificationsLink)
		}
		out[i] = GroupItems{Label: g.Label, Items: d.items(links)}
	}
	return out
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

// Initial is the first letter of DisplayName, upper-cased, for the avatar
// ("?" without a name).
func (d Data) Initial() string {
	for _, r := range strings.TrimSpace(d.DisplayName) {
		return strings.ToUpper(string(r))
	}
	return "?"
}

func (d Data) items(links []Link) []Item {
	out := make([]Item, len(links))
	for i, l := range links {
		out[i] = Item{Link: l, Current: !strings.Contains(l.Href, "#") && (d.Active == l.Href || strings.HasPrefix(d.Active, l.Href+"/"))}
	}
	return out
}

// Partial defines the shared page shell every portal page is built on:
//
//   - "page.head": the contents of <head> before the <title> (meta tags,
//     the shared stylesheet, the theme script, htmx, and the installable-app
//     tags: the web app manifest, theme colours, the iOS home-screen icon
//     and pwa.js, which registers the service worker). Each layout writes
//     <head>{{template "page.head"}}<title>…</title></head>, so every page
//     loads the same assets by their versioned URLs (package static).
//     theme.js is render-blocking on purpose: it sets <html data-theme>
//     from localStorage before the first paint, so a stored choice never
//     flashes the other palette.
//   - "nav": signed in, the drawer toggle, the top bar (narrow screens) and
//     the sidebar with the brand, the grouped links, the user block, the
//     theme toggle and the sign-out form; signed out, a top bar with the
//     brand and the theme toggle.
//   - "footer": the links to the public Privacy Policy, Terms of Service
//     and Support pages (package portal); layouts render it after </main>.
//
// Neither has inline script or style (CSP). The toggle is rendered hidden
// and theme.js reveals it: without JavaScript there is no dead control and
// the page follows the system colour scheme.
const Partial = `{{define "page.head"}}<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="referrer" content="no-referrer">
  <meta name="color-scheme" content="light dark">
  <script src="{{asset "theme.js"}}"></script>
  <link rel="stylesheet" href="{{asset "portal.css"}}">
  <link rel="icon" type="image/svg+xml" href="{{asset "favicon.svg"}}">
  <script src="{{asset "htmx.min.js"}}" defer></script>
  <link rel="manifest" href="/manifest.webmanifest">
  <meta name="theme-color" content="#0e7268" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#0d0f12" media="(prefers-color-scheme: dark)">
  <link rel="apple-touch-icon" href="{{asset "icons/apple-touch-icon.png"}}">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="Gateway">
  <script src="{{asset "pwa.js"}}" defer></script>
{{- end}}

{{define "brand"}}<a class="brand" href="/">{{icon "brand"}}<span class="brand-name">MCP Gateway</span></a>{{end}}

{{define "theme.toggle"}}<div class="theme-toggle" role="group" aria-label="Color theme" data-theme-toggle hidden>
      <button type="button" class="theme-choice" data-theme-choice="light" aria-pressed="false" title="Light theme">{{icon "sun"}}<span class="sr-only">Light</span></button>
      <button type="button" class="theme-choice" data-theme-choice="system" aria-pressed="true" title="Follow the system setting">{{icon "system"}}<span class="sr-only">System</span></button>
      <button type="button" class="theme-choice" data-theme-choice="dark" aria-pressed="false" title="Dark theme">{{icon "moon"}}<span class="sr-only">Dark</span></button>
    </div>{{end}}

{{define "nav"}}{{if .SignedIn -}}
<input type="checkbox" id="nav-drawer" class="drawer-toggle" aria-label="Show navigation" aria-controls="sidebar">
<header class="topbar">
  <label for="nav-drawer" class="menu-button" title="Menu">{{icon "menu"}}<span class="sr-only">Menu</span></label>
  {{template "brand"}}
</header>
<aside class="sidebar" id="sidebar">
  <div class="sidebar-head">{{template "brand"}}</div>
  <nav class="site-nav" aria-label="Main">
    {{- range .NavGroups}}
    <div class="nav-group">
      {{- if .Label}}<p class="nav-label">{{.Label}}</p>{{end}}
      {{- range .Items}}
      <a class="nav-link" href="{{.Href}}"{{if .Current}} aria-current="page"{{end}}>{{icon .Icon}}{{.Label}}</a>
      {{- end}}
    </div>
    {{- end}}
  </nav>
  <div class="sidebar-foot">
    <div class="who">
      <span class="avatar" aria-hidden="true">{{.Initial}}</span>
      <span class="who-name">{{if .DisplayName}}{{.DisplayName}}{{else}}Signed in{{end}}</span>
    </div>
    <div class="sidebar-tools">
      {{template "theme.toggle"}}
      <form method="post" action="/auth/signout" class="signout">
        <input type="hidden" name="_csrf" value="{{.CSRFToken}}">
        <button class="btn ghost small" type="submit" title="Sign out">{{icon "signout"}}Sign out</button>
      </form>
    </div>
  </div>
</aside>
<label for="nav-drawer" class="drawer-scrim" aria-hidden="true"></label>
{{- else -}}
<header class="topbar public">
  {{template "brand"}}
  <div class="topbar-tools">{{template "theme.toggle"}}</div>
</header>
{{- end}}{{end}}

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

// IconFuncName is the template function Add registers: {{icon "servers"}}
// renders that inline SVG icon (see Icon).
const IconFuncName = "icon"

// Add parses Partial into t's template set (call it before the set is
// executed) and returns t, so it chains: template.Must(nav.Add(t)).
func Add(t *template.Template) (*template.Template, error) {
	if _, err := t.Funcs(template.FuncMap{AssetFuncName: static.URL, IconFuncName: Icon}).New("nav.partial").Parse(Partial); err != nil {
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

// Funcs is the FuncMap a module adds when it parses its template set
// (functions must exist at parse time): the placeholder navData, which
// renders the anonymous bar until For binds the real data per request,
// plus asset and icon so page templates can use them too.
func Funcs() template.FuncMap {
	return template.FuncMap{FuncName: func() Data { return Data{} }, AssetFuncName: static.URL, IconFuncName: Icon}
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
