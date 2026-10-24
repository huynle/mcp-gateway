package nav_test

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/portal/static"
)

func render(t *testing.T, d nav.Data) string {
	t.Helper()
	tpl := template.Must(nav.Add(template.New("page")))
	tpl = template.Must(tpl.Parse(`<body>{{template "nav" .}}</body>`))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, d); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestMemberSeesUserLinksOnly(t *testing.T) {
	body := render(t, nav.Data{SignedIn: true, CSRFToken: "c-1"})
	if got := navtest.Links(body); !slices.Equal(got, navtest.Member) {
		t.Errorf("member links = %v, want %v", got, navtest.Member)
	}
	if strings.Contains(body, "/admin/") {
		t.Errorf("member nav mentions an admin route:\n%s", body)
	}
	if !strings.Contains(body, `action="/auth/signout"`) || !strings.Contains(body, `value="c-1"`) {
		t.Errorf("no sign-out form with the CSRF token:\n%s", body)
	}
}

func TestAdminSeesAdminLinks(t *testing.T) {
	body := render(t, nav.Data{SignedIn: true, IsAdmin: true, CSRFToken: "c-2", DisplayName: "Ada <admin>"})
	if got := navtest.Links(body); !slices.Equal(got, navtest.Admin) {
		t.Errorf("admin links = %v, want %v", got, navtest.Admin)
	}
	if !strings.Contains(body, "Ada &lt;admin&gt;") {
		t.Errorf("display name missing or unescaped:\n%s", body)
	}
}

func TestAnonymousSeesBrandOnly(t *testing.T) {
	// IsAdmin without a signed-in user must not leak links either.
	body := render(t, nav.Data{IsAdmin: true})
	if got := navtest.Links(body); len(got) != 0 {
		t.Errorf("anonymous links = %v, want none", got)
	}
	if strings.Contains(body, "signout") || !strings.Contains(body, `href="/"`) {
		t.Errorf("anonymous header:\n%s", body)
	}
}

func TestActiveLinkIsMarked(t *testing.T) {
	for path, want := range map[string]string{
		"/tokens/new":         "/tokens",
		"/approvals/history":  "/approvals",
		"/admin/roles/member": "/admin/roles",
		"/account":            "/account",
	} {
		body := render(t, nav.Data{SignedIn: true, IsAdmin: true, Active: path})
		if got := navtest.Current(body); got != want {
			t.Errorf("Active %q: current link = %q, want %q", path, got, want)
		}
	}
	if got := navtest.Current(render(t, nav.Data{SignedIn: true, Active: "/tokensx"})); got != "" {
		t.Errorf("prefix without a slash marked %q current", got)
	}
}

func TestFromRequest(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/operations?x=1", nil)
	if got := nav.FromRequest(r); got.SignedIn || got.IsAdmin || got.Active != "/operations" {
		t.Errorf("no data in context: %+v", got)
	}
	in := nav.Data{SignedIn: true, IsAdmin: true, CSRFToken: "c", DisplayName: "Ada"}
	r = r.WithContext(nav.WithData(r.Context(), in))
	want := in
	want.Active = "/operations"
	if got := nav.FromRequest(r); got != want {
		t.Errorf("FromRequest = %+v, want %+v", got, want)
	}
}

// page renders a minimal page on the shared shell: the "page.head"
// partial inside <head> and the nav bar.
func page(t *testing.T, d nav.Data) string {
	t.Helper()
	tpl := template.Must(nav.Add(template.New("page")))
	tpl = template.Must(tpl.Parse(`<!doctype html><html lang="en"><head>{{template "page.head"}}<title>x</title></head><body>{{template "nav" .}}<main></main></body></html>`))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, d); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The shared head links the one stylesheet and the theme script, so every
// module's layout that includes it looks the same.
func TestPageHeadIsTheSharedShell(t *testing.T) {
	for _, d := range []nav.Data{{}, {SignedIn: true, IsAdmin: true, CSRFToken: "c"}} {
		body := page(t, d)
		navtest.AssertShell(t, fmt.Sprintf("signed in %v", d.SignedIn), body)
		htmx, _ := static.URL("htmx.min.js")
		pwa, _ := static.URL("pwa.js")
		touch, _ := static.URL("icons/apple-touch-icon.png")
		for _, want := range []string{
			`<meta charset="utf-8">`,
			`<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">`,
			`<link rel="manifest" href="/manifest.webmanifest">`,
			`<meta name="theme-color" content="#0e7268" media="(prefers-color-scheme: light)">`,
			`<meta name="theme-color" content="#0d0f12" media="(prefers-color-scheme: dark)">`,
			`<link rel="apple-touch-icon" href="` + touch + `">`,
			`<meta name="apple-mobile-web-app-capable" content="yes">`,
			`<meta name="mobile-web-app-capable" content="yes">`,
			`<meta name="apple-mobile-web-app-status-bar-style" content="default">`,
			`<meta name="apple-mobile-web-app-title" content="Gateway">`,
			`<script src="` + pwa + `" defer></script>`,
			`<meta name="referrer" content="no-referrer">`,
			`<meta name="color-scheme" content="light dark">`,
			`<script src="` + htmx + `" defer></script>`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("head lacks %s:\n%s", want, body)
			}
		}
	}
}

// The shell assertion catches a page that drifted: its own <style>, no
// shared stylesheet, no toggle.
func TestShellProblemsCatchesDrift(t *testing.T) {
	drifted := `<!doctype html><html lang="en"><head><style>body{}</style></head><body><header><nav class="site-nav"></nav></header><h1>x</h1></body></html>`
	got := strings.Join(navtest.ShellProblems(drifted), "\n")
	for _, want := range []string{"shared stylesheet", "theme script", "theme toggle", "<main>", "<style>"} {
		if !strings.Contains(got, want) {
			t.Errorf("drifted page: problems lack %q:\n%s", want, got)
		}
	}
}

// The theme toggle is on every page, signed in or not: three buttons
// (light, system, dark) in a labelled group, each with aria-pressed. It is
// rendered hidden; theme.js reveals it, so without JavaScript there is no
// dead control and the page follows the system setting.
func TestThemeToggleIsAccessibleAndHiddenWithoutJS(t *testing.T) {
	for _, d := range []nav.Data{{}, {SignedIn: true, CSRFToken: "c"}} {
		body := render(t, d)
		at := strings.Index(body, `data-theme-toggle`)
		if at < 0 {
			t.Fatalf("no toggle (signed in %v):\n%s", d.SignedIn, body)
		}
		toggle, _, _ := strings.Cut(body[at:], "</div>")
		open, _, _ := strings.Cut(body[strings.LastIndex(body[:at], "<"):], ">")
		for _, want := range []string{`role="group"`, `aria-label="Color theme"`, "hidden"} {
			if !strings.Contains(open, want) {
				t.Errorf("toggle element %q lacks %s", open, want)
			}
		}
		for _, choice := range []string{"light", "system", "dark"} {
			want := `<button type="button" class="theme-choice" data-theme-choice="` + choice + `" aria-pressed="`
			if !strings.Contains(toggle, want) {
				t.Errorf("toggle lacks the %s button (%s):\n%s", choice, want, toggle)
			}
		}
		if strings.Count(toggle, "<button") != 3 {
			t.Errorf("toggle has %d buttons, want 3:\n%s", strings.Count(toggle, "<button"), toggle)
		}
	}
}

// /servers (a member's servers) and /admin/servers (every server) must not
// share a label in the admin's bar.
func TestAdminServersLinkIsLabelledAllServers(t *testing.T) {
	body := render(t, nav.Data{SignedIn: true, IsAdmin: true})
	if !regexp.MustCompile(`href="/admin/servers">(<svg[^>]*>.*?</svg>)?All servers</a>`).MatchString(body) {
		t.Errorf("admin servers link is not labelled All servers:\n%s", body)
	}
	if n := strings.Count(body, ">Servers</a>"); n != 1 {
		t.Errorf("%d links labelled Servers, want 1:\n%s", n, body)
	}
}

// The sidebar groups its links under headings, in order, and the Admin
// group exists only for admins.
func TestSidebarGroupsLinks(t *testing.T) {
	labels := func(body string) []string {
		var out []string
		for _, m := range regexp.MustCompile(`<p class="nav-label">([^<]*)</p>`).FindAllStringSubmatch(body, -1) {
			out = append(out, m[1])
		}
		return out
	}
	if got, want := labels(render(t, nav.Data{SignedIn: true})), []string{"Access", "Integrations", "Activity"}; !slices.Equal(got, want) {
		t.Errorf("member groups = %v, want %v", got, want)
	}
	if got, want := labels(render(t, nav.Data{SignedIn: true, IsAdmin: true})), []string{"Access", "Integrations", "Activity", "Admin"}; !slices.Equal(got, want) {
		t.Errorf("admin groups = %v, want %v", got, want)
	}
	if got := labels(render(t, nav.Data{IsAdmin: true})); len(got) != 0 {
		t.Errorf("anonymous groups = %v, want none", got)
	}
}

// Every link carries an icon, and the icon is decorative (the label is the
// accessible name).
func TestEveryLinkHasADecorativeIcon(t *testing.T) {
	body := render(t, nav.Data{SignedIn: true, IsAdmin: true})
	links := regexp.MustCompile(`<a class="nav-link"[^>]*>(.*?)</a>`).FindAllStringSubmatch(body, -1)
	if len(links) != len(navtest.Admin) {
		t.Fatalf("%d nav links, want %d", len(links), len(navtest.Admin))
	}
	for _, l := range links {
		if !strings.HasPrefix(l[1], `<svg class="icon`) || !strings.Contains(l[1], `aria-hidden="true"`) {
			t.Errorf("link without a decorative icon: %s", l[0])
		}
	}
}

func TestIconRejectsUnknownNames(t *testing.T) {
	if _, err := nav.Icon("no-such-icon"); err == nil {
		t.Error("Icon accepted an unknown name")
	}
	got, err := nav.Icon("servers")
	if err != nil || !strings.HasPrefix(string(got), `<svg class="icon icon-servers" viewBox="0 0 24 24" aria-hidden="true"`) {
		t.Errorf("Icon(servers) = %q, %v", got, err)
	}
}

// Narrow screens open the sidebar with a labelled checkbox and a menu
// button (no script); the signed-out bar has neither.
func TestDrawerToggle(t *testing.T) {
	body := render(t, nav.Data{SignedIn: true})
	for _, want := range []string{
		`<input type="checkbox" id="nav-drawer" class="drawer-toggle" aria-label="Show navigation" aria-controls="sidebar">`,
		`<label for="nav-drawer" class="menu-button"`,
		`<aside class="sidebar" id="sidebar">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("signed-in shell lacks %s", want)
		}
	}
	if anon := render(t, nav.Data{}); strings.Contains(anon, "nav-drawer") || strings.Contains(anon, "sidebar") {
		t.Errorf("anonymous shell has a drawer:\n%s", anon)
	}
}

func TestUserBlockShowsInitial(t *testing.T) {
	for name, want := range map[string]string{"ada lovelace": "A", "  émile": "É", "": "?"} {
		if got := (nav.Data{DisplayName: name}).Initial(); got != want {
			t.Errorf("Initial(%q) = %q, want %q", name, got, want)
		}
	}
}
