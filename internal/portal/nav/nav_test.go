package nav_test

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
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
