package nav_test

import (
	"bytes"
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav"
)

func TestForBindsTheRequestsNavDataPerClone(t *testing.T) {
	base := nav.Setup(template.New(""))
	template.Must(base.New("page").Parse(`{{template "nav" navData}}`))

	render := func(d *nav.Data) string {
		r := httptest.NewRequest("GET", "/tokens", nil)
		if d != nil {
			r = r.WithContext(nav.WithData(r.Context(), *d))
		}
		c, err := nav.For(base, r)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := c.ExecuteTemplate(&b, "page", nil); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	admin := render(&nav.Data{SignedIn: true, IsAdmin: true, CSRFToken: "t"})
	member := render(&nav.Data{SignedIn: true, CSRFToken: "t"})
	anon := render(nil)

	for _, href := range []string{"/admin/users", "/admin/roles", "/admin/audit", "/admin/vendor-apps"} {
		if !strings.Contains(admin, `href="`+href+`"`) {
			t.Errorf("admin bar lacks %s", href)
		}
		if strings.Contains(member, href) {
			t.Errorf("member bar shows %s", href)
		}
	}
	for _, href := range []string{"/account", "/tokens", "/connections", "/approvals", "/operations", "/harnesses", "/activity"} {
		if !strings.Contains(member, `href="`+href+`"`) {
			t.Errorf("member bar lacks %s", href)
		}
	}
	if !strings.Contains(member, `href="/tokens" aria-current="page"`) {
		t.Error("current page not marked")
	}
	if strings.Contains(anon, "/tokens") || strings.Contains(anon, "signout") {
		t.Error("anonymous bar shows user links")
	}
	// The base set is never executed, so it can be cloned again.
	if _, err := nav.For(base, httptest.NewRequest("GET", "/", nil)); err != nil {
		t.Fatalf("base set no longer clonable: %v", err)
	}
}
