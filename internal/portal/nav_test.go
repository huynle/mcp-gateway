package portal_test

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

// assertNav checks a page carries exactly one shared nav with the member
// or admin link set, and never an /admin/ link for a member.
func assertNav(t *testing.T, what, body string, admin bool) {
	t.Helper()
	want := navtest.Member
	if admin {
		want = navtest.Admin
	}
	if n := navtest.Count(body); n != 1 {
		t.Errorf("%s: %d site navs, want 1:\n%s", what, n, body)
	}
	if got := navtest.Links(body); !slices.Equal(got, want) {
		t.Errorf("%s: nav links = %v, want %v", what, got, want)
	}
	if !admin && strings.Contains(body, `href="/admin/`) {
		t.Errorf("%s: member page links an admin route:\n%s", what, body)
	}
}

// The portal's own pages render the shared nav: the same links on every
// page, admin links for admins only.
func TestPortalPagesShowTheSharedNav(t *testing.T) {
	h := newHarness(t)
	member, _ := h.session(t, memberSub, "Member")
	admin, _ := h.session(t, adminSub, "Admin")
	for _, c := range []struct {
		path  string
		admin bool
	}{
		{"/account", false}, {"/no-such-page", false}, {"/admin/users", false},
		{"/account", true}, {"/no-such-page", true}, {"/admin/users", true},
	} {
		ck := member
		if c.admin {
			ck = admin
		}
		body := h.do(t, request{method: http.MethodGet, path: c.path, cookie: ck}).Body.String()
		assertNav(t, fmt.Sprintf("%s (admin=%v)", c.path, c.admin), body, c.admin)
	}
	// Signed out: the brand only.
	if body := h.do(t, request{method: http.MethodGet, path: "/signin"}).Body.String(); navtest.Count(body) != 0 || strings.Contains(body, "/auth/signout") {
		t.Errorf("sign-in page shows the nav:\n%s", body)
	}
}

// Mounted module pages get the nav data from the request: signed in, the
// session's CSRF token and the server-side admin flag.
func TestMountedHandlersGetNavData(t *testing.T) {
	h := newHarness(t)
	p := h.portal
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := nav.FromRequest(r)
		_, _ = fmt.Fprintf(w, "%v|%v|%s|%s|%s", d.SignedIn, d.IsAdmin, d.CSRFToken, d.DisplayName, d.Active)
	})
	p.MountUser("GET /echo", echo)
	p.MountAdmin("GET /admin/echo", echo)
	h.h = p.Handler()
	member, mp := h.session(t, memberSub, "Member")
	admin, ap := h.session(t, adminSub, "Admin")
	for _, c := range []struct {
		path string
		ck   *http.Cookie
		want string
	}{
		{"/echo", member, "true|false|" + mp.CSRFToken + "|Member|/echo"},
		{"/echo", admin, "true|true|" + ap.CSRFToken + "|Admin|/echo"},
		{"/admin/echo", admin, "true|true|" + ap.CSRFToken + "|Admin|/admin/echo"},
	} {
		if got := h.do(t, request{method: http.MethodGet, path: c.path, cookie: c.ck}).Body.String(); got != c.want {
			t.Errorf("GET %s = %q, want %q", c.path, got, c.want)
		}
	}
}
