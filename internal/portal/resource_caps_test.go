package portal_test

import (
	"context"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	isettings "github.com/huynle/mcp-gateway/internal/settings"
)

type fakeCaps struct {
	org    caps.Values
	users  map[string]caps.Values
	admins map[string]bool
	usage  caps.Values
	orgSet []caps.Patch
	usrSet map[string][]caps.Patch
}

func (f *fakeCaps) eff(u string) caps.Values {
	out := maps.Clone(caps.Builtin)
	maps.Copy(out, f.org)
	maps.Copy(out, f.users[u])
	return out
}
func (f *fakeCaps) Effective(_ context.Context, u string) caps.Values { return f.eff(u) }
func (f *fakeCaps) Usage(context.Context, string) (caps.Values, error) {
	return maps.Clone(f.usage), nil
}
func (f *fakeCaps) Defaults() caps.Values { return maps.Clone(caps.Builtin) }
func (f *fakeCaps) CapsSnapshot(context.Context) isettings.CapsSnapshot {
	return isettings.CapsSnapshot{Org: maps.Clone(f.org), Users: maps.Clone(f.users), Admins: f.admins}
}
func apply(v caps.Values, p caps.Patch) caps.Values {
	if v == nil {
		v = caps.Values{}
	}
	for r, n := range p {
		if n == nil {
			delete(v, r)
		} else {
			v[r] = *n
		}
	}
	return v
}
func (f *fakeCaps) SetOrg(_ context.Context, actor string, p caps.Patch) error {
	if !f.admins[actor] {
		return isettings.ErrNotAdmin
	}
	f.orgSet = append(f.orgSet, p)
	f.org = apply(f.org, p)
	return nil
}
func (f *fakeCaps) SetUser(_ context.Context, actor, u string, p caps.Patch) error {
	if !f.admins[actor] {
		return isettings.ErrNotAdmin
	}
	f.usrSet[u] = append(f.usrSet[u], p)
	f.users[u] = apply(f.users[u], p)
	return nil
}

func TestResourceCapsPages(t *testing.T) {
	h := newHarness(t)
	member, mp := h.session(t, memberSub, "Member")
	admin, ap := h.session(t, adminSub, "Admin")
	f := &fakeCaps{org: caps.Values{}, users: map[string]caps.Values{}, admins: map[string]bool{ap.UserID: true},
		usage: caps.Values{caps.Servers: 3, caps.Tunnels: 1}, usrSet: map[string][]caps.Patch{}}
	h.portal.SetResourceCaps(f)
	h.h = h.portal.Handler()

	// My account: effective limits and usage, read only.
	body := h.do(t, request{method: http.MethodGet, path: "/account", cookie: member}).Body.String()
	for _, want := range []string{`id="resource-limits"`, "Resource limits", "MCP servers", "3 of 10", "1 of 5", "ask an admin"} {
		if !strings.Contains(body, want) {
			t.Errorf("account lacks %q", want)
		}
	}

	// Admin pages are 404 for members, GET and POST alike.
	for _, rq := range []request{
		{method: http.MethodGet, path: "/admin/settings/resource-caps", cookie: member},
		{method: http.MethodPost, path: "/admin/settings/resource-caps", cookie: member, form: url.Values{"_csrf": {mp.CSRFToken}, "servers": {"100"}}},
		{method: http.MethodGet, path: "/admin/users/" + mp.UserID + "/limits", cookie: member},
		{method: http.MethodPost, path: "/admin/users/" + mp.UserID + "/limits", cookie: member, form: url.Values{"_csrf": {mp.CSRFToken}, "servers": {"100"}}},
	} {
		if rec := h.do(t, rq); rec.Code != http.StatusNotFound {
			t.Errorf("member %s %s = %d, want 404", rq.method, rq.path, rec.Code)
		}
	}
	if len(f.orgSet)+len(f.usrSet) != 0 {
		t.Fatal("member changed caps")
	}

	// Settings index links the page.
	if body := h.do(t, request{method: http.MethodGet, path: "/admin/settings", cookie: admin}).Body.String(); !strings.Contains(body, `href="/admin/settings/resource-caps"`) {
		t.Error("settings index lacks the resource caps link")
	}
	rec := h.do(t, request{method: http.MethodGet, path: "/admin/settings/resource-caps", cookie: admin})
	body = rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("admin page = %d", rec.Code)
	}
	navtest.AssertShell(t, "/admin/settings/resource-caps", body)
	for _, want := range []string{"Resource limits", `name="servers"`, `name="pending_approvals"`, "Member", `href="/admin/users/` + mp.UserID + `/limits"`, `name="_csrf"`} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page lacks %q", want)
		}
	}
	// Org: a value sets, blank clears, 0 is unlimited.
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/settings/resource-caps", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken},
		"servers": {"4"}, "tunnels": {"0"}, "connections_per_app": {""}, "connections_total": {"30"}, "pending_approvals": {""}}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("org post = %d %s", rec.Code, rec.Body)
	}
	if f.org[caps.Servers] != 4 || f.org[caps.Tunnels] != 0 || f.org[caps.ConnectionsTotal] != 30 {
		t.Fatalf("org = %v", f.org)
	}
	if _, ok := f.org[caps.PendingApprovals]; ok {
		t.Error("blank set a value")
	}
	for _, bad := range []string{"-1", "100001", "many"} {
		rec = h.do(t, request{method: http.MethodPost, path: "/admin/settings/resource-caps", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "servers": {bad}}})
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("servers=%q = %d, want 422", bad, rec.Code)
		}
	}
	// CSRF is required.
	if rec := h.do(t, request{method: http.MethodPost, path: "/admin/settings/resource-caps", cookie: admin, form: url.Values{"servers": {"9"}}}); rec.Code == http.StatusSeeOther {
		t.Error("post without CSRF accepted")
	}

	// Per user page.
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/users/" + mp.UserID + "/limits", cookie: admin})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Member") || !strings.Contains(rec.Body.String(), `action="/admin/users/`+mp.UserID+`/limits"`) {
		t.Fatalf("user page = %d", rec.Code)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/users/" + mp.UserID + "/limits", cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "servers": {"0"}, "tunnels": {"2"}}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("user post = %d %s", rec.Code, rec.Body)
	}
	if v := f.users[mp.UserID]; v[caps.Servers] != 0 || v[caps.Tunnels] != 2 {
		t.Fatalf("user caps = %v", v)
	}
	if body := h.do(t, request{method: http.MethodGet, path: "/admin/users/" + mp.UserID + "/limits", cookie: admin}).Body.String(); !strings.Contains(body, `value="2"`) {
		t.Error("user page does not show the override")
	}
	if rec := h.do(t, request{method: http.MethodGet, path: "/admin/users/00000000-0000-4000-8000-000000000999/limits", cookie: admin}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown user = %d", rec.Code)
	}
	// The users list links each user's limits.
	if body := h.do(t, request{method: http.MethodGet, path: "/admin/users", cookie: admin}).Body.String(); !strings.Contains(body, `href="/admin/users/`+mp.UserID+`/limits"`) {
		t.Error("users list lacks the limits link")
	}
}
