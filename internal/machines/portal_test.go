package machines

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/store"
)

const csrf = "csrf-token-1"

// portalEnv serves the pages with the caller taken from X-Test-User
// (admin when X-Test-Admin is set), as the portal's session would.
func (e *env) portal(t *testing.T) *httptest.Server {
	t.Helper()
	p := NewPortal(e.svc, func(r *http.Request) (string, string, bool) {
		return r.Header.Get("X-Test-User"), csrf, r.Header.Get("X-Test-Admin") != ""
	}, slog.New(slog.DiscardHandler))
	mux := http.NewServeMux()
	p.Mount(func(pattern string, h http.Handler) { mux.Handle(pattern, h) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.Header.Get("X-Test-User"); u != "" {
			r = r.WithContext(nav.WithData(r.Context(), nav.Data{SignedIn: true, CSRFToken: csrf, IsAdmin: r.Header.Get("X-Test-Admin") != ""}))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func page(t *testing.T, srv *httptest.Server, method, path, user string, admin bool, form url.Values) (int, string, http.Header) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	c := srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestActivatePageShowsTheRequestAndApprovesForTheSignedInUser(t *testing.T) {
	e := newEnv(t)
	srv := e.portal(t)
	body, _ := e.requestDevice("huy-macbook")
	uc := body["user_code"].(string)

	if code, _, _ := page(t, srv, http.MethodGet, "/activate", "", false, nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous /activate = %d", code)
	}
	code, html, h := page(t, srv, http.MethodGet, "/activate", alice, false, nil)
	if code != http.StatusOK || !strings.Contains(html, `name="code"`) || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("/activate form = %d\n%s", code, html)
	}
	code, html, _ = page(t, srv, http.MethodGet, "/activate?code="+url.QueryEscape(uc), alice, false, nil)
	d, _ := e.st.DeviceRequestByUserCode(context.Background(), HashSecret(strings.ReplaceAll(uc, "-", "")))
	for _, want := range []string{"huy-macbook", DisplayFingerprint(d.Fingerprint), "198.51.100.7", "1.0.0", "Approve", "Deny", `value="` + csrf + `"`} {
		if !strings.Contains(html, want) {
			t.Errorf("confirm page lacks %q", want)
		}
	}
	if code != http.StatusOK {
		t.Fatalf("confirm = %d", code)
	}
	// Without the CSRF token nothing happens.
	if code, _, _ := page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"action": {"approve"}, "request_id": {d.ID}, "code": {uc}}); code != http.StatusForbidden {
		t.Fatalf("approve without CSRF = %d", code)
	}
	// The request id alone is not enough: the code must match it.
	other, _ := e.requestDevice("other")
	if code, _, _ := page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"_csrf": {csrf}, "action": {"approve"}, "request_id": {d.ID}, "code": {other["user_code"].(string)}}); code == http.StatusOK {
		ms, _ := e.st.ListMachines(context.Background(), alice)
		if len(ms) != 0 {
			t.Fatal("approved with a mismatched code")
		}
	}
	code, html, _ = page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"_csrf": {csrf}, "action": {"approve"}, "request_id": {d.ID}, "code": {uc}})
	if code != http.StatusOK || !strings.Contains(html, "approved") {
		t.Fatalf("approve = %d\n%s", code, html)
	}
	ms, _ := e.st.ListMachines(context.Background(), alice)
	if len(ms) != 1 || ms[0].Name != "huy-macbook" {
		t.Fatalf("alice's machines = %+v", ms)
	}
	// The code is spent.
	code, html, _ = page(t, srv, http.MethodGet, "/activate?code="+url.QueryEscape(uc), alice, false, nil)
	if !strings.Contains(html, "No pending request") {
		t.Fatalf("spent code = %d\n%s", code, html)
	}
}

func TestActivatePageDeny(t *testing.T) {
	e := newEnv(t)
	srv := e.portal(t)
	body, _ := e.requestDevice("laptop")
	uc := body["user_code"].(string)
	d, _ := e.svc.LookupUserCode(context.Background(), bob, uc)
	code, html, _ := page(t, srv, http.MethodPost, "/activate", bob, false, url.Values{"_csrf": {csrf}, "action": {"deny"}, "request_id": {d.ID}, "code": {uc}})
	if code != http.StatusOK || !strings.Contains(html, "denied") {
		t.Fatalf("deny = %d\n%s", code, html)
	}
	if c, out := e.form(deviceGrant(body["device_code"].(string))); c != http.StatusBadRequest || out["error"] != "access_denied" {
		t.Fatalf("poll after deny = %d %v", c, out)
	}
}

func TestMachinesPageListsRevokesAndCreatesCodes(t *testing.T) {
	e := newEnv(t)
	srv := e.portal(t)
	aliceID, _ := e.enroll(alice, "laptop")
	bobID, _ := e.enroll(bob, "bob-desk")
	code, html, _ := page(t, srv, http.MethodGet, "/machines", alice, false, nil)
	m, _ := e.st.Machine(context.Background(), aliceID)
	if code != http.StatusOK || !strings.Contains(html, "laptop") || strings.Contains(html, "bob-desk") || !strings.Contains(html, DisplayFingerprint(m.Fingerprint)) {
		t.Fatalf("/machines = %d\n%s", code, html)
	}
	// Bob's machine cannot be revoked by Alice.
	if code, _, _ := page(t, srv, http.MethodPost, "/machines/"+bobID+"/revoke", alice, false, url.Values{"_csrf": {csrf}}); code != http.StatusNotFound {
		t.Fatalf("revoke bob's machine as alice = %d", code)
	}
	if code, _, h := page(t, srv, http.MethodPost, "/machines/"+aliceID+"/revoke", alice, false, url.Values{"_csrf": {csrf}}); code != http.StatusSeeOther || h.Get("Location") != "/machines?revoked=1" {
		t.Fatalf("revoke own = %d", code)
	}
	if m, _ := e.st.Machine(context.Background(), aliceID); m.RevokedAt == nil || m.RevokeReason != store.MachineRevokedByOwner {
		t.Fatalf("machine after revoke = %+v", m)
	}

	code, html, h := page(t, srv, http.MethodPost, "/machines/codes", alice, false, url.Values{"_csrf": {csrf}, "label": {"ci <box>"}, "ttl": {"24h"}})
	raw := regexp.MustCompile(`mge_[A-Za-z0-9]{8}_[A-Za-z0-9]{43}`).FindString(html)
	if code != http.StatusOK || raw == "" || !strings.Contains(html, "ci &lt;box&gt;") || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("create code = %d\n%s", code, html)
	}
	if !strings.Contains(html, "mcp-gateway login --enroll-code") {
		t.Errorf("no login command shown")
	}
	_, html, _ = page(t, srv, http.MethodGet, "/machines", alice, false, nil)
	if strings.Contains(html, raw) || !strings.Contains(html, "ci &lt;box&gt;") {
		t.Fatal("the code is shown again, or its label is missing")
	}
	if code, _, _ := page(t, srv, http.MethodPost, "/machines/codes", alice, false, url.Values{"_csrf": {csrf}, "ttl": {"30d"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad ttl = %d", code)
	}
	codes, _ := e.st.ListEnrollmentCodes(context.Background(), alice)
	if code, _, _ := page(t, srv, http.MethodPost, "/machines/codes/"+codes[0].ID+"/revoke", bob, false, url.Values{"_csrf": {csrf}}); code != http.StatusNotFound {
		t.Fatalf("bob revokes alice's code = %d", code)
	}
	if code, _, _ := page(t, srv, http.MethodPost, "/machines/codes/"+codes[0].ID+"/revoke", alice, false, url.Values{"_csrf": {csrf}}); code != http.StatusSeeOther {
		t.Fatalf("revoke own code = %d", code)
	}
}

func TestAdminMachinesPage(t *testing.T) {
	e := newEnv(t)
	srv := e.portal(t)
	aliceID, _ := e.enroll(alice, "laptop")
	e.enroll(bob, "bob-desk")
	if code, _, _ := page(t, srv, http.MethodGet, "/admin/machines", alice, false, nil); code != http.StatusNotFound {
		t.Fatalf("non-admin = %d", code)
	}
	code, html, _ := page(t, srv, http.MethodGet, "/admin/machines", bob, true, nil)
	if code != http.StatusOK || !strings.Contains(html, "laptop") || !strings.Contains(html, "bob-desk") || !strings.Contains(html, "Alice") {
		t.Fatalf("admin list = %d\n%s", code, html)
	}
	if code, _, _ := page(t, srv, http.MethodPost, "/admin/machines/"+aliceID+"/revoke", alice, false, url.Values{"_csrf": {csrf}}); code != http.StatusNotFound {
		t.Fatalf("non-admin revoke = %d", code)
	}
	if code, _, _ := page(t, srv, http.MethodPost, "/admin/machines/"+aliceID+"/revoke", bob, true, url.Values{"_csrf": {csrf}}); code != http.StatusSeeOther {
		t.Fatalf("admin revoke = %d", code)
	}
	m, _ := e.st.Machine(context.Background(), aliceID)
	if m.RevokeReason != store.MachineRevokedByAdmin || m.RevokedBy != bob {
		t.Fatalf("machine = %+v", m)
	}
}

func TestPagesUseThePortalShell(t *testing.T) {
	e := newEnv(t)
	srv := e.portal(t)
	e.enroll(alice, "laptop")
	for _, p := range []struct {
		path  string
		admin bool
	}{{"/activate", false}, {"/activate?code=BCDF-GHJK", false}, {"/machines", false}, {"/admin/machines", true}} {
		code, html, _ := page(t, srv, http.MethodGet, p.path, alice, p.admin, nil)
		if code != http.StatusOK {
			t.Fatalf("%s = %d", p.path, code)
		}
		navtest.AssertShell(t, p.path, html)
	}
}
