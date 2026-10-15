package connections_test

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/store"
)

// portalConnect runs a connect flow through the portal routes: GET the
// start path, follow the fake vendor's authorize hop, GET the callback.
// It returns the authorize request the vendor saw.
func (h *harness) portalConnect(t *testing.T, cookie *http.Cookie, v *fakeVendor, startPath string) url.Values {
	t.Helper()
	rec := h.do(t, request{method: http.MethodGet, path: startPath, cookie: cookie})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET %s = %d %q", startPath, rec.Code, rec.Header().Get("Location"))
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rec.Header().Get("Location"), nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	back, _ := url.Parse(res.Header.Get("Location"))
	rec = h.do(t, request{method: http.MethodGet, path: back.RequestURI(), cookie: cookie})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/connections?connected=") {
		t.Fatalf("callback = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	return v.lastAuthorize()
}

var grantLinkRE = regexp.MustCompile(`<a class="btn[^"]*" href="([^"]+)">(Grant more access|Reconnect)</a>`)

// grantLinks returns the decoded Grant more access / Reconnect links of
// a connections page, by label.
func grantLinks(t *testing.T, body string) map[string]*url.URL {
	t.Helper()
	out := map[string]*url.URL{}
	for _, m := range grantLinkRE.FindAllStringSubmatch(body, -1) {
		u, err := url.Parse(html.UnescapeString(m[1]))
		if err != nil {
			t.Fatalf("link %q: %v", m[1], err)
		}
		out[m[2]] = u
	}
	return out
}

// TestConnectionsPageGrantMoreAccess: a connection lacking scopes for
// tools the user may see gets a Grant more access link naming the
// missing scopes and the connection, with what it unlocks; following it
// asks the vendor for the old and the new scopes, after which nothing is
// missing and the link disappears. Connect itself asked for reads only.
func TestConnectionsPageGrantMoreAccess(t *testing.T) {
	h := newHarness(t)
	v := newFakeVendor(t)
	registerFakeApp(t, &testEnv{svc: h.conn, store: h.mem}, v)
	h.conn.SetToolCatalog(testCatalog(t), nil)
	member, _ := h.session(t, memberSub, "Member")

	first := h.portalConnect(t, member, v, "/connect/fake/start?variant=default")
	if got := first.Get("scope"); got != "read:user repo" {
		t.Errorf("connect asked for %q, want the base and the read tool's scope", got)
	}
	rec := h.do(t, request{method: http.MethodGet, path: "/connections", cookie: member})
	body := rec.Body.String()
	links := grantLinks(t, body)
	grant := links["Grant more access"]
	if rec.Code != http.StatusOK || grant == nil {
		t.Fatalf("GET /connections = %d, no Grant more access link:\n%s", rec.Code, body)
	}
	conns := h.mem.ConnectionRows()
	if len(conns) != 1 {
		t.Fatalf("connections = %d", len(conns))
	}
	q := grant.Query()
	if grant.Path != "/connect/fake/start" || q.Get("variant") != "default" || q.Get("connection") != conns[0].ID ||
		q.Get("scopes") != "write:org" || q.Get("return_to") != "/connections" {
		t.Errorf("grant link = %s", grant)
	}
	if !strings.Contains(body, "Unlocks 1 function: fake.edit_org") {
		t.Errorf("page lacks the unlock summary:\n%s", body)
	}
	if strings.Contains(body, `name="scopes"`) {
		t.Errorf("page still offers the free-text scopes field:\n%s", body)
	}

	second := h.portalConnect(t, member, v, grant.RequestURI())
	if got := second.Get("scope"); got != "read:user repo write:org" {
		t.Errorf("grant more access asked for %q, want the earlier grant and the missing scope", got)
	}
	rec = h.do(t, request{method: http.MethodGet, path: "/connections", cookie: member})
	if links := grantLinks(t, rec.Body.String()); links["Grant more access"] != nil {
		t.Errorf("Grant more access still offered after granting everything:\n%s", rec.Body)
	}
	if conns := h.mem.ConnectionRows(); len(conns) != 1 || strings.Join(conns[0].Scopes, " ") != "read:user repo write:org" {
		t.Errorf("connections after grant = %+v", conns)
	}
}

// fakeAdvisor reports a fixed gap, or an error.
type fakeAdvisor struct {
	gap connections.AccessGap
	err error
}

func (f fakeAdvisor) MissingAccess(context.Context, string, connections.Info) (connections.AccessGap, error) {
	return f.gap, f.err
}

// TestConnectionsPageSummaryAndReconnect: the unlock summary names at
// most eight functions; a connection that needs reconnecting gets a
// Reconnect link carrying the missing scopes too; when the gap cannot be
// computed the page still renders (the reconnect link without scopes).
func TestConnectionsPageSummaryAndReconnect(t *testing.T) {
	h := newHarness(t)
	v := newFakeVendor(t)
	registerFakeApp(t, &testEnv{svc: h.conn, store: h.mem}, v)
	h.conn.SetToolCatalog(testCatalog(t), nil)
	member, _ := h.session(t, memberSub, "Member")
	h.portalConnect(t, member, v, "/connect/fake/start")

	var tools []string
	for i := 1; i <= 11; i++ {
		tools = append(tools, fmt.Sprintf("fake.tool_%02d", i))
	}
	h.cp.SetAccessAdvisor(fakeAdvisor{gap: connections.AccessGap{Scopes: []string{"a:write", "b:write"}, Tools: tools, Extended: []string{"fake.list_repos"}}})
	body := h.do(t, request{method: http.MethodGet, path: "/connections", cookie: member}).Body.String()
	want := "Unlocks 11 functions: " + strings.Join(tools[:8], ", ") + " and 3 more"
	if !strings.Contains(body, want) {
		t.Errorf("page lacks %q:\n%s", want, body)
	}
	if !strings.Contains(body, "Also extends fake.list_repos") {
		t.Errorf("page lacks the extended tools:\n%s", body)
	}
	if got := grantLinks(t, body)["Grant more access"]; got == nil || got.Query().Get("scopes") != "a:write b:write" {
		t.Errorf("grant link = %v", got)
	}

	id := h.mem.ConnectionRows()[0].ID
	if err := h.mem.Bypass(context.Background(), func(tx connections.Tx) error {
		return tx.SetConnectionStatus(context.Background(), id, store.ConnectionNeedsReconnect)
	}); err != nil {
		t.Fatal(err)
	}
	links := grantLinks(t, h.do(t, request{method: http.MethodGet, path: "/connections", cookie: member}).Body.String())
	re := links["Reconnect"]
	if re == nil || links["Grant more access"] != nil {
		t.Fatalf("links = %v, want only Reconnect", links)
	}
	if q := re.Query(); q.Get("scopes") != "a:write b:write" || q.Get("connection") != id || q.Get("variant") != "default" {
		t.Errorf("reconnect link = %s", re)
	}

	h.cp.SetAccessAdvisor(fakeAdvisor{err: errors.New("catalog broken")})
	rec := h.do(t, request{method: http.MethodGet, path: "/connections", cookie: member})
	links = grantLinks(t, rec.Body.String())
	if rec.Code != http.StatusOK || links["Reconnect"] == nil || links["Reconnect"].Query().Has("scopes") {
		t.Errorf("advisor failure: %d, links %v", rec.Code, links)
	}
}
