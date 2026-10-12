package admin_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

func mustStatus(t *testing.T, got, want int, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status %d, want %d", what, got, want)
	}
}

func TestNonAdminsGet404OnEveryRoute(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain"}})
	h.st.tunnels = []admin.Tunnel{{ID: "30000000-0000-4000-8000-000000000001", OwnerUserID: ownerID, Name: "laptop"}}
	h.st.hosts = []store.NetguardAllowHost{{ID: "40000000-0000-4000-8000-000000000001", Pattern: "10.0.0.0/8"}}
	gets := []string{
		"/admin/servers", "/admin/servers/reviews", "/admin/servers/" + s.ID, "/admin/servers/" + s.ID + "/review",
		"/admin/tunnels", "/admin/network/allow-hosts",
	}
	posts := []string{
		"/admin/servers/" + s.ID + "/publish", "/admin/servers/" + s.ID + "/unpublish",
		"/admin/servers/" + s.ID + "/shared-credential", "/admin/servers/" + s.ID + "/static-client",
		"/admin/servers/" + s.ID + "/disable", "/admin/servers/" + s.ID + "/enable",
		"/admin/servers/" + s.ID + "/delete", "/admin/servers/" + s.ID + "/refresh", "/admin/servers/" + s.ID + "/review",
		"/admin/tunnels/30000000-0000-4000-8000-000000000001/revoke",
		"/admin/network/allow-hosts", "/admin/network/allow-hosts/40000000-0000-4000-8000-000000000001/delete",
	}
	for _, who := range []req{{member: true}, {anon: true}} {
		for _, p := range gets {
			r := who
			r.path = p
			if rec := h.do(t, r); rec.Code != http.StatusNotFound {
				t.Errorf("GET %s as %+v = %d, want 404", p, who, rec.Code)
			}
		}
		for _, p := range posts {
			r := who
			r.method, r.path = http.MethodPost, p
			r.form = url.Values{"roles": {roleEng}, "confirm": {"brain"}, "pattern": {"10.1.0.0/16"}, "api_key": {"k"}}
			if rec := h.do(t, r); rec.Code != http.StatusNotFound {
				t.Errorf("POST %s as %+v = %d, want 404", p, who, rec.Code)
			}
		}
	}
	if w := h.st.wrote(); len(w) > 0 {
		t.Errorf("non-admin requests wrote %v", w)
	}
	if len(h.hook.calls()) > 0 || h.allow.count() > 0 || len(h.tunnels.revoked) > 0 || len(h.audit.actions()) > 0 {
		t.Error("non-admin requests reached a service")
	}
}

func TestPostsNeedCSRF(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain"}})
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/publish", form: url.Values{"roles": {roleEng}}, noCSRF: true})
	mustStatus(t, rec.Code, http.StatusForbidden, "publish without CSRF")
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/network/allow-hosts", form: url.Values{"pattern": {"10.0.0.0/8"}, "_csrf": {"wrong"}}, noCSRF: true})
	mustStatus(t, rec.Code, http.StatusForbidden, "allow-host with a wrong CSRF token")
	if len(h.st.wrote()) > 0 || h.allow.count() > 0 {
		t.Error("a POST without a valid CSRF token changed something")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestListShowsEveryServerWithFilters(t *testing.T) {
	h := newHarness(t)
	a := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "alpha", URL: "https://alpha.example.com/mcp", CredentialMode: store.MCPCredentialShared, AuthKind: store.MCPAuthAPIKey},
		HasSharedCredential: true, PublishedRoleIDs: []string{roleEng}, UserConnectionCount: 3, LatestVersion: 2, ApprovedVersion: 1})
	a.Audience = store.MCPAudiencePublished
	h.st.servers[a.ID].Audience = store.MCPAudiencePublished
	h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "beta", Status: store.MCPServerDisabled, URL: "https://beta.internal.example/x"}, LatestVersion: 1, ApprovedVersion: 1})

	rec := h.do(t, req{path: "/admin/servers"})
	mustStatus(t, rec.Code, http.StatusOK, "list")
	body := rec.Body.String()
	for _, want := range []string{"alpha", "beta", "alpha.example.com", "beta.internal.example", "Olivia Owner", "engineering", "shared", "pending review", "/admin/servers/" + a.ID} {
		if !strings.Contains(body, want) {
			t.Errorf("list misses %q", want)
		}
	}
	if strings.Contains(body, "/mcp\"") || strings.Contains(body, "https://alpha.example.com/mcp") {
		t.Error("list shows the full URL; want the host only")
	}

	rec = h.do(t, req{path: "/admin/servers?pending=1"})
	if b := rec.Body.String(); !strings.Contains(b, "alpha") || strings.Contains(b, ">beta<") {
		t.Errorf("pending filter: want alpha only")
	}
	rec = h.do(t, req{path: "/admin/servers?status=disabled"})
	if b := rec.Body.String(); strings.Contains(b, ">alpha<") || !strings.Contains(b, ">beta<") {
		t.Errorf("status filter: want beta only")
	}
}

func TestReviewQueueListsPendingServers(t *testing.T) {
	h := newHarness(t)
	h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "pending-one"}, LatestVersion: 3, ApprovedVersion: 2})
	h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "never-approved"}, LatestVersion: 1})
	h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "settled"}, LatestVersion: 2, ApprovedVersion: 2})
	h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "no-snapshot"}})
	rec := h.do(t, req{path: "/admin/servers/reviews"})
	mustStatus(t, rec.Code, http.StatusOK, "reviews")
	b := rec.Body.String()
	if !strings.Contains(b, "pending-one") || !strings.Contains(b, "never-approved") {
		t.Error("review queue misses a pending server")
	}
	if strings.Contains(b, "settled") || strings.Contains(b, "no-snapshot") {
		t.Error("review queue lists a server without a pending snapshot")
	}
}

func TestPublishCallsStoreHookAndAudit(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain"}})
	rec := h.do(t, req{path: "/admin/servers/" + s.ID})
	mustStatus(t, rec.Code, http.StatusOK, "detail")
	if b := rec.Body.String(); !strings.Contains(b, `value="`+roleEng+`"`) || !strings.Contains(b, "engineering") {
		t.Error("detail page does not offer the roles to publish to")
	}

	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/publish", form: url.Values{"roles": {roleEng, roleSales}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "publish")
	got := h.st.get(s.ID)
	if got.Audience != store.MCPAudiencePublished || !slices.Equal(got.PublishedRoleIDs, []string{roleEng, roleSales}) {
		t.Fatalf("after publish: audience %q roles %v", got.Audience, got.PublishedRoleIDs)
	}
	if !slices.Equal(h.hook.calls(), []string{s.ID}) {
		t.Errorf("hook calls = %v, want [%s]", h.hook.calls(), s.ID)
	}
	ev := h.audit.last()
	if ev.UserID != adminID || ev.ResourceIdentity["action"] != "mcp_server.published" || ev.ResourceIdentity["server"] != "brain" ||
		ev.ResourceIdentity["roles"] != "engineering,sales" || ev.Outcome != "succeeded" {
		t.Errorf("audit event = %+v", ev)
	}
}

func TestPublishRefusesUnknownOrNoRoles(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain"}})
	for _, form := range []url.Values{{}, {"roles": {"10000000-0000-4000-8000-0000000000ff"}}, {"roles": {"not-a-uuid"}}} {
		rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/publish", form: form})
		mustStatus(t, rec.Code, http.StatusUnprocessableEntity, "publish "+form.Encode())
	}
	if len(h.st.wrote()) > 0 || len(h.hook.calls()) > 0 {
		t.Error("an invalid publish changed something")
	}
}

func TestUnpublishMakesServerPrivate(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", Audience: store.MCPAudiencePublished}, PublishedRoleIDs: []string{roleEng}})
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/unpublish"})
	mustStatus(t, rec.Code, http.StatusSeeOther, "unpublish")
	got := h.st.get(s.ID)
	if got.Audience != store.MCPAudiencePrivate || len(got.PublishedRoleIDs) != 0 {
		t.Fatalf("after unpublish: audience %q roles %v", got.Audience, got.PublishedRoleIDs)
	}
	if len(h.hook.calls()) != 1 || h.audit.last().ResourceIdentity["action"] != "mcp_server.unpublished" {
		t.Errorf("hook %v, audit %v", h.hook.calls(), h.audit.actions())
	}
}

func TestSharedCredentialIsWriteOnly(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", CredentialMode: store.MCPCredentialShared, AuthKind: store.MCPAuthAPIKey}})
	const secret = "sk-very-secret-value"
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/shared-credential", form: url.Values{"api_key": {secret}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "set shared credential")
	if c := h.auth.shared[s.ID]; c.APIKey != secret {
		t.Fatalf("stored credential = %+v", c)
	}
	if a := h.auth.actors[0]; a.UserID != adminID || !a.Admin {
		t.Errorf("auth actor = %+v, want admin", a)
	}
	if len(h.hook.calls()) != 1 {
		t.Errorf("hook calls = %v", h.hook.calls())
	}
	ev := h.audit.last()
	if ev.ResourceIdentity["action"] != "mcp_server.shared_credential_set" {
		t.Errorf("audit = %+v", ev)
	}
	for k, v := range ev.ResourceIdentity {
		if strings.Contains(v, secret) || strings.Contains(k, secret) {
			t.Error("audit event carries the secret")
		}
	}
	h.st.servers[s.ID].HasSharedCredential = true
	rec = h.do(t, req{path: "/admin/servers/" + s.ID})
	if b := rec.Body.String(); strings.Contains(b, secret) || !strings.Contains(b, "A shared credential is stored") {
		t.Error("detail page renders the secret or does not say one is stored")
	}

	// A validation error re-renders without echoing what was typed.
	h.auth.err = auth.ErrInvalidCredential
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/shared-credential", form: url.Values{"api_key": {secret + "\x01"}}})
	mustStatus(t, rec.Code, http.StatusUnprocessableEntity, "invalid credential")
	if strings.Contains(rec.Body.String(), secret) {
		t.Error("error page echoes the secret")
	}
}

func TestSharedCredentialNeedsSharedMode(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", AuthKind: store.MCPAuthAPIKey}})
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/shared-credential", form: url.Values{"api_key": {"x"}}})
	mustStatus(t, rec.Code, http.StatusUnprocessableEntity, "per-user server")
	if len(h.auth.shared) > 0 {
		t.Error("stored a shared credential for a per-user server")
	}
}

func TestStaticClientSecretIsWriteOnly(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", AuthKind: store.MCPAuthOAuth}})
	const secret = "client-secret-xyz"
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/static-client",
		form: url.Values{"client_id": {"gw-client"}, "client_secret": {secret}, "issuer": {"https://as.example.com"}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "static client")
	if c := h.auth.clients[s.ID]; c != [3]string{"gw-client", secret, "https://as.example.com"} {
		t.Fatalf("stored client = %v", c)
	}
	h.st.clients[s.ID] = "gw-client"
	b := h.do(t, req{path: "/admin/servers/" + s.ID}).Body.String()
	if strings.Contains(b, secret) || !strings.Contains(b, "gw-client") {
		t.Error("detail page renders the client secret or misses the client ID")
	}
	if h.audit.last().ResourceIdentity["action"] != "mcp_server.static_client_set" || len(h.hook.calls()) != 1 {
		t.Errorf("audit %v hook %v", h.audit.actions(), h.hook.calls())
	}
}

func TestDisableEnableDelete(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain"}})
	mustStatus(t, h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/disable"}).Code, http.StatusSeeOther, "disable")
	if h.st.get(s.ID).Status != store.MCPServerDisabled {
		t.Fatal("not disabled")
	}
	mustStatus(t, h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/enable"}).Code, http.StatusSeeOther, "enable")
	if h.st.get(s.ID).Status != store.MCPServerActive {
		t.Fatal("not enabled")
	}
	// Delete needs the server's name typed as confirmation.
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/delete", form: url.Values{"confirm": {"wrong"}}})
	mustStatus(t, rec.Code, http.StatusUnprocessableEntity, "delete without confirmation")
	if h.st.get(s.ID) == nil {
		t.Fatal("deleted without confirmation")
	}
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/delete", form: url.Values{"confirm": {"brain"}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "delete")
	if h.st.get(s.ID) != nil {
		t.Fatal("not deleted")
	}
	want := []string{"mcp_server.disabled", "mcp_server.enabled", "mcp_server.deleted"}
	if got := h.audit.actions(); !slices.Equal(got, want) {
		t.Errorf("audit actions = %v, want %v", got, want)
	}
	if len(h.hook.calls()) != 3 {
		t.Errorf("hook calls = %v, want 3", h.hook.calls())
	}
	mustStatus(t, h.do(t, req{path: "/admin/servers/" + s.ID}).Code, http.StatusNotFound, "deleted server")
}

func TestUnknownOrMalformedServerIs404(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/admin/servers/20000000-0000-4000-8000-0000000000ff", "/admin/servers/not-a-uuid", "/admin/servers/x/review"} {
		mustStatus(t, h.do(t, req{path: p}).Code, http.StatusNotFound, p)
	}
}

func TestRefreshUsesOwnerConnectionOrExplains(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", AuthKind: store.MCPAuthOAuth}})
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/refresh"})
	mustStatus(t, rec.Code, http.StatusSeeOther, "refresh")
	if loc := rec.Header().Get("Location"); loc != "/admin/servers/"+s.ID+"/review" {
		t.Errorf("redirect = %q", loc)
	}
	if !slices.Equal(h.factory.users, []string{ownerID}) {
		t.Errorf("factory opened as %v, want the owner", h.factory.users)
	}
	if a := h.snaps.actors[0]; !a.Admin || a.UserID != adminID {
		t.Errorf("refresh actor = %+v, want admin", a)
	}
	if h.audit.last().ResourceIdentity["action"] != "mcp_server.refreshed" {
		t.Errorf("audit = %v", h.audit.actions())
	}

	h.factory.err = auth.ErrNotConnected
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/refresh"})
	mustStatus(t, rec.Code, http.StatusBadGateway, "refresh without credentials")
	if b := rec.Body.String(); !strings.Contains(b, "shared credential") || !strings.Contains(b, "owner") {
		t.Errorf("refresh failure does not explain the missing credential: %s", b)
	}
}

func TestAdminReviewApprovesAsAdmin(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", Audience: store.MCPAudiencePublished}, PublishedRoleIDs: []string{roleEng}})
	h.snaps.pending(s.ID, &snapshot.Snapshot{Tools: []snapshot.Tool{
		{Name: "search", Description: "<script>alert(1)</script>\u202eevil", Annotations: &snapshot.Annotations{ReadOnlyHint: true}},
		{Name: "create_note"},
	}})
	rec := h.do(t, req{path: "/admin/servers/" + s.ID + "/review"})
	mustStatus(t, rec.Code, http.StatusOK, "review page")
	b := rec.Body.String()
	if strings.Contains(b, "<script>alert") || strings.Contains(b, "\u202e") {
		t.Error("review page renders upstream text unescaped")
	}
	if !strings.Contains(b, `name="enable" value="0"`) || !strings.Contains(b, `name="version" value="1"`) {
		t.Error("review page has no approve form")
	}

	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/review", form: url.Values{"version": {"1"}, "enable": {"0"}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "approve")
	d := h.snaps.approvals[0]
	if e := d.Tools["search"].Enabled; e == nil || !*e {
		t.Error("search not enabled")
	}
	if e := d.Tools["create_note"].Enabled; e == nil || *e {
		t.Error("unchecked write not disabled")
	}
	last := h.snaps.actors[len(h.snaps.actors)-1]
	if !last.Admin || last.UserID != adminID {
		t.Errorf("approve actor = %+v, want admin", last)
	}
	if !slices.Equal(h.hook.calls(), []string{s.ID}) {
		t.Errorf("hook = %v", h.hook.calls())
	}
	if ev := h.audit.last(); ev.ResourceIdentity["action"] != "mcp_server.reviewed" || ev.ResourceIdentity["version"] != "1" {
		t.Errorf("audit = %+v", ev)
	}

	// A stale version is refused.
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/review", form: url.Values{"version": {"7"}}})
	mustStatus(t, rec.Code, http.StatusConflict, "stale approve")
}

func TestAdminReviewUsesTheSharedViewAndApproveAll(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", Audience: store.MCPAudiencePublished}, PublishedRoleIDs: []string{roleEng}})
	h.snaps.pending(s.ID, &snapshot.Snapshot{Tools: []snapshot.Tool{
		{Name: "attachment_get", Description: "Get an attachment. Long details follow.\nMore."},
		{Name: "attachment_add"},
		{Name: "search", Annotations: &snapshot.Annotations{ReadOnlyHint: true}},
	}})
	rec := h.do(t, req{path: "/admin/servers/" + s.ID + "/review"})
	mustStatus(t, rec.Code, http.StatusOK, "review page")
	b := rec.Body.String()
	for _, want := range []string{
		`action="/admin/servers/` + s.ID + `/review"`, `name="_csrf" value="` + csrf + `"`, `data-review`, `class="review-bar"`,
		`data-select="all"`, `data-select="read"`, `data-group="attachment"`, `data-group-check`, `0 of 3 selected`,
		`name="action" value="approve_all"`, "Approve as admin", `<b>3</b> total`, `src="/static/review.js?v=`,
		`<span class="tool-summary">Get an attachment.</span>`, `<details class="tool-more">`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("admin review page lacks %q", want)
		}
	}

	// approve_all as an admin enables every tool of a published server.
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/review", form: url.Values{"version": {"1"}, "action": {"approve_all"}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "approve all")
	d := h.snaps.approvals[0]
	for _, name := range []string{"attachment_get", "attachment_add", "search"} {
		if e := d.Tools[name].Enabled; e == nil || !*e {
			t.Errorf("%s not enabled by approve_all", name)
		}
	}
	if last := h.snaps.actors[len(h.snaps.actors)-1]; !last.Admin {
		t.Errorf("approve actor = %+v, want admin", last)
	}
	if ev := h.audit.last(); ev.ResourceIdentity["enabled_tools"] != "3" {
		t.Errorf("audit = %+v", ev)
	}

	// approve_all still needs the CSRF token and the latest version.
	n := len(h.snaps.approvals)
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/review", form: url.Values{"version": {"1"}, "action": {"approve_all"}}, noCSRF: true})
	mustStatus(t, rec.Code, http.StatusForbidden, "approve all without CSRF")
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/review", form: url.Values{"version": {"7"}, "action": {"approve_all"}}})
	mustStatus(t, rec.Code, http.StatusConflict, "stale approve all")
	if len(h.snaps.approvals) != n {
		t.Error("a refused approve_all reached the snapshot service")
	}
}

func TestTunnelsListAndRevoke(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	h.st.tunnels = []admin.Tunnel{
		{ID: "30000000-0000-4000-8000-000000000001", OwnerUserID: ownerID, OwnerName: "Olivia Owner", Name: "laptop", CreatedAt: now},
		{ID: "30000000-0000-4000-8000-000000000002", OwnerUserID: memberID, OwnerName: "Mo Member", Name: "<b>nas</b>", CreatedAt: now, RevokedAt: &now},
	}
	h.tunnels.online["30000000-0000-4000-8000-000000000001"] = true
	rec := h.do(t, req{path: "/admin/tunnels"})
	mustStatus(t, rec.Code, http.StatusOK, "tunnels")
	b := rec.Body.String()
	for _, want := range []string{"laptop", "Olivia Owner", "online", "revoked", "&lt;b&gt;nas&lt;/b&gt;"} {
		if !strings.Contains(b, want) {
			t.Errorf("tunnels page misses %q", want)
		}
	}
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/tunnels/30000000-0000-4000-8000-000000000001/revoke"})
	mustStatus(t, rec.Code, http.StatusSeeOther, "revoke")
	if !slices.Equal(h.tunnels.revoked, []string{ownerID + "/30000000-0000-4000-8000-000000000001"}) {
		t.Errorf("revoked = %v", h.tunnels.revoked)
	}
	if ev := h.audit.last(); ev.ResourceIdentity["action"] != "tunnel.revoked" || ev.UserID != adminID {
		t.Errorf("audit = %+v", ev)
	}
	mustStatus(t, h.do(t, req{method: http.MethodPost, path: "/admin/tunnels/30000000-0000-4000-8000-0000000000ff/revoke"}).Code, http.StatusNotFound, "unknown tunnel")
}

func TestAllowHostsAddDeleteInvalidate(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, req{path: "/admin/network/allow-hosts"})
	mustStatus(t, rec.Code, http.StatusOK, "allow-hosts page")
	if !strings.Contains(rec.Body.String(), "internal networks") {
		t.Error("allow-hosts page has no warning")
	}
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/network/allow-hosts", form: url.Values{"pattern": {" 10.20.0.0/16 "}, "note": {"lab"}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "add")
	if len(h.st.hosts) != 1 || h.st.hosts[0].Pattern != "10.20.0.0/16" || h.st.hosts[0].Note != "lab" ||
		h.st.hosts[0].CreatedBy == nil || *h.st.hosts[0].CreatedBy != adminID {
		t.Fatalf("hosts = %+v", h.st.hosts)
	}
	if h.allow.count() != 1 {
		t.Errorf("Invalidate calls = %d, want 1", h.allow.count())
	}
	if ev := h.audit.last(); ev.ResourceIdentity["action"] != "netguard.allow_host_added" || ev.ResourceIdentity["pattern"] != "10.20.0.0/16" {
		t.Errorf("audit = %+v", ev)
	}
	b := h.do(t, req{path: "/admin/network/allow-hosts"}).Body.String()
	if !strings.Contains(b, "10.20.0.0/16") || !strings.Contains(b, "lab") {
		t.Error("list misses the new entry")
	}

	for _, bad := range []string{"", "10.0.0.0/99", "http://x.example", "*.example.com", "bad host"} {
		rec = h.do(t, req{method: http.MethodPost, path: "/admin/network/allow-hosts", form: url.Values{"pattern": {bad}}})
		mustStatus(t, rec.Code, http.StatusUnprocessableEntity, "invalid pattern "+bad)
	}
	rec = h.do(t, req{method: http.MethodPost, path: "/admin/network/allow-hosts", form: url.Values{"pattern": {"10.20.0.0/16"}}})
	mustStatus(t, rec.Code, http.StatusUnprocessableEntity, "duplicate")
	if h.allow.count() != 1 {
		t.Errorf("invalid adds invalidated the allow list (%d)", h.allow.count())
	}

	rec = h.do(t, req{method: http.MethodPost, path: "/admin/network/allow-hosts/" + h.st.hosts[0].ID + "/delete"})
	mustStatus(t, rec.Code, http.StatusSeeOther, "delete")
	if len(h.st.hosts) != 0 || h.allow.count() != 2 {
		t.Errorf("hosts %v, invalidations %d", h.st.hosts, h.allow.count())
	}
	if ev := h.audit.last(); ev.ResourceIdentity["action"] != "netguard.allow_host_removed" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestNewAdminPanicsWithoutRequiredDeps(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewAdmin without deps did not panic")
		}
	}()
	admin.NewAdmin(admin.Deps{})
}
