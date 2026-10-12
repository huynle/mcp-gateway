package admin_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Published servers are admin-governed (Brain task mpszh6h0, decision
// q7vbxlyk point 3): only an admin changes their address, and the change
// withdraws the approved snapshot until an admin reviews the server again.

func TestAdminChangesAddressOfPublishedServer(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", URL: "https://brain.example.com/mcp", Audience: store.MCPAudiencePublished},
		PublishedRoleIDs: []string{roleEng}, LatestVersion: 2, ApprovedVersion: 2})
	rec := h.do(t, req{path: "/admin/servers/" + s.ID})
	mustStatus(t, rec.Code, http.StatusOK, "detail")
	if b := rec.Body.String(); !strings.Contains(b, `action="/admin/servers/`+s.ID+`/address"`) || !strings.Contains(b, `name="url"`) {
		t.Fatal("detail page offers no address form")
	}

	rec = h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/address", form: url.Values{"url": {"https://brain-v2.example.com/mcp"}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "change address")
	if loc := rec.Header().Get("Location"); loc != "/admin/servers/"+s.ID+"?done=address" {
		t.Errorf("Location = %q", loc)
	}
	if w := h.st.wrote(); !slices.Equal(w, []string{"address:" + s.ID + ":https://brain-v2.example.com/mcp"}) {
		t.Errorf("writes = %v", w)
	}
	if !slices.Equal(h.hook.calls(), []string{s.ID}) {
		t.Errorf("hook calls = %v", h.hook.calls())
	}
	ev := h.audit.last()
	if ev.ResourceIdentity["action"] != "mcp_server.address_changed" || ev.ResourceIdentity["old_host"] != "brain.example.com" ||
		ev.ResourceIdentity["new_host"] != "brain-v2.example.com" || ev.UserID != adminID {
		t.Errorf("audit = %+v", ev)
	}

	// The approval is withdrawn (the store's trigger): the pages say a
	// re-review is needed and link to it.
	rec = h.do(t, req{path: "/admin/servers/" + s.ID + "?done=address"})
	b := rec.Body.String()
	for _, want := range []string{"Re-review required", `href="/admin/servers/` + s.ID + `/review"`, "refresh"} {
		if !strings.Contains(b, want) {
			t.Errorf("detail after the change misses %q", want)
		}
	}
	rec = h.do(t, req{path: "/admin/servers"})
	if b := rec.Body.String(); !strings.Contains(b, "re-review required") {
		t.Error("list does not flag the re-review")
	}
}

func TestAdminAddressChangeRefusesBadInput(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", URL: "https://brain.example.com/mcp"}})
	for _, u := range []string{"", "http://brain.example.com/mcp", "https://user:pw@brain.example.com/mcp", "https://brain.example.com/mcp#x",
		"tunnel://30000000-0000-4000-8000-000000000001/mcp", "https://brain.example.com/mcp", "https://" + strings.Repeat("a", 2100) + ".example.com"} {
		rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/address", form: url.Values{"url": {u}}})
		mustStatus(t, rec.Code, http.StatusUnprocessableEntity, "address "+u)
	}
	if len(h.st.wrote()) > 0 || len(h.hook.calls()) > 0 {
		t.Error("a refused address change changed something")
	}
}

func TestReReviewFlaggedForPublishedServerWithoutApproval(t *testing.T) {
	h := newHarness(t)
	pub := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "pub", Audience: store.MCPAudiencePublished}, LatestVersion: 1})
	priv := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "priv"}, LatestVersion: 1})
	if b := h.do(t, req{path: "/admin/servers/" + pub.ID}).Body.String(); !strings.Contains(b, "Re-review required") {
		t.Error("published server without an approved snapshot not flagged")
	}
	if b := h.do(t, req{path: "/admin/servers/" + priv.ID}).Body.String(); strings.Contains(b, "Re-review required") {
		t.Error("private server flagged for an admin re-review")
	}
}
