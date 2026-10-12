package admin_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

func approvedServer(h *harness, audience string) *admin.Server {
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", OwnerUserID: ownerID, Audience: audience}, ApprovedVersion: 1, LatestVersion: 1})
	obj := json.RawMessage(`{"type":"object"}`)
	rec := &snapshot.Record{ServerID: s.ID, Version: 1, Status: store.MCPSnapshotApproved,
		Snapshot: &snapshot.Snapshot{Tools: []snapshot.Tool{
			{Name: "search", InputSchema: obj, Annotations: &snapshot.Annotations{ReadOnlyHint: true}},
			{Name: "save", InputSchema: obj}, {Name: "purge", InputSchema: obj},
		}},
		Review: snapshot.Review{
			"search": {Enabled: true, Kind: snapshot.KindRead},
			"save":   {Enabled: true, Kind: snapshot.KindWrite, Approval: snapshot.ApprovalAuto},
			"purge":  {Enabled: true, Kind: snapshot.KindWrite},
		}}
	h.snaps.current[s.ID], h.snaps.latest[s.ID] = rec, rec
	return s
}

// The admin server page shows the approval modes with the edit form, for
// published servers too (the admin sets them for granted roles).
func TestAdminServerPageShowsApprovalModes(t *testing.T) {
	h := newHarness(t)
	s := approvedServer(h, store.MCPAudiencePublished)
	rec := h.do(t, req{path: "/admin/servers/" + s.ID})
	mustStatus(t, rec.Code, http.StatusOK, "detail")
	body := rec.Body.String()
	for _, want := range []string{"3 tools", "2 run without asking", "1 ask", `action="/admin/servers/` + s.ID + `/approval"`,
		`name="mode_1" value="auto" checked`, `name="all" value="auto"`, "without a confirmation"} {
		if !strings.Contains(body, want) {
			t.Errorf("admin server page lacks %q", want)
		}
	}
}

// POST /admin/servers/{id}/approval: an admin changes the modes of a
// published server; audited, hook called; members get 404; CSRF and a
// fresh version are required.
func TestAdminApprovalModesPost(t *testing.T) {
	h := newHarness(t)
	s := approvedServer(h, store.MCPAudiencePublished)
	path := "/admin/servers/" + s.ID + "/approval"

	rec := h.do(t, req{method: http.MethodPost, path: path, form: url.Values{"version": {"1"}, "all": {"auto"}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "admin edit")
	if loc := rec.Header().Get("Location"); loc != "/admin/servers/"+s.ID+"?done=modes" {
		t.Errorf("Location = %q", loc)
	}
	if len(h.snaps.modeEdits) != 1 || h.snaps.modeEdits[0]["purge"] != snapshot.ApprovalAuto || len(h.snaps.modeEdits[0]) != 2 {
		t.Errorf("mode edits = %v", h.snaps.modeEdits)
	}
	if a := h.snaps.actors[len(h.snaps.actors)-1]; !a.Admin || a.UserID != adminID {
		t.Errorf("actor = %+v, want the admin", a)
	}
	ev := h.audit.last()
	if ev.ResourceIdentity["action"] != "mcp_server.approval_modes_changed" || ev.UserID != adminID || ev.ResourceIdentity["auto_run"] != "2" {
		t.Errorf("audit = %+v", ev)
	}
	if len(h.hook.calls()) != 1 {
		t.Errorf("hook calls = %v", h.hook.calls())
	}
	if body := h.do(t, req{path: "/admin/servers/" + s.ID + "?done=modes"}).Body.String(); !strings.Contains(body, "Approval modes saved") {
		t.Error("no notice after the edit")
	}

	mustStatus(t, h.do(t, req{method: http.MethodPost, path: path, form: url.Values{"version": {"1"}, "all": {"auto"}}, member: true}).Code,
		http.StatusNotFound, "member")
	mustStatus(t, h.do(t, req{method: http.MethodPost, path: path, form: url.Values{"version": {"1"}, "all": {"auto"}}, noCSRF: true}).Code,
		http.StatusForbidden, "no csrf")
	mustStatus(t, h.do(t, req{method: http.MethodPost, path: path, form: url.Values{"version": {"5"}, "all": {"auto"}}}).Code,
		http.StatusConflict, "stale version")
	mustStatus(t, h.do(t, req{method: http.MethodPost, path: path, form: url.Values{"version": {"1"}, "mode_1": {"never"}}}).Code,
		http.StatusUnprocessableEntity, "bad mode")
	if len(h.snaps.modeEdits) != 1 {
		t.Errorf("refused posts reached the service: %v", h.snaps.modeEdits)
	}
}

// The admin review form carries the approval modes into the decisions.
func TestAdminReviewCarriesApprovalModes(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", OwnerUserID: ownerID, Audience: store.MCPAudiencePublished}})
	h.snaps.pending(s.ID, &snapshot.Snapshot{Tools: []snapshot.Tool{{Name: "save", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	body := h.do(t, req{path: "/admin/servers/" + s.ID + "/review"}).Body.String()
	if !strings.Contains(body, `name="approval_0" value="ask" checked`) || !strings.Contains(body, "Run selected without asking") {
		t.Errorf("admin review lacks the approval controls:\n%s", body)
	}
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/review",
		form: url.Values{"version": {"1"}, "action": {"approve_auto"}, "enable": {"0"}}})
	mustStatus(t, rec.Code, http.StatusSeeOther, "approve_auto")
	d := h.snaps.approvals[len(h.snaps.approvals)-1]
	if a := d.Tools["save"].Approval; a == nil || *a != snapshot.ApprovalAuto {
		t.Errorf("decision = %+v", d.Tools["save"])
	}
}
