package portal

import (
	"net/url"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

func modesOf(t *testing.T, d snapshot.ReviewDecisions, name string) snapshot.Approval {
	t.Helper()
	if a := d.Tools[name].Approval; a != nil {
		return *a
	}
	return ""
}

// The review form posts an Ask/Auto choice per write tool (approval_<i>)
// and the decisions carry it; reads get none.
func TestReviewFormCarriesApprovalModes(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, snapOf(readTool("search", "s"), writeTool("save", "s"), writeTool("purge", "p")))

	body := e.get("/servers/"+s.ID+"/review", alice).body
	mustContain(t, body, `name="approval_1" value="ask" checked`, `name="approval_2"`, `value="approve_auto"`, `value="approve_ask"`,
		"Run selected without asking", "Ask for selected", "without a confirmation")
	mustNotContain(t, body, `name="approval_0"`)

	r := e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"1"}, "action": {"approve"}, "enable": {"0", "1", "2"},
		"approval_1": {"auto"}, "approval_2": {"ask"}, "approval_0": {"auto"}})
	if r.code != 303 {
		t.Fatalf("approve: %d %s", r.code, r.body)
	}
	d := e.snap.approvals[0].d
	if modesOf(t, d, "save") != snapshot.ApprovalAuto || modesOf(t, d, "purge") != snapshot.ApprovalAsk || modesOf(t, d, "search") != "" {
		t.Errorf("decisions = %+v", d.Tools)
	}
}

// The bulk actions set the mode of the selected writes and approve;
// approve_all keeps the posted per-tool modes.
func TestReviewBulkApprovalActions(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, snapOf(readTool("search", "s"), writeTool("save", "s"), writeTool("purge", "p")))

	r := e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"1"}, "action": {ActionApproveAuto}, "enable": {"0", "1"},
		"approval_1": {"ask"}, "approval_2": {"ask"}})
	if r.code != 303 {
		t.Fatalf("approve_auto: %d %s", r.code, r.body)
	}
	d := e.snap.approvals[0].d
	if modesOf(t, d, "save") != snapshot.ApprovalAuto || modesOf(t, d, "purge") != snapshot.ApprovalAsk || modesOf(t, d, "search") != "" {
		t.Errorf("approve_auto decisions = %+v", d.Tools)
	}
	if on := d.Tools["save"].Enabled; on == nil || !*on {
		t.Error("approve_auto did not enable the selected tool")
	}
	if on := d.Tools["purge"].Enabled; on == nil || *on {
		t.Error("approve_auto enabled an unselected tool")
	}

	e.snap.pending(s.ID, snapOf(readTool("search", "s"), writeTool("save", "s"), writeTool("purge", "p")))
	r = e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"2"}, "action": {ActionApproveAsk}, "enable": {"1", "2"},
		"approval_1": {"auto"}, "approval_2": {"auto"}})
	if r.code != 303 {
		t.Fatalf("approve_ask: %d %s", r.code, r.body)
	}
	d = e.snap.approvals[1].d
	if modesOf(t, d, "save") != snapshot.ApprovalAsk || modesOf(t, d, "purge") != snapshot.ApprovalAsk {
		t.Errorf("approve_ask decisions = %+v", d.Tools)
	}

	e.snap.pending(s.ID, snapOf(readTool("search", "s"), writeTool("save", "s"), writeTool("purge", "p")))
	r = e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"3"}, "action": {ActionApproveAll}, "approval_1": {"auto"}, "approval_2": {"ask"}})
	if r.code != 303 {
		t.Fatalf("approve_all: %d %s", r.code, r.body)
	}
	d = e.snap.approvals[2].d
	if modesOf(t, d, "save") != snapshot.ApprovalAuto || modesOf(t, d, "purge") != snapshot.ApprovalAsk {
		t.Errorf("approve_all decisions = %+v", d.Tools)
	}
}

// The review page shows the current mode of an approved write and warns
// about a destructive tool set to auto.
func TestReviewShowsCurrentModeAndDestructiveWarning(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	yes := true
	snap := snapOf(writeTool("save", "s"))
	snap.Tools = append(snap.Tools, snapshot.Tool{Name: "wipe", InputSchema: []byte(`{"type":"object"}`), Annotations: &snapshot.Annotations{DestructiveHint: &yes}})
	e.snap.approved(s.ID, snap, snapshot.Review{
		"save": {Enabled: true, Kind: snapshot.KindWrite, Approval: snapshot.ApprovalAuto},
		"wipe": {Enabled: true, Kind: snapshot.KindWrite, Approval: snapshot.ApprovalAuto},
	})
	body := e.get("/servers/"+s.ID+"/review", alice).body
	mustContain(t, body, `name="approval_0" value="auto" checked`, `name="approval_1" value="auto" checked`, "destructive-auto")
}

func approvedBrain(e *env, audience string) *store.MCPServer {
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone, Audience: audience})
	e.snap.approved(s.ID, snapOf(readTool("search", "s"), writeTool("save", "s"), writeTool("purge", "p")), snapshot.Review{
		"search": {Enabled: true, Kind: snapshot.KindRead},
		"save":   {Enabled: true, Kind: snapshot.KindWrite, Approval: snapshot.ApprovalAuto},
		"purge":  {Enabled: true, Kind: snapshot.KindWrite},
	})
	return s
}

// The server page shows the modes as counts and a compact list; the owner
// of a private server gets the edit form with the one-click buttons.
func TestServerPageShowsApprovalModes(t *testing.T) {
	e := newEnv(t)
	s := approvedBrain(e, store.MCPAudiencePrivate)
	body := e.get("/servers/"+s.ID, alice).body
	mustContain(t, body, "3 tools", "2 run without asking", "1 ask",
		`action="/servers/`+s.ID+`/approval"`, `name="all" value="auto"`, `name="all" value="ask"`, "Run all without asking",
		`name="mode_1" value="auto" checked`, `name="mode_2" value="ask" checked`, "without a confirmation")

	pub := approvedBrain(e, store.MCPAudiencePublished)
	body = e.get("/servers/"+pub.ID, alice).body
	mustContain(t, body, "2 run without asking", "An admin sets")
	mustNotContain(t, body, `/approval"`)
}

// POST /servers/{id}/approval: the owner of a private server changes the
// modes (one by one or all at once), audited and applied; the owner of a
// published server gets 403, anyone else 404; CSRF and a fresh version
// are required.
func TestApprovalModesPost(t *testing.T) {
	e := newEnv(t)
	s := approvedBrain(e, store.MCPAudiencePrivate)
	path := "/servers/" + s.ID + "/approval"

	r := e.post(path, alice, url.Values{"version": {"1"}, "mode_1": {"ask"}, "mode_2": {"auto"}, "mode_0": {"ask"}})
	if r.code != 303 || r.hdr.Get("Location") != "/servers/"+s.ID+"?modes=1" {
		t.Fatalf("owner edit: %d %q %s", r.code, r.hdr.Get("Location"), r.body)
	}
	edit := e.snap.modeEdits[0]
	if edit.actor.UserID != alice || edit.actor.Admin || edit.modes["save"] != snapshot.ApprovalAsk || edit.modes["purge"] != snapshot.ApprovalAuto {
		t.Errorf("edit = %+v", edit)
	}
	if _, ok := edit.modes["search"]; ok {
		t.Error("a read tool's mode was posted on")
	}
	if len(e.hook.changed) != 1 {
		t.Errorf("hook %v", e.hook.changed)
	}
	if len(e.aud.events) != 1 || e.aud.events[0].ResourceIdentity["action"] != "mcp_server.approval_modes_changed" ||
		e.aud.events[0].UserID != alice || e.aud.events[0].ResourceIdentity["auto_run"] != "1" {
		t.Errorf("audit = %+v", e.aud.events)
	}
	mustContain(t, e.get("/servers/"+s.ID+"?modes=1", alice).body, "Approval modes saved")

	// One click: everything runs without asking.
	if r := e.post(path, alice, url.Values{"version": {"1"}, "all": {"auto"}}); r.code != 303 {
		t.Fatalf("all auto: %d %s", r.code, r.body)
	}
	all := e.snap.modeEdits[1].modes
	if all["save"] != snapshot.ApprovalAuto || all["purge"] != snapshot.ApprovalAuto || len(all) != 2 {
		t.Errorf("all auto modes = %v", all)
	}
	if cur, _ := e.snap.Current(t.Context(), snapshot.Actor{}, s.ID); len(cur.Review.AutoRunWrites()) != 2 {
		t.Errorf("after all auto: %v", cur.Review.AutoRunWrites())
	}

	if r := e.post(path, alice, url.Values{"_csrf": {""}, "version": {"1"}, "all": {"auto"}}); r.code != 403 {
		t.Errorf("no csrf: %d", r.code)
	}
	if r := e.post(path, alice, url.Values{"version": {"9"}, "all": {"auto"}}); r.code != 409 {
		t.Errorf("stale version: %d", r.code)
	}
	if r := e.post(path, alice, url.Values{"version": {"1"}, "all": {"sometimes"}}); r.code != 422 {
		t.Errorf("bad mode: %d", r.code)
	}
	if r := e.post(path, bob, url.Values{"version": {"1"}, "all": {"auto"}}); r.code != 404 {
		t.Errorf("stranger: %d, want 404", r.code)
	}

	pub := approvedBrain(e, store.MCPAudiencePublished)
	before := len(e.snap.modeEdits)
	r = e.post("/servers/"+pub.ID+"/approval", alice, url.Values{"version": {"1"}, "all": {"auto"}})
	if r.code != 403 {
		t.Errorf("owner of a published server: %d, want 403", r.code)
	}
	mustContain(t, r.body, "an admin")
	if len(e.snap.modeEdits) != before {
		t.Error("published edit reached the service")
	}
}
