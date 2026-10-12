package portal

import (
	"net/http"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Adding MCP servers needs permission (Brain task ds5tjou2, decision
// bnneszc1): admin, or a role with "May add MCP servers". Servers a user
// already owns keep working.

const carol = "cccccccc-0000-4000-8000-000000000003"

const askAdmin = "Ask an admin for a role that may add MCP servers"

func TestPermittedUserSeesAddServer(t *testing.T) {
	e := newEnv(t)
	r := e.get("/servers", alice)
	mustContain(t, r.body, `href="/servers/new"`)
	mustNotContain(t, r.body, askAdmin)
}

func TestUnpermittedUserHasNoAddServerButton(t *testing.T) {
	e := newEnv(t)
	e.perm.denied[carol] = true // before any request: no lock needed
	r := e.get("/servers", carol)
	if r.code != http.StatusOK {
		t.Fatalf("GET /servers = %d", r.code)
	}
	mustNotContain(t, r.body, `/servers/new`, ">Add server<")
	mustContain(t, r.body, askAdmin)
}

func TestUnpermittedUserCannotOpenAddForm(t *testing.T) {
	e := newEnv(t)
	e.perm.denied[carol] = true // before any request: no lock needed
	r := e.get("/servers/new", carol)
	if r.code != http.StatusForbidden {
		t.Fatalf("GET /servers/new = %d, want 403", r.code)
	}
	mustContain(t, r.body, askAdmin)
	mustNotContain(t, r.body, `name="url"`)
	navtest.AssertShell(t, "403 page", r.body)
}

func TestUnpermittedUserCannotCreateOrDetect(t *testing.T) {
	e := newEnv(t)
	e.perm.denied[carol] = true // before any request: no lock needed
	r := e.post("/servers/new", carol, addForm("name", "sneaky", "url", "https://sneaky.example/mcp", "auth_kind", "none"))
	if r.code != http.StatusForbidden {
		t.Errorf("POST create = %d, want 403", r.code)
	}
	mustContain(t, r.body, askAdmin)
	if s := e.serverByName("sneaky"); s != nil {
		t.Errorf("server created without permission: %+v", s)
	}
	if len(e.hook.changed) != 0 {
		t.Errorf("hook told about %v", e.hook.changed)
	}
	r = e.post("/servers/new", carol, addForm("action", "detect", "name", "sneaky", "url", "https://sneaky.example/mcp"))
	if r.code != http.StatusForbidden {
		t.Errorf("POST detect = %d, want 403", r.code)
	}
	if len(e.auth.detected) != 0 {
		t.Errorf("detection ran without permission: %v", e.auth.detected)
	}
}

// The CSRF check still comes first: a forged POST is refused as forged.
func TestUnpermittedCreateWithoutCSRFIsStill403(t *testing.T) {
	e := newEnv(t)
	e.perm.denied[carol] = true // before any request: no lock needed
	form := addForm("name", "x", "url", "https://x.example/mcp", "auth_kind", "none")
	form.Set("_csrf", "wrong")
	if r := e.post("/servers/new", carol, form); r.code != http.StatusForbidden {
		t.Errorf("POST with a bad token = %d", r.code)
	}
}

func TestOwnerWithoutPermissionKeepsTheirServer(t *testing.T) {
	e := newEnv(t)
	e.perm.denied[carol] = true // before any request: no lock needed
	s := e.st.add(store.MCPServer{Name: "notes", URL: "https://notes.example/mcp", OwnerUserID: carol, AuthKind: store.MCPAuthNone})
	e.snap.next[s.ID] = snapOf(readTool("search", "Search notes"))

	r := e.get("/servers", carol)
	mustContain(t, r.body, "notes")
	if r := e.get("/servers/"+s.ID, carol); r.code != http.StatusOK {
		t.Errorf("view = %d", r.code)
	}
	r = e.post("/servers/"+s.ID+"/refresh", carol, nil)
	if r.code != http.StatusSeeOther {
		t.Errorf("refresh = %d %s", r.code, r.body)
	}
	if r := e.get("/servers/"+s.ID+"/review", carol); r.code != http.StatusOK {
		t.Errorf("review = %d", r.code)
	}
	// Editing settings keeps working; moving the server to another address
	// would be adding a different server, so that needs the permission.
	r = e.post("/servers/"+s.ID+"/edit", carol, addForm("url", "https://notes.example/mcp", "auth_kind", "none"))
	if r.code != http.StatusSeeOther {
		t.Errorf("edit same address = %d %s", r.code, r.body)
	}
	r = e.post("/servers/"+s.ID+"/edit", carol, addForm("url", "https://elsewhere.example/mcp", "auth_kind", "none"))
	if r.code != http.StatusUnprocessableEntity {
		t.Errorf("edit new address = %d, want 422", r.code)
	}
	mustContain(t, r.body, askAdmin)
	if got := e.serverByName("notes"); got.URL != "https://notes.example/mcp" {
		t.Errorf("address changed to %s", got.URL)
	}
	r = e.post("/servers/"+s.ID+"/delete", carol, nil)
	if r.code != http.StatusSeeOther || len(e.st.deleted) != 1 {
		t.Errorf("delete = %d, deleted %v", r.code, e.st.deleted)
	}
}

// A permitted owner may move their server to a new address.
func TestPermittedOwnerMayChangeAddress(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "notes", URL: "https://notes.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	r := e.post("/servers/"+s.ID+"/edit", alice, addForm("url", "https://elsewhere.example/mcp", "auth_kind", "none"))
	if r.code != http.StatusSeeOther {
		t.Fatalf("edit = %d %s", r.code, r.body)
	}
	if got := e.serverByName("notes"); got.URL != "https://elsewhere.example/mcp" {
		t.Errorf("address = %s", got.URL)
	}
}
