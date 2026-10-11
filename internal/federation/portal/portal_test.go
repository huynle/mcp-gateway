package portal

import (
	"net/url"
	"slices"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestListShowsMyAndPublishedServersWithConnectionState(t *testing.T) {
	e := newEnv(t)
	notes := e.st.add(store.MCPServer{Name: "notes", URL: "https://notes.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthOAuth})
	wiki := e.st.add(store.MCPServer{Name: "wiki", URL: "https://wiki.example/mcp", OwnerUserID: bob, AuthKind: store.MCPAuthAPIKey,
		Audience: store.MCPAudiencePublished}, alice)
	kb := e.st.add(store.MCPServer{Name: "kb", URL: "https://kb.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthBearer})
	e.st.add(store.MCPServer{Name: "open", URL: "https://open.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.st.add(store.MCPServer{Name: "bobsprivate", URL: "https://b.example/mcp", OwnerUserID: bob, AuthKind: store.MCPAuthNone})
	e.st.setConn(wiki.ID, alice, store.MCPConnectionNeedsReconnect)
	e.st.setConn(kb.ID, alice, store.MCPConnectionActive)
	e.st.setConn(notes.ID, bob, store.MCPConnectionActive) // bob's connection is not alice's
	e.snap.pending(notes.ID, &snapshot.Snapshot{})

	r := e.get("/servers", alice)
	if r.code != 200 {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	if got := r.hdr.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	mustContain(t, r.body, "notes", "wiki", "kb", "open",
		`href="/servers/`+notes.ID+`"`, `href="/servers/new"`,
		"needs connect", "needs reconnect", "connected", "no connection needed", "pending review", "published")
	mustNotContain(t, r.body, "bobsprivate")
}

func TestOtherUsersPrivateServerIs404Everywhere(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "bobs", URL: "https://b.example/mcp", OwnerUserID: bob, AuthKind: store.MCPAuthNone})
	e.snap.approved(s.ID, &snapshot.Snapshot{Prompts: []snapshot.Prompt{{Name: "p"}}}, snapshot.Review{})
	for _, path := range []string{"/servers/" + s.ID, "/servers/" + s.ID + "/review", "/servers/" + s.ID + "/resources",
		"/servers/" + s.ID + "/prompts/p", "/servers/" + s.ID + "/edit", "/servers/not-a-uuid"} {
		if r := e.get(path, alice); r.code != 404 {
			t.Errorf("GET %s = %d, want 404", path, r.code)
		} else {
			mustContain(t, r.body, "Page not found")
			mustNotContain(t, r.body, "bobs")
		}
	}
	for _, path := range []string{"/servers/" + s.ID + "/refresh", "/servers/" + s.ID + "/delete", "/servers/" + s.ID + "/credential",
		"/servers/" + s.ID + "/disconnect", "/servers/" + s.ID + "/review", "/servers/" + s.ID + "/resources/read",
		"/servers/" + s.ID + "/prompts/p", "/servers/" + s.ID + "/edit"} {
		if r := e.post(path, alice, url.Values{"api_key": {"k"}, "version": {"1"}, "uri": {"x"}}); r.code != 404 {
			t.Errorf("POST %s = %d, want 404", path, r.code)
		}
	}
	if len(e.fac.opened)+len(e.auth.user)+len(e.auth.disconnects)+len(e.snap.approvals)+len(e.st.deleted) != 0 {
		t.Error("a refused request reached a service")
	}
}

func TestPostWithoutCSRFIs403(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "mine", URL: "https://m.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	for _, tok := range []string{"", "csrf-" + bob} {
		r := e.post("/servers/"+s.ID+"/delete", alice, url.Values{"_csrf": {tok}})
		if r.code != 403 {
			t.Errorf("csrf %q: status %d, want 403", tok, r.code)
		}
	}
	// A valid token of another user does not reach someone else's server.
	if r := e.post("/servers/"+s.ID+"/delete", bob, nil); r.code != 404 {
		t.Errorf("bob deletes alice's server: %d", r.code)
	}
	if len(e.st.deleted) != 0 {
		t.Error("deleted without a valid CSRF token")
	}
}

func TestNavShowsServersForMembers(t *testing.T) {
	e := newEnv(t)
	r := e.get("/servers", alice)
	if !slices.Contains(navtest.Links(r.body), "/servers") || navtest.Current(r.body) != "/servers" || navtest.Count(r.body) != 1 {
		t.Errorf("nav links %v current %q", navtest.Links(r.body), navtest.Current(r.body))
	}
	if !slices.Equal(navtest.Links(r.body), navtest.Member) {
		t.Errorf("member links = %v, want %v", navtest.Links(r.body), navtest.Member)
	}
	if r := e.get("/servers/new", alice); navtest.Current(r.body) != "/servers" {
		t.Errorf("new page current = %q", navtest.Current(r.body))
	}
}

func TestAnonymousIs401(t *testing.T) {
	e := newEnv(t)
	if r := e.get("/servers", ""); r.code != 401 {
		t.Errorf("status %d", r.code)
	}
}
