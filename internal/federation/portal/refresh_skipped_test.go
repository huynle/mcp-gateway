package portal

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// A refresh that left upstream items out (NUL or control characters in a
// key, Brain task jsb8470s) shows the review page at once with the list,
// instead of redirecting: the list is not stored.
func TestRefreshListsSkippedItems(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "notes", URL: "https://notes.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	snap := snapOf(readTool("search", "Search notes"))
	snap.Skipped = []snapshot.Skipped{
		{Kind: snapshot.SkippedTool, Name: "evil<b>", Reason: snapshot.ReasonInvalidName},
		{Kind: snapshot.SkippedPrompt, Name: "badarg", Reason: snapshot.ReasonInvalidArgument},
	}
	e.snap.next[s.ID] = snap
	r := e.post("/servers/"+s.ID+"/refresh", alice, nil)
	if r.code != 200 {
		t.Fatalf("refresh with skipped items: %d %q", r.code, r.hdr.Get("Location"))
	}
	mustContain(t, r.body, "skipped", "tool evil&lt;b&gt;", "(invalid name)", "prompt badarg", "(invalid argument)",
		`action="/servers/`+s.ID+`/review"`, "Search notes")
	mustNotContain(t, r.body, "evil<b>")

	// Nothing skipped: the usual redirect.
	e.snap.next[s.ID] = snapOf(readTool("search", "Search notes"))
	if r := e.post("/servers/"+s.ID+"/refresh", alice, nil); r.code != 303 {
		t.Errorf("clean refresh: %d", r.code)
	}
}
