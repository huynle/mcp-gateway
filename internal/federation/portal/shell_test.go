package portal

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestServerPagesUseTheSharedShell(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, snapOf(writeTool("attachment_get", "g")))
	for _, path := range []string{"/servers", "/servers/new", "/servers/" + s.ID, "/servers/" + s.ID + "/review"} {
		r := e.get(path, alice)
		if r.code != 200 {
			t.Errorf("GET %s = %d", path, r.code)
		}
		navtest.AssertShell(t, path, r.body)
	}
}
