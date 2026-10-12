package admin_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestAdminRefreshListsSkippedItems(t *testing.T) {
	h := newHarness(t)
	s := h.st.add(admin.Server{MCPServer: store.MCPServer{Name: "brain", AuthKind: store.MCPAuthNone}})
	h.snaps.skipped = []snapshot.Skipped{{Kind: snapshot.SkippedTool, Name: "evil", Reason: snapshot.ReasonInvalidSchema}}
	rec := h.do(t, req{method: http.MethodPost, path: "/admin/servers/" + s.ID + "/refresh"})
	mustStatus(t, rec.Code, http.StatusOK, "refresh with skipped items")
	b := rec.Body.String()
	for _, want := range []string{"skipped", "tool evil", "(invalid schema)", `action="/admin/servers/` + s.ID + `/review"`} {
		if !strings.Contains(b, want) {
			t.Errorf("admin refresh page lacks %q", want)
		}
	}
}
