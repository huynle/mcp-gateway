package admin_test

import (
	"net/http"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

func TestAdminServerPagesUseTheSharedShell(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/admin/servers", "/admin/servers/reviews", "/admin/tunnels", "/admin/network/allow-hosts"} {
		rec := h.do(t, req{path: path})
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", path, rec.Code)
		}
		navtest.AssertShell(t, path, rec.Body.String())
	}
}
