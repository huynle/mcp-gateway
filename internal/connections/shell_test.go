package connections_test

import (
	"net/http"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

func TestConnectionPagesUseTheSharedShell(t *testing.T) {
	h := newHarness(t)
	member, _ := h.session(t, memberSub, "Member")
	admin, _ := h.session(t, adminSub, "Admin")
	navtest.AssertShell(t, "/connections", h.do(t, request{method: http.MethodGet, path: "/connections", cookie: member}).Body.String())
	for _, path := range []string{"/admin/vendor-apps", "/admin/vendor-apps/github"} {
		navtest.AssertShell(t, path, h.do(t, request{method: http.MethodGet, path: path, cookie: admin}).Body.String())
	}
}
