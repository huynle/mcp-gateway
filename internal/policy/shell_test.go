package policy_test

import (
	"net/http"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

func TestRolePagesUseTheSharedShell(t *testing.T) {
	p := newPages(t)
	for _, path := range []string{"/admin/roles", "/admin/roles/member", "/admin/roles/new", "/admin/settings/default-role"} {
		navtest.AssertShell(t, path, p.do(t, http.MethodGet, path, nil, true).Body.String())
	}
}
