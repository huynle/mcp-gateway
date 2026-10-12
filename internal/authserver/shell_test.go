package authserver_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

// /harnesses, the OAuth consent page and the authorize error page are
// built on the shared shell.
func TestAuthserverPagesUseTheSharedShell(t *testing.T) {
	f := newFlow(t)
	navtest.AssertShell(t, "/harnesses", f.harnesses().Body.String())
	navtest.AssertShell(t, "consent", f.authorize(f.authorizeParams()).Body.String())
	q := f.authorizeParams()
	q.Set("redirect_uri", "https://evil.test/cb")
	navtest.AssertShell(t, "authorize error", f.authorize(q).Body.String())
}
