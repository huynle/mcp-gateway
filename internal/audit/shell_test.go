package audit_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

// /activity and /admin/audit are built on the shared portal shell like
// every other page (they used to carry their own light-only styles).
func TestAuditPagesUseTheSharedShell(t *testing.T) {
	f := &fakeReader{rows: sampleRows()}
	navtest.AssertShell(t, "/activity", get(t, audit.ActivityHandler(f, identity(alice, false)), "/activity").Body.String())
	navtest.AssertShell(t, "/admin/audit", get(t, audit.AdminSearchHandler(f, identity(alice, true)), "/admin/audit").Body.String())
	navtest.AssertShell(t, "/activity empty", get(t, audit.ActivityHandler(&fakeReader{}, identity(alice, false)), "/activity").Body.String())
}
