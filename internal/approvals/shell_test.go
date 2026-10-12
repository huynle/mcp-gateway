package approvals_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

func TestApprovalPagesUseTheSharedShell(t *testing.T) {
	f := newPages(t)
	for _, path := range []string{"/approvals", "/approvals/history"} {
		navtest.AssertShell(t, path, f.get(t, path).Body.String())
	}
}
