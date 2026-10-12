package tokens_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

func TestTokenPagesUseTheSharedShell(t *testing.T) {
	f := newPages(t)
	for _, path := range []string{"/tokens", "/tokens/new"} {
		navtest.AssertShell(t, path, f.get(t, path).Body.String())
	}
}
