package netguard

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/huynle/mcp-gateway/internal/netguard/rawhttpcheck"
)

// TestFederationUsesOnlyTheGuard fails when any package under
// internal/federation builds its own HTTP client or transport instead of
// using netguard.Guard (plan 0omkv2e1 §4: the guard is the only way to
// reach a user-supplied URL). It skips until the directory exists.
func TestFederationUsesOnlyTheGuard(t *testing.T) {
	dir := filepath.Join("..", "federation")
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		t.Skip("internal/federation does not exist yet")
	}
	findings, err := rawhttpcheck.Dir(dir)
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
