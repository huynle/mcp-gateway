//go:build darwin

package machineclient

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// The rendered LaunchAgent passes Apple's plist linter.
func TestLaunchdPlistLints(t *testing.T) {
	o, _, _ := serviceOpts(t, "darwin")
	o.Env["XDG_CONFIG_HOME"] = "/x & <y>"
	if err := ServiceInstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(o.Home, "Library/LaunchAgents/com.huynle.mcp-gateway.plist")
	if out, err := exec.CommandContext(context.Background(), "/usr/bin/plutil", "-lint", p).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint: %v\n%s", err, out)
	}
}
