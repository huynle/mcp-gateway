package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/tunnelclient"
)

// The alias keeps its own name in the usage text and status lines.
func TestAliasHelpUsesItsName(t *testing.T) {
	var stderr bytes.Buffer
	code := tunnelclient.Run(context.Background(), tunnelclient.Options{Name: "mcp-gateway-tunnel"}, []string{"--help"}, func(string) string { return "" }, &stderr)
	if code != 0 || !strings.Contains(stderr.String(), "usage: mcp-gateway-tunnel --gateway") {
		t.Fatalf("code %d, stderr:\n%s", code, stderr.String())
	}
}
