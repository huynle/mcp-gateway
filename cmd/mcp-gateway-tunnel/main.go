// Command mcp-gateway-tunnel is the compatible alias of `mcp-gateway
// tunnel`: it connects a stdio or private-network MCP server to an MCP
// gateway with the same flags and environment. The implementation lives in
// internal/tunnelclient. See docs/tunnel.md.
package main

import (
	"context"
	"os"

	"github.com/huynle/mcp-gateway/internal/tunnelclient"
)

var version = "dev"

func main() {
	os.Exit(tunnelclient.Run(context.Background(), tunnelclient.Options{Name: "mcp-gateway-tunnel", Version: version}, os.Args[1:], os.Getenv, os.Stderr))
}
