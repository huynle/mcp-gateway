package main

import (
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/mcp"
)

// federationResources is what /mcp serves for resources/* and prompts/*:
// the approved resources, templates and prompts of the user-added servers
// the caller may use (docs/federation-connector.md, "Resources and
// prompts"). Without a federation there is none, and /mcp advertises
// neither capability.
func federationResources(fed *connector.Federation) mcp.ResourceProvider {
	if fed == nil {
		return nil
	}
	return fed.Manager.ResourceProvider()
}
