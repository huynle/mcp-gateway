package main

import (
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/mcp"
)

// federationResources is what /mcp serves for resources/* and prompts/*:
// the approved resources, templates and prompts of the user-added servers
// the caller may use, enabled by the review and permitted by pol (the
// policy service: "<server>.resources/read" and "<server>.prompts/get",
// docs/federation-connector.md, "Resources and prompts"). Without a
// federation there is none, and /mcp advertises neither capability.
func federationResources(fed *connector.Federation, pol connector.ResourcePolicy) mcp.ResourceProvider {
	if fed == nil {
		return nil
	}
	return fed.Manager.ResourceProvider(pol)
}
