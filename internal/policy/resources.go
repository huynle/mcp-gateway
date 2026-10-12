package policy

import (
	"context"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Per-server actions of user-added MCP servers (Brain task bdb5zcud,
// decision q7vbxlyk point 2). Resources and prompts follow policy like
// tools: a role grants "<server>.resources/read" (resources/list,
// resources/templates/list and resources/read) and "<server>.prompts/get"
// (prompts/list and prompts/get), or both through the "<server>.*"
// wildcard; the owner layer (OwnerGrant) covers them; a role deny wins.
// They are read actions, so a read-only token keeps them.
const (
	ResourcesReadTool = "resources/read"
	PromptsGetTool    = "prompts/get"
)

// IsServerAccessTool reports whether name (the part after "<server>.") is
// one of the per-server actions.
func IsServerAccessTool(name string) bool {
	return name == ResourcesReadTool || name == PromptsGetTool
}

// ServerAccessTool is the pseudo-tool policy decides for one per-server
// action of app (ResourcesReadTool or PromptsGetTool). It is never
// registered in the tool registry and never listed in tools/list.
func ServerAccessTool(app, name string) connectors.Tool {
	return connectors.Tool{App: app, Name: name, Kind: connectors.KindRead}
}

// Permits reports whether in is plainly allowed: Decide answers allow.
// Confirm counts as refused, because reading a resource or getting a
// prompt has no approval flow; hidden and deny are refused.
func (c *Compiled) Permits(in Input) bool {
	in.AccountLabel, in.ResourceIdentity = "", nil
	return c.Decide(in).Outcome == OutcomeAllow
}

// Permits is Compiled.Permits for the user's assigned roles (in.Roles is
// replaced). It is not counted in the decision metrics: lists ask it for
// every server. Without any policy it returns false with the error.
func (s *Service) Permits(ctx context.Context, in Input) (bool, error) {
	c, err := s.forUser(ctx, in.UserID)
	if err != nil {
		return false, err
	}
	in.Roles = c.RolesFor(in.UserID)
	return c.Permits(in), nil
}
