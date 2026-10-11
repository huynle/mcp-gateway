package connector

import (
	"context"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
)

// Decider wraps base (the policy service) with server visibility, so one
// wrapper covers every place the pipeline consults policy: tools/list and
// resolve (mcp.PolicyVisibility over Visible) and the policy stage
// (Decide). For a server tool of a server the user may not use, Visible
// is false and Decide answers hidden (the stage then answers exactly like
// an unknown tool) without asking base. Everything else is base's.
// cmd/gateway passes the wrapped decider to the /mcp pipeline.
func (m *Manager) Decider(base mcp.Decider) mcp.Decider {
	return decider{m: m, base: base}
}

type decider struct {
	m    *Manager
	base mcp.Decider
}

func (d decider) Decide(ctx context.Context, in policy.Input) (policy.Decision, error) {
	if !d.m.serverToolUsable(ctx, in.UserID, in.Tool) {
		return policy.Decision{Outcome: policy.OutcomeHidden, Reason: "federated server not visible to the user"}, nil
	}
	return d.base.Decide(ctx, in)
}

func (d decider) Visible(ctx context.Context, in policy.Input) (bool, error) {
	if !d.m.serverToolUsable(ctx, in.UserID, in.Tool) {
		return false, nil
	}
	return d.base.Visible(ctx, in)
}

// serverToolUsable reports whether userID may use tool's server; true for
// built-in tools (not the Manager's to decide).
func (m *Manager) serverToolUsable(ctx context.Context, userID string, tool connectors.Tool) bool {
	if !m.o.Registry.IsServerApp(tool.App) {
		return true
	}
	e, ok := m.entry(tool.App)
	return ok && m.canSee(ctx, userID, e.server.ID)
}
