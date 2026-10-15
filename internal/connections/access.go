package connections

import (
	"context"
	"slices"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// ToolVisibility answers whether the user's roles and restrictions let
// them see a tool, independent of any token and of the scopes any
// account granted. PolicyAllowance adapts policy.Service.
type ToolVisibility interface {
	VisibleToUser(ctx context.Context, userID string, tool connectors.Tool) (bool, error)
}

// AccessGap is what a connection lacks for the tools its user may see:
// Scopes to request (missing RequiredScopes and OptionalScopes, under the
// app's coverage semantics), the Tools those scopes unlock (their
// RequiredScopes are not covered today) and the tools they Extend (usable
// today, they do more with an optional scope). All sorted, full names.
type AccessGap struct {
	Scopes   []string
	Tools    []string
	Extended []string
}

// Empty reports whether nothing is missing.
func (g AccessGap) Empty() bool { return len(g.Scopes) == 0 }

// SetToolCatalog installs the tool registry and the policy view the
// grant-more-access computation and the connect flow consult: which
// tools exist for a vendor (MapApp), which scopes they need, and which
// of them a user may see. A nil vis treats every tool as visible; with
// no registry the gateway knows no tool scopes (nothing is missing, and
// the connect flow requests only base and previously granted scopes).
func (s *Service) SetToolCatalog(reg *connectors.Registry, vis ToolVisibility) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools, s.visibility = reg, vis
}

func (s *Service) toolCatalog() (*connectors.Registry, ToolVisibility) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tools, s.visibility
}

// vendorTools returns the built-in tools of the vendor's apps that run
// against an account (no list_accounts, no user-added server tools).
func (s *Service) vendorTools(reg *connectors.Registry, vendor string) []connectors.Tool {
	if reg == nil {
		return nil
	}
	apps := s.appsFor(vendor)
	var out []connectors.Tool
	for _, t := range reg.List() {
		if t.NoAccount || reg.IsServerApp(t.App) || !slices.Contains(apps, t.App) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// visibleTools keeps the tools policy lets the user see. When the policy
// cannot be evaluated every tool is kept (logged): asking the vendor for
// more scopes than a role needs is harmless, because policy still
// decides every call, while hiding "grant more access" is the bug this
// exists to fix.
func (s *Service) visibleTools(ctx context.Context, vis ToolVisibility, userID string, tools []connectors.Tool) []connectors.Tool {
	if vis == nil {
		return tools
	}
	var out []connectors.Tool
	for _, t := range tools {
		ok, err := vis.VisibleToUser(ctx, userID, t)
		if err != nil {
			s.log.Warn("policy unavailable; assuming every vendor tool is visible", "event", "connections.policy_unavailable",
				"user_id", userID, "tool", t.FullName(), "error", observability.RedactError(err))
			return tools
		}
		if ok {
			out = append(out, t)
		}
	}
	return out
}

// MissingAccess computes the connection's AccessGap for userID: over
// every tool of the connection's vendor the user's policy shows, the
// union of the required and optional scopes conn.Scopes does not cover
// (connectors.Registry.MissingScopes, so Google's and Microsoft's
// broader scopes count). A connection without recorded scopes has no
// gap, exactly as the scope stage does not refuse it (GitHub App user
// tokens carry no scope list).
func (s *Service) MissingAccess(ctx context.Context, userID string, conn Info) (AccessGap, error) {
	reg, vis := s.toolCatalog()
	if reg == nil || len(conn.Scopes) == 0 {
		return AccessGap{}, nil
	}
	var gap AccessGap
	var scopes [][]string
	for _, t := range s.visibleTools(ctx, vis, userID, s.vendorTools(reg, conn.Vendor)) {
		required := reg.MissingScopes(t, conn.Scopes)
		optional := reg.MissingScopes(connectors.Tool{App: t.App, RequiredScopes: t.OptionalScopes}, conn.Scopes)
		switch {
		case len(required) > 0:
			gap.Tools = append(gap.Tools, t.FullName())
		case len(optional) > 0:
			gap.Extended = append(gap.Extended, t.FullName())
		default:
			continue
		}
		scopes = append(scopes, required, optional)
	}
	gap.Scopes = unionScopes(scopes...)
	gap.Tools, gap.Extended = unionScopes(gap.Tools), unionScopes(gap.Extended)
	return gap, nil
}
