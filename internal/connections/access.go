package connections

import (
	"context"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
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

// flowScopes is what Start asks the vendor for: the app's base scopes,
// every scope the connection being re-granted (req.ConnectionID) already
// holds (an incremental request must not lose them: Microsoft issues a token
// for exactly the scopes asked, and Google keeps earlier grants only
// with include_granted_scopes), and either the requested scopes or, when
// none were requested (Connect), the scopes of the read tools the user's
// policy shows: reads first, writes through grant more access.
//
// Requested scopes are accepted only when they are base scopes or some
// tool of the vendor requires or uses them; anything else is dropped and
// logged, so a crafted link cannot widen what the gateway asks for.
func (s *Service) flowScopes(ctx context.Context, app VendorApp, req StartRequest) ([]string, error) {
	reg, vis := s.toolCatalog()
	tools := s.vendorTools(reg, app.Vendor)
	allowed := map[string]bool{}
	for _, sc := range app.Scopes {
		allowed[sc] = true
	}
	for _, t := range tools {
		for _, sc := range slices.Concat(t.RequiredScopes, t.OptionalScopes) {
			allowed[sc] = true
		}
	}
	var accepted, ignored []string
	for _, sc := range unionScopes(req.Scopes) {
		if allowed[sc] {
			accepted = append(accepted, sc)
		} else {
			ignored = append(ignored, sc)
		}
	}
	if len(ignored) > 0 {
		s.log.Warn("connect flow ignored scopes no tool needs", "event", "connections.scopes_ignored", "user_id", req.UserID,
			"vendor", app.Vendor, "variant", app.Variant, "scopes", strings.Join(ignored, " "))
	}
	var reads []string
	if len(req.Scopes) == 0 {
		reads = readScopes(s.visibleTools(ctx, vis, req.UserID, tools), tools)
	}
	previous, err := s.grantedScopes(ctx, req.UserID, req.ConnectionID, app)
	if err != nil {
		return nil, err
	}
	return unionScopes(app.Scopes, previous, accepted, reads), nil
}

// readScopes are the required and optional scopes of the visible read
// tools that no write tool of the vendor needs: a scope a write needs
// (Slack's chat:write, which list_scheduled_messages also requires)
// lets the account write, so it waits for grant more access.
func readScopes(visible, all []connectors.Tool) []string {
	writes := map[string]bool{}
	for _, t := range all {
		if t.Kind == connectors.KindWrite {
			for _, sc := range t.RequiredScopes {
				writes[sc] = true
			}
		}
	}
	var out []string
	for _, t := range visible {
		if t.Kind != connectors.KindRead {
			continue
		}
		for _, sc := range slices.Concat(t.RequiredScopes, t.OptionalScopes) {
			if !writes[sc] {
				out = append(out, sc)
			}
		}
	}
	return out
}

// grantedScopes returns the scopes of the user's connection
// connectionID when it is a live (not revoked) connection of app; none
// otherwise (no connection named, someone else's, another app's).
func (s *Service) grantedScopes(ctx context.Context, userID, connectionID string, app VendorApp) ([]string, error) {
	if connectionID == "" {
		return nil, nil
	}
	conns, err := s.Connections(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, c := range conns {
		if c.ID == connectionID && c.Vendor == app.Vendor && c.Variant == app.Variant && c.Status != store.ConnectionRevoked {
			return c.Scopes, nil
		}
	}
	s.log.Warn("connect flow named a connection that is not the user's for this app", "event", "connections.flow_connection_ignored",
		"user_id", userID, "vendor", app.Vendor, "variant", app.Variant)
	return nil, nil
}
