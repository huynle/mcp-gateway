package policy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/store"
)

// MemberBaselineRole is the role "Apply public member baseline" edits.
const MemberBaselineRole = "member"

// MemberBaselineApps lists the apps the public member baseline grants:
// every built-in (vendor) app registered at this moment, without
// user-added MCP servers (their owners and publishing decide who sees
// them) and without the gateway management app (behind its own
// permission and per-user switch).
func MemberBaselineApps(reg *connectors.Registry) []string {
	if reg == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, t := range reg.List() {
		if t.App == GatewayApp || reg.IsServerApp(t.App) {
			continue
		}
		seen[t.App] = true
	}
	out := make([]string, 0, len(seen))
	for app := range seen {
		out = append(out, app)
	}
	sort.Strings(out)
	return out
}

// ApplyMemberBaseline is the explicit admin action behind "Apply public
// member baseline" (the service never seeds roles on its own): it adds an
// "<app>.*: allow" rule to the member role for every app in apps that has
// no "*" rule yet (an admin's existing rules, including denies and
// confirms, are kept: deny wins over allow), sets may_add_servers, creates
// the role when missing, audits the change and recompiles. It does not
// make member the default role. Running it again changes nothing.
func (s *Service) ApplyMemberBaseline(ctx context.Context, actorID string, apps []string) error {
	role, err := s.Role(ctx, MemberBaselineRole)
	switch {
	case errors.Is(err, store.ErrNotFound):
		role = Role{Name: MemberBaselineRole, Description: "Public member baseline"}
	case err != nil:
		return err
	}
	has := map[string]bool{}
	for _, r := range role.Rules {
		if r.Tool == Wildcard {
			has[r.App] = true
		}
	}
	for _, app := range apps {
		if !identRE.MatchString(app) {
			return fmt.Errorf("%w: app %q must be a lower-case identifier", ErrInvalidRole, app)
		}
		if !has[app] {
			role.Rules = append(role.Rules, ToolRule{App: app, Tool: Wildcard, Outcome: OutcomeAllow})
			has[app] = true
		}
	}
	role.MayAddServers = true
	role.Normalize()
	if err := role.Validate(); err != nil {
		return err
	}
	if err := s.store.SaveRole(ctx, role); err != nil {
		return err
	}
	return s.afterChange(ctx, actorID, "member_baseline_applied", role.Name, map[string]string{
		"apps": strconv.Itoa(len(apps)), "may_add_servers": "true",
	})
}
