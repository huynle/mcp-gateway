package policy

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ServerApproval is the approval-mode layer of one active user-added MCP
// server (the per-tool "ask" / "auto" of its approved snapshot review,
// internal/federation/snapshot Approval). It is the server-level default
// for every principal that may call the server's tools (the owner layer
// and role grants alike):
//
//   - a write tool named in AutoRun runs without a confirmation when the
//     call is otherwise allowed (owner layer, or a role allow);
//   - every other write tool of the app needs a confirmation (ask), even
//     under a role allow;
//   - read tools are not touched.
//
// It only removes the confirmation it adds itself: a role's or a user
// restriction's own confirm still confirms, and forbids (role deny, user
// restriction deny, token narrowing) still win. App is the server name
// (the tool prefix); AutoRun holds registry tool names without the
// prefix. Every app of an OwnerGrant gets this layer, with an empty
// AutoRun when no ServerApproval names it (all writes ask).
type ServerApproval struct {
	App     string
	AutoRun []string
}

// Validate checks the layer can be compiled.
func (a ServerApproval) Validate() error {
	if !identRE.MatchString(a.App) {
		return fmt.Errorf("%w: server approval app %q must be a lower-case identifier", ErrInvalidRole, a.App)
	}
	for _, t := range a.AutoRun {
		if !identRE.MatchString(t) {
			return fmt.Errorf("%w: server approval tool %q of %s must be a lower-case identifier", ErrInvalidRole, t, a.App)
		}
	}
	return nil
}

// Layers are the implicit layers of user-added MCP servers compiled next
// to the roles: the owners' grants and the servers' approval modes.
type Layers struct {
	Owners  []OwnerGrant
	Servers []ServerApproval
}

// normalizeServers validates the layers and returns, per app, the sorted
// and de-duplicated auto-run tool names; every owner app is present
// (empty list) so its writes ask by default.
func normalizeServers(servers []ServerApproval, owners []OwnerGrant) (map[string][]string, error) {
	out := map[string][]string{}
	for _, g := range owners {
		if _, ok := out[g.App]; !ok {
			out[g.App] = nil
		}
	}
	for _, s := range servers {
		s.App = strings.ToLower(strings.TrimSpace(s.App))
		if err := s.Validate(); err != nil {
			return nil, err
		}
		list := slices.Concat(out[s.App], s.AutoRun)
		slices.Sort(list)
		out[s.App] = slices.Compact(list)
	}
	return out, nil
}

// serverApproval emits the confirm-writes policy of one server app: every
// write of the app confirms, unless it is one of the auto-run tools.
func (w *writer) serverApproval(app string, auto []string) {
	resource := fmt.Sprintf(`resource in %s::%s`, EntityApp, strconv.Quote(app))
	var unless []string
	if len(auto) > 0 {
		names := make([]string, len(auto))
		for i, t := range auto {
			names[i] = strconv.Quote(app + "." + t)
		}
		unless = []string{"[" + strings.Join(names, ", ") + "].contains(resource.name)"}
	}
	w.policy("server/"+app+"/confirm_writes", "permit", "principal", actions(ActionConfirm), resource,
		[]string{`resource.kind == "write"`}, unless)
}

// sortedKeys returns m's keys in order.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
