package policy

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// OwnerGrant is the implicit policy layer for the owner of an active
// user-added MCP server (Brain task fybs78bs, decision mrvsu07m):
// the owner may list and call every tool of the server's app (App is the
// server name, the tool prefix), reads are allowed and writes need a
// confirmation. It is compiled into the same Cedar set as the roles, so
// the token-narrowing forbids and user restrictions still apply, a role
// can add confirmations or denials but never lift the write confirmation,
// and the admin role gets nothing from it (admin is only a role name).
// The layer applies whether the server is private or published (decision
// q7vbxlyk, task fekckdrt): publishing shares the server with the chosen
// roles, whose holders still need a role grant, and the owner keeps
// access.
type OwnerGrant struct {
	UserID string
	App    string
}

// Validate checks the grant can be compiled.
func (g OwnerGrant) Validate() error {
	switch {
	case strings.TrimSpace(g.UserID) == "":
		return fmt.Errorf("%w: owner grant needs a user id", ErrInvalidRole)
	case !identRE.MatchString(g.App):
		return fmt.Errorf("%w: owner grant app %q must be a lower-case identifier", ErrInvalidRole, g.App)
	case strings.ContainsAny(g.UserID, "\"\\\n\r"):
		return fmt.Errorf("%w: owner grant user id must not contain quotes or line breaks", ErrInvalidRole)
	}
	return nil
}

// normalizeOwners trims, validates, sorts and de-duplicates grants so the
// compiled text (and its version) does not depend on their order.
func normalizeOwners(owners []OwnerGrant) ([]OwnerGrant, error) {
	out := make([]OwnerGrant, 0, len(owners))
	for _, g := range owners {
		g.UserID, g.App = strings.TrimSpace(g.UserID), strings.ToLower(strings.TrimSpace(g.App))
		if err := g.Validate(); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b OwnerGrant) int {
		if c := strings.Compare(a.UserID, b.UserID); c != 0 {
			return c
		}
		return strings.Compare(a.App, b.App)
	})
	return slices.Compact(out), nil
}

// owner emits one owner grant: list and call every tool of the app, and
// confirm its writes.
func (w *writer) owner(g OwnerGrant) {
	principal := fmt.Sprintf(`principal == %s::%s`, EntityUser, strconv.Quote(g.UserID))
	resource := fmt.Sprintf(`resource in %s::%s`, EntityApp, strconv.Quote(g.App))
	id := "owner/" + g.UserID + "/" + g.App
	w.policy(id, "permit", principal, actions(ActionCall, ActionList), resource, nil, nil)
	w.policy(id+"/confirm_writes", "permit", principal, actions(ActionConfirm), resource, []string{`resource.kind == "write"`}, nil)
}
