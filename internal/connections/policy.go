package connections

import (
	"context"
	"fmt"
	"slices"

	"github.com/huynle/mcp-gateway/internal/policy"
)

// PolicyAllowance implements PersonalAccountPolicy over the policy
// service: a personal account is refused for an app when any of the
// user's assigned roles sets the app's personal-account allowance to deny
// (deny wins across roles, exactly as the compiled Cedar forbid does at
// call time; decision mh7c6z3v). allow and confirm_writes permit the
// connection; confirmation of writes is the policy stage's job later.
type PolicyAllowance struct {
	Service *policy.Service
}

// PersonalAccountsAllowed implements PersonalAccountPolicy.
func (p PolicyAllowance) PersonalAccountsAllowed(ctx context.Context, userID, app string) (bool, error) {
	compiled, err := p.Service.Current(ctx)
	if err != nil {
		return false, fmt.Errorf("connections: policy: %w", err)
	}
	assigned := compiled.RolesFor(userID)
	if len(assigned) == 0 {
		return true, nil
	}
	roles, err := p.Service.Roles(ctx)
	if err != nil {
		return false, fmt.Errorf("connections: policy roles: %w", err)
	}
	for _, r := range roles {
		if slices.Contains(assigned, r.Name) && r.PersonalAccounts[app] == policy.AllowanceDeny {
			return false, nil
		}
	}
	return true, nil
}
