package connections_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
)

// PolicyAllowance asks the compiled roles: a user whose roles include one
// that denies personal accounts for the app is refused (deny wins across
// roles, as in the Cedar policy); confirm_writes and allow permit the
// connection; a user without roles is permitted (nothing denies).
func TestPolicyAllowanceFollowsAssignedRoles(t *testing.T) {
	st := policytest.NewMemStore()
	st.PutRole(policy.Role{Name: "member", Rules: []policy.ToolRule{{App: "fake", Tool: "*", Outcome: policy.OutcomeAllow}}})
	st.PutRole(policy.Role{Name: "strict", PersonalAccounts: map[string]policy.Allowance{"fake": policy.AllowanceDeny}})
	st.PutRole(policy.Role{Name: "careful", PersonalAccounts: map[string]policy.Allowance{"fake": policy.AllowanceConfirmWrites, "github": policy.AllowanceDeny}})
	st.Assign(userAlice, "member")
	st.Assign(userAlice, "strict")
	st.Assign(userBob, "member")
	st.Assign(userBob, "careful")
	svc, err := policy.New(st, policy.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	pa := connections.PolicyAllowance{Service: svc}
	ctx := context.Background()
	cases := []struct {
		user, app string
		want      bool
	}{
		{userAlice, "fake", false},
		{userAlice, "github", true},
		{userBob, "fake", true},
		{userBob, "github", false},
		{"33333333-3333-4333-8333-333333333333", "fake", true},
	}
	for _, c := range cases {
		got, err := pa.PersonalAccountsAllowed(ctx, c.user, c.app)
		if err != nil || got != c.want {
			t.Errorf("PersonalAccountsAllowed(%s, %s) = %v, %v; want %v", c.user, c.app, got, err, c.want)
		}
	}
}
