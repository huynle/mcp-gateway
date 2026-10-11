package connector

import (
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/policy"
)

// allowDecider allows and shows everything (the policy stand-in).
type allowDecider struct{ decided int }

func (a *allowDecider) Decide(context.Context, policy.Input) (policy.Decision, error) {
	a.decided++
	return policy.Decision{Outcome: policy.OutcomeAllow, VersionID: "v1"}, nil
}
func (a *allowDecider) Visible(context.Context, policy.Input) (bool, error) { return true, nil }

type failDecider struct{}

func (failDecider) Decide(context.Context, policy.Input) (policy.Decision, error) {
	return policy.Decision{}, errors.New("policy down")
}
func (failDecider) Visible(context.Context, policy.Input) (bool, error) {
	return false, errors.New("policy down")
}

// The Decider wrapper applies server visibility to tools/list, resolve
// and the policy stage alike: a server tool of a server the user may not
// use is hidden, whatever the policy says.
func TestManagerDecider(t *testing.T) {
	f := newFixture(t)
	base := &allowDecider{}
	d := f.m.Decider(base)
	search, _ := f.reg.Get("notes.search")
	builtin, _ := f.reg.Get("github.list_issues")

	if ok, err := d.Visible(t.Context(), policy.Input{UserID: alice, Tool: search}); !ok || err != nil {
		t.Errorf("owner Visible = %v, %v", ok, err)
	}
	if ok, _ := d.Visible(t.Context(), policy.Input{UserID: bob, Tool: search}); ok {
		t.Error("another user sees a private server's tool")
	}
	if ok, _ := d.Visible(t.Context(), policy.Input{UserID: bob, Tool: builtin}); !ok {
		t.Error("built-in visibility not delegated")
	}
	dec, err := d.Decide(t.Context(), policy.Input{UserID: bob, Tool: search})
	if err != nil || dec.Outcome != policy.OutcomeHidden {
		t.Errorf("Decide for a user who cannot see the server = %+v, %v; want hidden", dec, err)
	}
	if base.decided != 0 {
		t.Error("the policy was asked about a server the user cannot see")
	}
	dec, err = d.Decide(t.Context(), policy.Input{UserID: alice, Tool: search})
	if err != nil || dec.Outcome != policy.OutcomeAllow || dec.VersionID != "v1" {
		t.Errorf("owner Decide = %+v, %v", dec, err)
	}
	// Policy failures pass through (the stage fails closed on them).
	if _, err := f.m.Decider(failDecider{}).Decide(t.Context(), policy.Input{UserID: alice, Tool: search}); err == nil {
		t.Error("policy error swallowed")
	}
}
