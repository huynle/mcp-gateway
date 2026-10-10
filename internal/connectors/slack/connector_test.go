package slack_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/connectortest"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
	"github.com/huynle/mcp-gateway/internal/policy"
)

func TestSlackPassesContract(t *testing.T) {
	for name, marker := range map[string]bool{"default": false, "marker reconcile": true} {
		t.Run(name, func(t *testing.T) {
			c, err := slack.New(slack.Options{Tokens: (&tokens{}).source, MarkerReconcile: marker})
			if err != nil {
				t.Fatal(err)
			}
			connectortest.ContractTest(t, c)
		})
	}
}

// Acceptance: a role rule "post only to #eng-*" is a prefix condition on
// the channel of the resource identity. Compiled through the real policy
// engine, a post to #eng-deploys is allowed, a post to #random is
// denied, and a post that names the channel by id does not match the
// rule and is denied too (the safe default: the gateway cannot know the
// name without a lookup, and policy must not depend on one).
func TestRoleRulePostOnlyToEngChannels(t *testing.T) {
	c, err := slack.New(slack.Options{Tokens: (&tokens{}).source})
	if err != nil {
		t.Fatal(err)
	}
	var post connectors.Tool
	for _, tool := range c.Tools() {
		if tool.Name == slack.ToolPostMessage {
			post = tool
		}
	}
	role := policy.Role{Name: "engineer", Rules: []policy.ToolRule{{
		App: slack.App, Tool: slack.ToolPostMessage, Outcome: policy.OutcomeAllow,
		Conditions: []policy.Condition{{Key: "channel", Op: policy.OpPrefix, Value: "eng-"}},
	}}}
	compiled, err := policy.Compile([]policy.Role{role}, []policy.Assignment{{UserID: alice, Role: "engineer"}}, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cases := map[string]struct {
		channel string
		want    policy.Outcome
	}{
		"#eng-deploys":          {"#eng-deploys", policy.OutcomeAllow},
		"eng-general, no hash":  {"eng-general", policy.OutcomeAllow},
		"#ENG-Leads, any case":  {"#ENG-Leads", policy.OutcomeAllow},
		"#random":               {"#random", policy.OutcomeDeny},
		"#engineering-adjacent": {"#engineering", policy.OutcomeDeny},
		"by id":                 {"C0ENGGEN01", policy.OutcomeDeny},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := policy.Input{
				UserID: alice, Roles: []string{"engineer"}, TokenID: "tok", Tool: post, AccountLabel: "company",
				ResourceIdentity: post.ResourceIdentity(map[string]any{"channel": tc.channel, "text": "secret text"}),
			}
			if d := compiled.Decide(in); d.Outcome != tc.want {
				t.Errorf("Decide(%s) = %s (%s), want %s", tc.channel, d.Outcome, d.Reason, tc.want)
			}
		})
	}
}
