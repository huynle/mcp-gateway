package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validRole() Role {
	return Role{
		Name:        "engineer",
		Description: "Engineers",
		Rules: []ToolRule{
			{App: "github", Tool: "*", Outcome: OutcomeAllow},
			{App: "github", Tool: "create_issue", Outcome: OutcomeConfirm, Conditions: []Condition{{Key: "repo", Op: OpPrefix, Value: "acme/"}}},
			{App: "slack", Tool: "post_message", Outcome: OutcomeDeny, Conditions: []Condition{{Key: "channel", Op: OpGlob, Value: "#exec-*"}}},
		},
		PersonalAccounts: map[string]Allowance{"github": AllowanceConfirmWrites, "slack": AllowanceDeny},
	}
}

func TestRoleValidateAccepts(t *testing.T) {
	if err := validRole().Validate(); err != nil {
		t.Fatalf("valid role rejected: %v", err)
	}
}

func TestRoleValidateRejects(t *testing.T) {
	cases := map[string]func(*Role){
		"empty name":        func(r *Role) { r.Name = "" },
		"upper-case name":   func(r *Role) { r.Name = "Engineer" },
		"name with space":   func(r *Role) { r.Name = "eng team" },
		"empty app":         func(r *Role) { r.Rules[0].App = "" },
		"app with dot":      func(r *Role) { r.Rules[0].App = "git.hub" },
		"empty tool":        func(r *Role) { r.Rules[0].Tool = "" },
		"bad tool":          func(r *Role) { r.Rules[1].Tool = "Create Issue" },
		"unknown outcome":   func(r *Role) { r.Rules[0].Outcome = "maybe" },
		"empty outcome":     func(r *Role) { r.Rules[0].Outcome = "" },
		"condition no key":  func(r *Role) { r.Rules[1].Conditions[0].Key = "" },
		"condition bad key": func(r *Role) { r.Rules[1].Conditions[0].Key = "Repo Name" },
		"condition no op":   func(r *Role) { r.Rules[1].Conditions[0].Op = "" },
		"condition bad op":  func(r *Role) { r.Rules[1].Conditions[0].Op = "regex" },
		"condition empty":   func(r *Role) { r.Rules[1].Conditions[0].Value = "" },
		"bad allowance":     func(r *Role) { r.PersonalAccounts["github"] = "sometimes" },
		"bad allowance app": func(r *Role) { r.PersonalAccounts["Git Hub"] = AllowanceAllow },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRole()
			mutate(&r)
			err := r.Validate()
			if !errors.Is(err, ErrInvalidRole) {
				t.Fatalf("Validate() = %v, want ErrInvalidRole", err)
			}
		})
	}
}

func TestRoleDefinitionRoundTrip(t *testing.T) {
	r := validRole()
	raw, err := r.MarshalDefinition()
	if err != nil {
		t.Fatal(err)
	}
	// Name and description live in their own columns, not in the definition.
	if strings.Contains(string(raw), "engineer") || strings.Contains(string(raw), "Engineers") {
		t.Errorf("definition carries name/description: %s", raw)
	}
	got, err := RoleFromDefinition("engineer", "Engineers", raw)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(r)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Errorf("round trip changed the role:\n%s\n%s", a, b)
	}
}

func TestRoleFromEmptyDefinition(t *testing.T) {
	for _, raw := range []string{"", "{}", "null"} {
		got, err := RoleFromDefinition("member", "", json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if got.Name != "member" || len(got.Rules) != 0 || len(got.PersonalAccounts) != 0 {
			t.Errorf("%q: got %+v", raw, got)
		}
	}
	if _, err := RoleFromDefinition("member", "", json.RawMessage(`{"rules": 5}`)); err == nil {
		t.Error("malformed definition accepted")
	}
}

func TestRoleNormalizeSortsAndLowercases(t *testing.T) {
	r := Role{Name: " Engineer ", Rules: []ToolRule{
		{App: "Slack", Tool: "Post_Message", Outcome: "DENY"},
		{App: "github", Tool: "*", Outcome: "allow"},
		{App: "github", Tool: "create_issue", Outcome: "confirm", Conditions: []Condition{{Key: " Repo ", Op: "PREFIX", Value: " acme/ "}}},
	}, PersonalAccounts: map[string]Allowance{"GitHub": "CONFIRM_WRITES"}}
	r.Normalize()
	if r.Name != "engineer" {
		t.Errorf("name = %q", r.Name)
	}
	want := []string{"github.* allow", "github.create_issue confirm", "slack.post_message deny"}
	for i, rule := range r.Rules {
		if got := rule.App + "." + rule.Tool + " " + string(rule.Outcome); got != want[i] {
			t.Errorf("rule %d = %q, want %q", i, got, want[i])
		}
	}
	c := r.Rules[1].Conditions[0]
	if c.Key != "repo" || c.Op != OpPrefix || c.Value != "acme/" {
		t.Errorf("condition = %+v", c)
	}
	if r.PersonalAccounts["github"] != AllowanceConfirmWrites || len(r.PersonalAccounts) != 1 {
		t.Errorf("personal accounts = %v", r.PersonalAccounts)
	}
	if err := r.Validate(); err != nil {
		t.Errorf("normalised role invalid: %v", err)
	}
}

func TestUserRestrictionValidate(t *testing.T) {
	ur := UserRestriction{UserID: "u1", Rules: []ToolRule{{App: "github", Tool: "*", Outcome: OutcomeDeny}}}
	if err := ur.Validate(); err != nil {
		t.Fatal(err)
	}
	ur.UserID = ""
	if err := ur.Validate(); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("empty user id: %v", err)
	}
	ur.UserID = "u1"
	ur.Rules[0].Outcome = "nope"
	if err := ur.Validate(); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("bad outcome: %v", err)
	}
}

func TestRuleMatchesTool(t *testing.T) {
	cases := []struct {
		rule ToolRule
		tool string
		want bool
	}{
		{ToolRule{App: "github", Tool: "*"}, "github.create_issue", true},
		{ToolRule{App: "github", Tool: "*"}, "slack.post_message", false},
		{ToolRule{App: "github", Tool: "create_issue"}, "github.create_issue", true},
		{ToolRule{App: "github", Tool: "create_issue"}, "github.list_issues", false},
	}
	for _, c := range cases {
		if got := c.rule.Matches(c.tool); got != c.want {
			t.Errorf("%+v Matches(%q) = %v, want %v", c.rule, c.tool, got, c.want)
		}
	}
}

func TestRoleValidateRejectsHiddenWithConditionsAndControlChars(t *testing.T) {
	r := validRole()
	r.Rules[0].Outcome = OutcomeHidden
	r.Rules[0].Conditions = []Condition{{Key: "repo", Op: OpEquals, Value: "x"}}
	if err := r.Validate(); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("hidden with conditions: %v", err)
	}
	r = validRole()
	r.Rules[1].Conditions[0].Value = "acme/\n"
	if err := r.Validate(); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("control character: %v", err)
	}
}
