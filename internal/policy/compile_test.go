package policy

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden .cedar files under testdata")

// fixture is one testdata/<name>.json: the inputs of Compile.
type fixture struct {
	Roles        []Role            `json:"roles"`
	Assignments  []Assignment      `json:"assignments"`
	Restrictions []UserRestriction `json:"restrictions"`
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

func compileFixture(t *testing.T, name string) *Compiled {
	t.Helper()
	f := loadFixture(t, name)
	c, err := Compile(f.Roles, f.Assignments, f.Restrictions)
	if err != nil {
		t.Fatalf("Compile(%s): %v", name, err)
	}
	return c
}

// TestGolden compiles every testdata/*.json fixture and compares the Cedar
// text with testdata/<name>.cedar. Run with -update to rewrite them.
func TestGolden(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no fixtures under testdata")
	}
	for _, path := range names {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		t.Run(name, func(t *testing.T) {
			c := compileFixture(t, name)
			golden := filepath.Join("testdata", name+".cedar")
			if *update {
				if err := os.WriteFile(golden, []byte(c.Cedar), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if string(want) != c.Cedar {
				t.Errorf("Cedar text differs from %s (run with -update after reviewing):\n--- want\n%s\n--- got\n%s", golden, want, c.Cedar)
			}
			// The text must be a parseable Cedar document and the version
			// its hash.
			again, err := Compile(loadFixture(t, name).Roles, nil, loadFixture(t, name).Restrictions)
			if err != nil {
				t.Fatal(err)
			}
			if again.Version == c.Version && len(loadFixture(t, name).Assignments) > 0 {
				t.Error("dropping the assignments did not change the version")
			}
			if len(c.Version) != 64 {
				t.Errorf("Version = %q, want a sha256 hex digest", c.Version)
			}
		})
	}
}

func TestCompileIsDeterministic(t *testing.T) {
	f := loadFixture(t, "engineering")
	a, err := Compile(f.Roles, f.Assignments, f.Restrictions)
	if err != nil {
		t.Fatal(err)
	}
	// Shuffle the inputs: same policy, same text, same version.
	roles := append([]Role(nil), f.Roles...)
	roles[0], roles[len(roles)-1] = roles[len(roles)-1], roles[0]
	for i := range roles {
		rules := roles[i].Rules
		for j := 0; j < len(rules)/2; j++ {
			rules[j], rules[len(rules)-1-j] = rules[len(rules)-1-j], rules[j]
		}
	}
	b, err := Compile(roles, f.Assignments, f.Restrictions)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cedar != b.Cedar || a.Version != b.Version {
		t.Errorf("order of inputs changed the output:\n%s\n%s", a.Cedar, b.Cedar)
	}
}

func TestCompileVersionTracksRoleChanges(t *testing.T) {
	f := loadFixture(t, "engineering")
	before, err := Compile(f.Roles, f.Assignments, f.Restrictions)
	if err != nil {
		t.Fatal(err)
	}
	f.Roles[0].Rules = append(f.Roles[0].Rules, ToolRule{App: "jira", Tool: "*", Outcome: OutcomeAllow})
	after, err := Compile(f.Roles, f.Assignments, f.Restrictions)
	if err != nil {
		t.Fatal(err)
	}
	if before.Version == after.Version {
		t.Error("adding a rule kept the version")
	}
	// A description change is not a policy change.
	f.Roles[0].Description = "renamed"
	again, err := Compile(f.Roles, f.Assignments, f.Restrictions)
	if err != nil {
		t.Fatal(err)
	}
	if again.Version != after.Version {
		t.Error("changing a description changed the version")
	}
}

func TestCompileRejectsInvalidInput(t *testing.T) {
	_, err := Compile([]Role{{Name: "Bad Name"}}, nil, nil)
	if !errors.Is(err, ErrInvalidRole) {
		t.Errorf("bad role: %v", err)
	}
	_, err = Compile([]Role{{Name: "a"}, {Name: "a"}}, nil, nil)
	if !errors.Is(err, ErrInvalidRole) {
		t.Errorf("duplicate role: %v", err)
	}
	_, err = Compile([]Role{{Name: "a", Rules: []ToolRule{{App: "github", Tool: "*", Outcome: OutcomeHidden, Conditions: []Condition{{Key: "repo", Op: OpEquals, Value: "x"}}}}}}, nil, nil)
	if !errors.Is(err, ErrInvalidRole) {
		t.Errorf("hidden with conditions: %v", err)
	}
	_, err = Compile([]Role{{Name: "a"}}, []Assignment{{UserID: "u1", Role: "ghost"}}, nil)
	if !errors.Is(err, ErrInvalidRole) {
		t.Errorf("assignment to unknown role: %v", err)
	}
	_, err = Compile(nil, nil, []UserRestriction{{UserID: "", Rules: nil}})
	if !errors.Is(err, ErrInvalidRole) {
		t.Errorf("restriction without user: %v", err)
	}
}

func TestCompileIgnoresLooseningRestrictionsWithWarning(t *testing.T) {
	roles := []Role{{Name: "member"}}
	restrictions := []UserRestriction{{UserID: "u1", Rules: []ToolRule{
		{App: "github", Tool: "*", Outcome: OutcomeAllow},
		{App: "github", Tool: "delete_repo", Outcome: OutcomeDeny},
	}}}
	c, err := Compile(roles, nil, restrictions)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "u1") || !strings.Contains(c.Warnings[0], "github.*") {
		t.Errorf("warnings = %v, want one naming the user and the ignored allow rule", c.Warnings)
	}
	if strings.Contains(c.Cedar, `permit`) && strings.Contains(c.Cedar, `User::"u1"`) && strings.Contains(c.Cedar, `Action::"call"`) {
		// A restriction may only ever add forbids and confirm permits.
		for _, line := range strings.Split(c.Cedar, "\n") {
			if strings.Contains(line, `User::"u1"`) && strings.Contains(line, "permit") {
				t.Errorf("restriction compiled to a permit: %s", line)
			}
		}
	}
	if !strings.Contains(c.Cedar, `Tool::"github.delete_repo"`) {
		t.Errorf("deny restriction missing:\n%s", c.Cedar)
	}
}

func TestCompiledRolesFor(t *testing.T) {
	c := compileFixture(t, "engineering")
	if got := c.RolesFor("u-alice"); strings.Join(got, ",") != "admin,engineer" {
		t.Errorf("RolesFor(u-alice) = %v", got)
	}
	if got := c.RolesFor("nobody"); len(got) != 0 {
		t.Errorf("RolesFor(nobody) = %v", got)
	}
	if !c.KnowsUser("u-alice") || c.KnowsUser("nobody") {
		t.Error("KnowsUser wrong")
	}
}

func TestCompileEmpty(t *testing.T) {
	c, err := Compile(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Cedar == "" || c.Version == "" {
		t.Errorf("empty compile = %+v", c)
	}
}
