package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Outcome is what a rule says about a tool (decision 490o45d0). Most
// specific rule wins (a tool rule over the app wildcard); across roles and
// rules of the same specificity, deny beats confirm beats allow. Hidden
// grants nothing: the tool is absent from tools/list and a call answers
// exactly like an unknown tool.
type Outcome string

// The four outcomes.
const (
	OutcomeAllow   Outcome = "allow"
	OutcomeConfirm Outcome = "confirm"
	OutcomeDeny    Outcome = "deny"
	OutcomeHidden  Outcome = "hidden"
)

// Valid reports whether o is one of the four outcomes.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeAllow, OutcomeConfirm, OutcomeDeny, OutcomeHidden:
		return true
	}
	return false
}

// Allowance is a role's stance on personal accounts of one app (decision
// mh7c6z3v): use them like company accounts, confirm every write on them,
// or refuse them. An app without an entry is treated as AllowanceAllow.
type Allowance string

// The three allowances.
const (
	AllowanceAllow         Allowance = "allow"
	AllowanceConfirmWrites Allowance = "confirm_writes"
	AllowanceDeny          Allowance = "deny"
)

// Valid reports whether a is one of the three allowances.
func (a Allowance) Valid() bool {
	switch a {
	case AllowanceAllow, AllowanceConfirmWrites, AllowanceDeny:
		return true
	}
	return false
}

// Op compares a resource-identity value with a condition's value.
type Op string

// The three operators. OpGlob uses Cedar's like pattern: "*" matches any
// run of characters, everything else is literal.
const (
	OpEquals Op = "equals"
	OpPrefix Op = "prefix"
	OpGlob   Op = "glob"
)

// Valid reports whether o is one of the three operators.
func (o Op) Valid() bool {
	switch o {
	case OpEquals, OpPrefix, OpGlob:
		return true
	}
	return false
}

// Wildcard is the Tool value of a rule that applies to every tool of its
// app.
const Wildcard = "*"

// Condition is one argument rule: it reads Key from the resource identity
// the connector extracted (repo, channel, org, site, ...) and compares it
// with Value. A rule's conditions must all hold for the rule to apply; a
// call whose resource identity lacks Key does not match.
type Condition struct {
	Key   string `json:"key"`
	Op    Op     `json:"op"`
	Value string `json:"value"`
}

// ToolRule gives an outcome to one tool of an app, or to every tool of the
// app when Tool is Wildcard. Several rules may name the same tool: an
// allow plus a conditional confirm means "confirm when the condition
// holds, allow otherwise".
type ToolRule struct {
	App        string      `json:"app"`
	Tool       string      `json:"tool"`
	Outcome    Outcome     `json:"outcome"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// Matches reports whether the rule applies to the tool named "app.tool".
func (r ToolRule) Matches(fullName string) bool {
	app, tool, ok := strings.Cut(fullName, ".")
	if !ok || app != r.App {
		return false
	}
	return r.Tool == Wildcard || r.Tool == tool
}

// IsWildcard reports whether the rule covers every tool of its app.
func (r ToolRule) IsWildcard() bool { return r.Tool == Wildcard }

// Role is what admins edit: a name, the tool rules and the per-app
// personal-account allowance. Admin is just a role name; only rules grant
// tools (decision uamxx6ba).
type Role struct {
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	Rules            []ToolRule           `json:"rules,omitempty"`
	PersonalAccounts map[string]Allowance `json:"personal_accounts,omitempty"`
}

// UserRestriction narrows one user below their roles (decision 0ft3v5mh):
// only hidden, deny and confirm rules have an effect; an allow rule cannot
// loosen anything and the compiler ignores it with a warning.
type UserRestriction struct {
	UserID string     `json:"user_id"`
	Rules  []ToolRule `json:"rules,omitempty"`
}

// Assignment binds a user to a role by name.
type Assignment struct {
	UserID string
	Role   string
}

// ErrInvalidRole reports a role, rule, condition or restriction that
// cannot be compiled; the message says which field.
var ErrInvalidRole = errors.New("policy: invalid role")

// identRE is the shape of an app, tool, role or condition key: the same as
// connectors' identifier rule so every rule can name a registered tool.
var identRE = regexp.MustCompile(`^[a-z0-9_-]+$`)

// Validate checks the role can be compiled.
func (r Role) Validate() error {
	if !identRE.MatchString(r.Name) {
		return fmt.Errorf("%w: name %q must be a lower-case identifier", ErrInvalidRole, r.Name)
	}
	if err := validateRules(r.Rules); err != nil {
		return err
	}
	for app, a := range r.PersonalAccounts {
		if !identRE.MatchString(app) {
			return fmt.Errorf("%w: personal account app %q must be a lower-case identifier", ErrInvalidRole, app)
		}
		if !a.Valid() {
			return fmt.Errorf("%w: personal account allowance for %s %q must be allow, confirm_writes or deny", ErrInvalidRole, app, a)
		}
	}
	return nil
}

// Validate checks the restriction can be compiled.
func (u UserRestriction) Validate() error {
	if strings.TrimSpace(u.UserID) == "" {
		return fmt.Errorf("%w: restriction needs a user id", ErrInvalidRole)
	}
	return validateRules(u.Rules)
}

func validateRules(rules []ToolRule) error {
	for i, rule := range rules {
		if !identRE.MatchString(rule.App) {
			return fmt.Errorf("%w: rule %d: app %q must be a lower-case identifier", ErrInvalidRole, i+1, rule.App)
		}
		if rule.Tool != Wildcard && !identRE.MatchString(rule.Tool) {
			return fmt.Errorf("%w: rule %d: tool %q must be a lower-case identifier or *", ErrInvalidRole, i+1, rule.Tool)
		}
		if !rule.Outcome.Valid() {
			return fmt.Errorf("%w: rule %d: outcome %q must be allow, confirm, deny or hidden", ErrInvalidRole, i+1, rule.Outcome)
		}
		for j, c := range rule.Conditions {
			if !identRE.MatchString(c.Key) {
				return fmt.Errorf("%w: rule %d condition %d: key %q must be a lower-case identifier", ErrInvalidRole, i+1, j+1, c.Key)
			}
			if !c.Op.Valid() {
				return fmt.Errorf("%w: rule %d condition %d: operator %q must be equals, prefix or glob", ErrInvalidRole, i+1, j+1, c.Op)
			}
			if c.Value == "" {
				return fmt.Errorf("%w: rule %d condition %d: value must not be empty", ErrInvalidRole, i+1, j+1)
			}
		}
	}
	return nil
}

// Normalize trims and lower-cases identifiers and outcomes and sorts the
// rules (app, tool, outcome, conditions) so two roles that mean the same
// compile to the same text. Condition values are trimmed but keep their
// case: resource identities are vendor data.
func (r *Role) Normalize() {
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	r.Description = strings.TrimSpace(r.Description)
	normalizeRules(r.Rules)
	if len(r.PersonalAccounts) > 0 {
		out := make(map[string]Allowance, len(r.PersonalAccounts))
		for app, a := range r.PersonalAccounts {
			out[strings.ToLower(strings.TrimSpace(app))] = Allowance(strings.ToLower(strings.TrimSpace(string(a))))
		}
		r.PersonalAccounts = out
	}
}

// Normalize is Role.Normalize for a restriction.
func (u *UserRestriction) Normalize() {
	u.UserID = strings.TrimSpace(u.UserID)
	normalizeRules(u.Rules)
}

func normalizeRules(rules []ToolRule) {
	for i := range rules {
		rule := &rules[i]
		rule.App = strings.ToLower(strings.TrimSpace(rule.App))
		rule.Tool = strings.ToLower(strings.TrimSpace(rule.Tool))
		rule.Outcome = Outcome(strings.ToLower(strings.TrimSpace(string(rule.Outcome))))
		for j := range rule.Conditions {
			c := &rule.Conditions[j]
			c.Key = strings.ToLower(strings.TrimSpace(c.Key))
			c.Op = Op(strings.ToLower(strings.TrimSpace(string(c.Op))))
			c.Value = strings.TrimSpace(c.Value)
		}
		slices.SortFunc(rule.Conditions, compareConditions)
	}
	slices.SortFunc(rules, compareRules)
}

func compareRules(a, b ToolRule) int {
	if c := strings.Compare(a.App, b.App); c != 0 {
		return c
	}
	// The wildcard sorts before named tools.
	if a.IsWildcard() != b.IsWildcard() {
		if a.IsWildcard() {
			return -1
		}
		return 1
	}
	if c := strings.Compare(a.Tool, b.Tool); c != 0 {
		return c
	}
	if c := strings.Compare(string(a.Outcome), string(b.Outcome)); c != 0 {
		return c
	}
	return slices.CompareFunc(a.Conditions, b.Conditions, compareConditions)
}

func compareConditions(a, b Condition) int {
	if c := strings.Compare(a.Key, b.Key); c != 0 {
		return c
	}
	if c := strings.Compare(string(a.Op), string(b.Op)); c != 0 {
		return c
	}
	return strings.Compare(a.Value, b.Value)
}

// definition is the roles.definition / user_restrictions.definition JSON
// document: everything but the name and description, which are columns.
type definition struct {
	Rules            []ToolRule           `json:"rules,omitempty"`
	PersonalAccounts map[string]Allowance `json:"personal_accounts,omitempty"`
}

// MarshalDefinition renders the rules and allowances for the roles table.
func (r Role) MarshalDefinition() (json.RawMessage, error) {
	return json.Marshal(definition{Rules: r.Rules, PersonalAccounts: r.PersonalAccounts})
}

// RoleFromDefinition rebuilds a role from its columns. An empty or null
// definition is a role that grants nothing.
func RoleFromDefinition(name, description string, raw json.RawMessage) (Role, error) {
	d, err := decodeDefinition(raw)
	if err != nil {
		return Role{}, fmt.Errorf("policy: role %q: %w", name, err)
	}
	return Role{Name: name, Description: description, Rules: d.Rules, PersonalAccounts: d.PersonalAccounts}, nil
}

// MarshalDefinition renders the rules for the user_restrictions table.
func (u UserRestriction) MarshalDefinition() (json.RawMessage, error) {
	return json.Marshal(definition{Rules: u.Rules})
}

// RestrictionFromDefinition rebuilds a restriction from its columns.
func RestrictionFromDefinition(userID string, raw json.RawMessage) (UserRestriction, error) {
	d, err := decodeDefinition(raw)
	if err != nil {
		return UserRestriction{}, fmt.Errorf("policy: restriction for %s: %w", userID, err)
	}
	return UserRestriction{UserID: userID, Rules: d.Rules}, nil
}

func decodeDefinition(raw json.RawMessage) (definition, error) {
	var d definition
	if len(raw) == 0 || string(raw) == "null" {
		return d, nil
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return definition{}, fmt.Errorf("decode definition: %w", err)
	}
	return d, nil
}
