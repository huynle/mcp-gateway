package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// Cedar vocabulary the compiler emits and Decide evaluates against
// (decision 490o45d0). Principals are User entities whose parents are
// their Role entities; resources are Tool entities whose parent is their
// App entity; the three actions are separate namespaces: call (may the
// tool run), confirm (does it need an approval first) and list (is it
// visible at all). Context carries the token (an entity with the scope),
// the resolved account's label and the resource identity the connector
// extracted.
const (
	EntityUser  = "User"
	EntityRole  = "Role"
	EntityTool  = "Tool"
	EntityApp   = "App"
	EntityToken = "Token"

	ActionCall    = "call"
	ActionConfirm = "confirm"
	ActionList    = "list"
)

// Compiled is one policy set: the canonical Cedar text, its version (the
// SHA-256 of the text, hex) and the parsed set Decide evaluates. ID is
// the policy_versions row the Service persisted it under; empty until
// then. Warnings list restriction rules that were ignored because they
// would loosen a role.
type Compiled struct {
	Version  string
	Cedar    string
	ID       string
	Warnings []string

	set         *cedar.PolicySet
	ids         map[cedar.PolicyID]string
	assignments map[string][]string
	owners      map[string]bool
}

// RolesFor returns the role names assigned to userID in sorted order, or
// nil when the user had no assignment at compile time.
func (c *Compiled) RolesFor(userID string) []string {
	return slices.Clone(c.assignments[userID])
}

// KnowsUser reports whether userID had at least one assignment at compile
// time. The Service refreshes early for users it does not know (a user
// created since the last compile).
func (c *Compiled) KnowsUser(userID string) bool {
	_, ok := c.assignments[userID]
	return ok || c.owners[userID]
}

// Compile turns roles, assignments and restrictions into a Cedar policy
// set. Inputs are normalised and validated; the output text is canonical
// (sorted, fixed layout) so equal policies have equal versions. Every
// role name an assignment or restriction refers to must exist. The
// token-narrowing forbids are part of every policy set (decision
// uamxx6ba: a token narrows below the role, never widens).
func Compile(roles []Role, assignments []Assignment, restrictions []UserRestriction) (*Compiled, error) {
	return CompileWithOwners(roles, assignments, restrictions, nil)
}

// CompileWithOwners is Compile plus the implicit owner layer of
// user-added MCP servers (OwnerGrant), with every server write asking for
// a confirmation (no approval modes). Without grants it produces exactly
// what Compile does.
func CompileWithOwners(roles []Role, assignments []Assignment, restrictions []UserRestriction, owners []OwnerGrant) (*Compiled, error) {
	return CompileWithLayers(roles, assignments, restrictions, Layers{Owners: owners})
}

// CompileWithLayers is Compile plus the implicit layers of user-added MCP
// servers: the owner grants (OwnerGrant) and the servers' approval modes
// (ServerApproval). Without layers it produces exactly what Compile does.
func CompileWithLayers(roles []Role, assignments []Assignment, restrictions []UserRestriction, layers Layers) (*Compiled, error) {
	owners, err := normalizeOwners(layers.Owners)
	if err != nil {
		return nil, err
	}
	servers, err := normalizeServers(layers.Servers, owners)
	if err != nil {
		return nil, err
	}
	roles = slices.Clone(roles)
	byName := map[string]bool{}
	for i := range roles {
		roles[i].Normalize()
		if err := roles[i].Validate(); err != nil {
			return nil, err
		}
		if byName[roles[i].Name] {
			return nil, fmt.Errorf("%w: role %q defined twice", ErrInvalidRole, roles[i].Name)
		}
		byName[roles[i].Name] = true
	}
	slices.SortFunc(roles, func(a, b Role) int { return strings.Compare(a.Name, b.Name) })

	assigned := map[string][]string{}
	for _, a := range assignments {
		user, role := strings.TrimSpace(a.UserID), strings.ToLower(strings.TrimSpace(a.Role))
		if user == "" {
			return nil, fmt.Errorf("%w: assignment without a user id", ErrInvalidRole)
		}
		if !byName[role] {
			return nil, fmt.Errorf("%w: user %s is assigned unknown role %q", ErrInvalidRole, user, role)
		}
		if !slices.Contains(assigned[user], role) {
			assigned[user] = append(assigned[user], role)
		}
	}
	for _, list := range assigned {
		slices.Sort(list)
	}

	restrictions = slices.Clone(restrictions)
	for i := range restrictions {
		restrictions[i].Normalize()
		if err := restrictions[i].Validate(); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(restrictions, func(a, b UserRestriction) int { return strings.Compare(a.UserID, b.UserID) })

	w := &writer{}
	w.header(assigned)
	w.tokenPolicies()
	w.gateway()
	for _, r := range roles {
		w.role(r)
	}
	ownerSet := map[string]bool{}
	for _, g := range owners {
		w.owner(g)
		ownerSet[g.UserID] = true
	}
	for _, app := range sortedKeys(servers) {
		w.serverApproval(app, servers[app])
	}
	var warnings []string
	for _, u := range restrictions {
		warnings = append(warnings, w.restriction(u)...)
	}
	text := w.String()

	set, err := cedar.NewPolicySetFromBytes("policy.cedar", []byte(text))
	if err != nil {
		// Every construct the writer emits is covered by the golden tests;
		// a parse failure here is a compiler bug, not bad admin input.
		return nil, fmt.Errorf("policy: compiled text does not parse: %w", err)
	}
	ids := map[cedar.PolicyID]string{}
	for id, p := range set.All() {
		if label, ok := p.Annotations()["id"]; ok {
			ids[id] = string(label)
		}
	}
	sum := sha256.Sum256([]byte(text))
	return &Compiled{
		Version:     hex.EncodeToString(sum[:]),
		Cedar:       text,
		Warnings:    warnings,
		set:         set,
		ids:         ids,
		assignments: assigned,
		owners:      ownerSet,
	}, nil
}

// writer accumulates the canonical text.
type writer struct {
	b strings.Builder
}

func (w *writer) String() string { return w.b.String() }

func (w *writer) header(assigned map[string][]string) {
	w.b.WriteString("// mcp-gateway policy set, compiled from structured roles (decision 490o45d0).\n")
	w.b.WriteString("// Generated: do not edit. Actions: call (may run), confirm (needs approval), list (visible).\n")
	users := make([]string, 0, len(assigned))
	for u := range assigned {
		users = append(users, u)
	}
	sort.Strings(users)
	if len(users) == 0 {
		w.b.WriteString("// assignments: none\n")
	}
	for _, u := range users {
		fmt.Fprintf(&w.b, "// assignment: %s = %s\n", u, strings.Join(assigned[u], ", "))
	}
	w.b.WriteString("\n")
}

// tokenPolicies narrow every principal by the token in the context: a
// read-only token never sees or calls a write tool; a token with an
// allow-list only sees and calls the apps and tools on it.
func (w *writer) tokenPolicies() {
	w.policy("token/read_only", "forbid", "principal", actions(ActionCall, ActionList), "resource",
		[]string{`context.token.read_only && resource.kind == "write"`}, nil)
	w.policy("token/allow_list", "forbid", "principal", actions(ActionCall, ActionList), "resource",
		[]string{`context.token.restricted && !(context.token.apps.contains(resource.app) || context.token.tools.contains(resource.name))`}, nil)
}

// role emits the rules of one role. Most specific wins: a wildcard rule
// steps aside for every tool of the app that has its own allow, confirm
// or hidden rule, exactly where that rule applies (under its conditions),
// so the wildcard stays the default elsewhere. Deny rules need no
// exclusion: a forbid wins over any permit. Hidden emits nothing but
// still excludes the tool from the wildcard.
func (w *writer) role(r Role) {
	principal := fmt.Sprintf(`principal in %s::%s`, EntityRole, strconv.Quote(r.Name))
	for _, rule := range r.Rules {
		var excl exclusions
		if rule.IsWildcard() {
			excl = exclusionsFor(rule.App, r.Rules)
		}
		w.rule("role/"+r.Name, principal, rule, excl, true)
	}
	apps := make([]string, 0, len(r.PersonalAccounts))
	for app := range r.PersonalAccounts {
		apps = append(apps, app)
	}
	sort.Strings(apps)
	for _, app := range apps {
		resource := fmt.Sprintf(`resource in %s::%s`, EntityApp, strconv.Quote(app))
		switch r.PersonalAccounts[app] {
		case AllowanceDeny:
			w.policy("role/"+r.Name+"/"+app+"/personal/deny", "forbid", principal, actions(ActionCall, ActionConfirm), resource,
				[]string{`context.account.label == "personal"`}, nil)
		case AllowanceConfirmWrites:
			w.policy("role/"+r.Name+"/"+app+"/personal/confirm_writes", "permit", principal, actions(ActionConfirm), resource,
				[]string{`context.account.label == "personal" && resource.kind == "write"`}, nil)
		}
	}
}

// exclusions is what a wildcard rule leaves to the specific rules of its
// app: call lists one term per specific rule (its tool, under its
// conditions); list names the tools (visibility knows no arguments).
type exclusions struct {
	call []string
	list []string
}

func exclusionsFor(app string, rules []ToolRule) exclusions {
	var ex exclusions
	for _, s := range rules {
		if s.App != app || s.IsWildcard() || s.Outcome == OutcomeDeny {
			continue
		}
		name := strconv.Quote(s.App + "." + s.Tool)
		term := "resource.name == " + name
		if when := conditions(s.Conditions); len(when) > 0 {
			term = "(" + term + " && " + strings.Join(when, " && ") + ")"
		}
		if !slices.Contains(ex.call, term) {
			ex.call = append(ex.call, term)
		}
		if !slices.Contains(ex.list, name) {
			ex.list = append(ex.list, name)
		}
	}
	slices.Sort(ex.call)
	slices.Sort(ex.list)
	return ex
}

func (ex exclusions) listClause() []string {
	if len(ex.list) == 0 {
		return nil
	}
	return []string{"[" + strings.Join(ex.list, ", ") + "].contains(resource.name)"}
}

// restriction emits one user's narrowing: forbids and confirm permits
// only. Allow rules are skipped and reported.
func (w *writer) restriction(u UserRestriction) []string {
	principal := fmt.Sprintf(`principal == %s::%s`, EntityUser, strconv.Quote(u.UserID))
	var warnings []string
	for _, rule := range u.Rules {
		if rule.Outcome == OutcomeAllow {
			warnings = append(warnings, fmt.Sprintf("restriction for user %s: allow rule for %s.%s ignored, restrictions can only tighten", u.UserID, rule.App, rule.Tool))
			continue
		}
		if rule.Outcome == OutcomeHidden {
			rule.Outcome = OutcomeDeny
		}
		w.rule("restriction/"+u.UserID, principal, rule, exclusions{}, false)
	}
	return warnings
}

// rule emits the policies for one rule under principal. Conditions and
// call exclusions apply to call (and confirm) only; the list action gets
// the name-only exclusions: a tool is visible whenever any rule grants
// it, whatever the arguments turn out to be. A conditional deny never
// touches visibility.
func (w *writer) rule(prefix, principal string, rule ToolRule, excl exclusions, grants bool) {
	name := rule.App + "." + rule.Tool
	id := prefix + "/" + name + "/" + string(rule.Outcome)
	var resource string
	if rule.IsWildcard() {
		resource = fmt.Sprintf(`resource in %s::%s`, EntityApp, strconv.Quote(rule.App))
	} else {
		resource = fmt.Sprintf(`resource == %s::%s`, EntityTool, strconv.Quote(name))
	}
	when := conditions(rule.Conditions)
	var effect string
	var callActions []string
	switch rule.Outcome {
	case OutcomeHidden:
		// Absent from the permits, so absent from tools/list and a call
		// answers like an unknown tool.
		return
	case OutcomeDeny:
		effect, callActions = "forbid", []string{ActionCall, ActionConfirm}
	case OutcomeAllow:
		if !grants {
			return
		}
		effect, callActions = "permit", []string{ActionCall}
	case OutcomeConfirm:
		effect = "permit"
		if !grants {
			// A restriction can add a confirmation but never the call itself.
			w.policy(id, effect, principal, actions(ActionConfirm), resource, when, nil)
			return
		}
		callActions = []string{ActionCall, ActionConfirm}
	}
	if len(when) == 0 && len(excl.call) == 0 {
		w.policy(id, effect, principal, actions(append(callActions, ActionList)...), resource, nil, nil)
		return
	}
	w.policy(id, effect, principal, actions(callActions...), resource, when, excl.call)
	if rule.Outcome == OutcomeDeny && len(when) > 0 {
		return
	}
	w.policy(id+"/list", effect, principal, actions(ActionList), resource, nil, excl.listClause())
}

// policy writes one statement in cedar-go's own layout.
func (w *writer) policy(id, effect, principal, action, resource string, when, unless []string) {
	fmt.Fprintf(&w.b, "@id(%s)\n%s (\n    %s,\n    %s,\n    %s\n)", strconv.Quote(id), effect, principal, action, resource)
	if len(when) > 0 {
		fmt.Fprintf(&w.b, "\nwhen { %s }", strings.Join(when, " && "))
	}
	if len(unless) > 0 {
		fmt.Fprintf(&w.b, "\nunless { %s }", strings.Join(unless, " || "))
	}
	w.b.WriteString(";\n\n")
}

// actions renders the action constraint for one or more actions.
func actions(names ...string) string {
	if len(names) == 1 {
		return fmt.Sprintf(`action == Action::%s`, strconv.Quote(names[0]))
	}
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = "Action::" + strconv.Quote(n)
	}
	return "action in [" + strings.Join(parts, ", ") + "]"
}

// conditions renders each condition as a guard on context.resource. A
// missing key never matches.
func conditions(cs []Condition) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		key := strconv.Quote(c.Key)
		access := fmt.Sprintf("context.resource[%s]", key)
		var test string
		switch c.Op {
		case OpEquals:
			test = fmt.Sprintf("%s == %s", access, strconv.Quote(c.Value))
		case OpPrefix:
			test = fmt.Sprintf("%s like %s", access, strconv.Quote(escapeLike(c.Value)+"*"))
		case OpGlob:
			// A glob is written in Cedar's own pattern language: "*" is the
			// wildcard, everything else literal.
			test = fmt.Sprintf("%s like %s", access, strconv.Quote(c.Value))
		}
		out = append(out, fmt.Sprintf("(context.resource has %s && %s)", key, test))
	}
	return out
}

// escapeLike makes s literal inside a Cedar like pattern ("*" is the only
// metacharacter; "\*" matches a literal star).
func escapeLike(s string) string { return strings.ReplaceAll(s, "*", `\*`) }
