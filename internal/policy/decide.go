package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Input is one authorization question: may this user, through this token,
// run this tool against an account with this label and these resource
// identity values? Roles are the user's role names (the Service fills
// them from the compiled assignments). ResourceIdentity is what the
// connector's hook extracted from the arguments; it is never the
// arguments themselves.
type Input struct {
	UserID           string
	Roles            []string
	TokenID          string
	TokenScope       tokens.Scope
	Tool             connectors.Tool
	AccountLabel     string
	ResourceIdentity map[string]string
}

// Decision is the answer: the outcome, the policy version that produced
// it (Version is the hash; VersionID the policy_versions row, which is
// what audit, approval and ledger rows reference, and empty when the
// policy was never persisted) and a short reason naming the deciding
// policy (for logs and audit, never for the harness).
type Decision struct {
	Outcome   Outcome
	Version   string
	VersionID string
	Reason    string
}

// Decide evaluates in against the compiled set in the order decision
// 490o45d0 fixes: a tool that is not visible is hidden; a forbid on call
// wins; call must be permitted, else deny; a permitted confirm turns the
// allow into confirm.
func (c *Compiled) Decide(in Input) Decision {
	ents, req := c.request(in)
	d := Decision{Version: c.Version, VersionID: c.ID}
	if ok, diag := c.authorize(ents, req, ActionList); !ok {
		d.Outcome, d.Reason = OutcomeHidden, c.reason("not visible: forbidden by", diag, "not visible: no rule lists it")
		return d
	}
	ok, diag := c.authorize(ents, req, ActionCall)
	if !ok {
		d.Outcome, d.Reason = OutcomeDeny, c.reason("forbidden by", diag, "denied: no rule permits the call")
		return d
	}
	callReason := c.reason("permitted by", diag, "")
	if ok, diag := c.authorize(ents, req, ActionConfirm); ok {
		d.Outcome, d.Reason = OutcomeConfirm, c.reason("confirm required by", diag, "")
		return d
	}
	d.Outcome, d.Reason = OutcomeAllow, callReason
	return d
}

// Visible reports whether the tool appears in tools/list for the user and
// token: the list action must be permitted and not forbidden. AccountLabel
// and ResourceIdentity are ignored (visibility is decided before any
// account or argument is known).
func (c *Compiled) Visible(in Input) bool {
	in.AccountLabel, in.ResourceIdentity = "", nil
	ents, req := c.request(in)
	ok, _ := c.authorize(ents, req, ActionList)
	return ok
}

func (c *Compiled) authorize(ents cedar.EntityMap, req cedar.Request, action string) (bool, cedar.Diagnostic) {
	req.Action = cedar.NewEntityUID("Action", cedar.String(action))
	d, diag := cedar.Authorize(c.set, ents, req)
	return bool(d), diag
}

// reason names the policies in the diagnostic by their @id annotation,
// or returns fallback when none applied.
func (c *Compiled) reason(prefix string, diag cedar.Diagnostic, fallback string) string {
	if len(diag.Reasons) == 0 {
		if fallback == "" {
			return prefix
		}
		return fallback
	}
	names := make([]string, 0, len(diag.Reasons))
	for _, r := range diag.Reasons {
		if label, ok := c.ids[r.PolicyID]; ok {
			names = append(names, label)
		} else {
			names = append(names, string(r.PolicyID))
		}
	}
	sort.Strings(names)
	return prefix + " " + strings.Join(names, ", ")
}

// request builds the entities and the request skeleton (the action is set
// per evaluation).
func (c *Compiled) request(in Input) (cedar.EntityMap, cedar.Request) {
	empty := cedar.NewRecord(nil)
	ents := cedar.EntityMap{}
	add := func(e cedar.Entity) {
		e.Tags = empty
		ents[e.UID] = e
	}

	roles := make([]cedar.EntityUID, 0, len(in.Roles))
	for _, r := range in.Roles {
		uid := cedar.NewEntityUID(EntityRole, cedar.String(r))
		roles = append(roles, uid)
		add(cedar.Entity{UID: uid, Attributes: empty})
	}
	user := cedar.NewEntityUID(EntityUser, cedar.String(in.UserID))
	add(cedar.Entity{UID: user, Parents: cedar.NewEntityUIDSet(roles...), Attributes: empty})

	app := cedar.NewEntityUID(EntityApp, cedar.String(in.Tool.App))
	add(cedar.Entity{UID: app, Attributes: empty})
	toolUID := cedar.NewEntityUID(EntityTool, cedar.String(in.Tool.FullName()))
	add(cedar.Entity{UID: toolUID, Parents: cedar.NewEntityUIDSet(app), Attributes: cedar.NewRecord(cedar.RecordMap{
		"app":  types.String(in.Tool.App),
		"name": types.String(in.Tool.FullName()),
		"kind": types.String(string(in.Tool.Kind)),
	})})

	tokenID := in.TokenID
	if tokenID == "" {
		tokenID = "-"
	}
	token := cedar.NewEntityUID(EntityToken, cedar.String(tokenID))
	add(cedar.Entity{UID: token, Attributes: cedar.NewRecord(cedar.RecordMap{
		"read_only":  types.Boolean(in.TokenScope.ReadOnly),
		"restricted": types.Boolean(in.TokenScope.IsRestricted()),
		"apps":       stringSet(in.TokenScope.Apps),
		"tools":      stringSet(in.TokenScope.Tools),
	})})

	resource := make(cedar.RecordMap, len(in.ResourceIdentity))
	for k, v := range in.ResourceIdentity {
		resource[cedar.String(k)] = types.String(v)
	}
	req := cedar.Request{
		Principal: user,
		Resource:  toolUID,
		Context: cedar.NewRecord(cedar.RecordMap{
			"token":    token,
			"account":  cedar.NewRecord(cedar.RecordMap{"label": types.String(in.AccountLabel)}),
			"resource": cedar.NewRecord(resource),
		}),
	}
	return ents, req
}

func stringSet(items []string) cedar.Set {
	vals := make([]types.Value, len(items))
	for i, s := range items {
		vals[i] = types.String(s)
	}
	return cedar.NewSet(vals...)
}

// String renders the decision for logs.
func (d Decision) String() string {
	return fmt.Sprintf("%s (%s; policy %s)", d.Outcome, d.Reason, d.Version)
}
