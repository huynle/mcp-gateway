package atlassian

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// The Jira writes added to close the gap with Atlassian's Rovo MCP
// server and sooperset/mcp-atlassian: edit an issue's fields, assign,
// edit a comment, log work, link issues, watch / unwatch, and move
// issues into a sprint. Deletions (Rovo's opt-in delete_jira group) are
// left out on purpose.

// More Jira write tool names.
const (
	ToolUpdateIssue       = "update_issue"
	ToolAssignIssue       = "assign_issue"
	ToolEditComment       = "edit_comment"
	ToolAddWorklog        = "add_worklog"
	ToolLinkIssues        = "link_issues"
	ToolAddWatcher        = "add_watcher"
	ToolRemoveWatcher     = "remove_watcher"
	ToolAddIssuesToSprint = "add_issues_to_sprint"
)

// ScopeSprintWrite is the granular Jira Software scope moving issues into
// a sprint needs (the agile API takes no classic scope).
const ScopeSprintWrite = "write:sprint:jira-software"

// maxSprintIssues is Jira Software's limit of issues per move request.
const maxSprintIssues = 50

// unassigned is the assignee identity of an unassign.
const unassigned = "unassigned"

var (
	accountIDRE = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)
	commentIDRE = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// jiraTimeLayout is the timestamp format Jira's REST API takes.
const jiraTimeLayout = "2006-01-02T15:04:05.000-0700"

func (c *Connector) jiraMoreWriteTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	work := []string{ScopeJiraWrite}
	tool := func(name, desc string, props []property, required, scopes []string, identity func(map[string]any) map[string]string,
		rec connectors.Reconciliation, ids func(connectors.Result) map[string]string) connectors.Tool {
		return connectors.Tool{App: JiraApp, Name: name, Kind: connectors.KindWrite, Description: desc, InputSchema: objectSchema(props, required),
			RequiredScopes: scopes, ResourceIdentity: identity, Reconcile: rec, ResultIDs: ids, Bounds: single}
	}
	accountProp := property{"account_id", "string", "Atlassian account id (from search_users, list_assignable_users or get_current_user).", nil}
	return []connectors.Tool{
		tool(ToolUpdateIssue, "Edit fields of a Jira issue (by key): summary, plain-text description (replaces it), labels (replace them), "+
			"priority, and further fields by id (see get_create_fields; only fields on the issue's edit screen can be set). Use assign_issue "+
			"to assign and transition_issue to change the status. The edit cannot be verified afterwards: if the outcome is unknown, check the issue.",
			[]property{keyProp, {"summary", "string", "New summary.", nil}, {"description", "string", "New description as plain text (one paragraph per line).", nil},
				{"labels", "array", "New labels (replace the current ones).", nil}, {"priority", "string", "Priority name, like High.", nil},
				{"fields", "object", `Further fields by field id, as Jira's REST v3 values, for example {"customfield_10010": [{"value": "Platform"}]}.`, nil}},
			[]string{"key"}, work, jiraIdentity, connectors.Reconciliation{Kind: connectors.ReconcileNone}, issueRefIDs),
		tool(ToolAssignIssue, "Assign a Jira issue (by key) to a user by account id, or unassign it when account_id is omitted.",
			[]property{keyProp, {"account_id", "string", "Account id of the new assignee; omit to unassign.", nil}},
			[]string{"key"}, work, assignIdentity, connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkAssignee}, assignResultIDs),
		tool(ToolEditComment, "Replace the text of one of your comments on a Jira issue (by key and comment id from get_issue_comments) with plain text.",
			[]property{keyProp, {"comment_id", "string", "The comment id (digits).", nil}, {"body", "string", "New comment text (one paragraph per line).", nil}},
			[]string{"key", "comment_id", "body"}, work, commentIdentity, connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkEditedComment}, commentResultIDs),
		tool(ToolAddWorklog, "Log time on a Jira issue (by key): time spent in Jira notation (\"1h 30m\", \"2d\"), optional start (RFC 3339, default now) and comment.",
			[]property{keyProp, {"time_spent", "string", "Time spent, like 1h 30m.", nil}, {"started", "string", "When the work started, RFC 3339 (default now).", nil},
				{"comment", "string", "Optional plain-text comment.", nil}},
			[]string{"key", "time_spent"}, work, jiraIdentity, connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkWorklog}, worklogResultIDs),
		tool(ToolLinkIssues, "Link two Jira issues with a link type (name from list_link_types, like Blocks or Relates). Jira reads the link as "+
			"inward_key <inward phrase> outward_key as configured on the link type.",
			[]property{{"link_type", "string", "Link type name, like Blocks.", nil}, {"inward_key", "string", "Inward issue key, like ABC-1.", nil},
				{"outward_key", "string", "Outward issue key, like ABC-2.", nil}},
			[]string{"link_type", "inward_key", "outward_key"}, work, linkIdentity, connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkLink}, linkResultIDs),
		tool(ToolAddWatcher, "Add a watcher (by account id; use get_current_user for yourself) to a Jira issue (by key).",
			[]property{keyProp, accountProp}, []string{"key", "account_id"}, work, watcherIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkWatcher(true)}, watcherResultIDs),
		tool(ToolRemoveWatcher, "Remove a watcher (by account id) from a Jira issue (by key).",
			[]property{keyProp, accountProp}, []string{"key", "account_id"}, work, watcherIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkWatcher(false)}, watcherResultIDs),
		tool(ToolAddIssuesToSprint, "Move up to 50 Jira issues (by key) into a sprint (id from list_sprints).",
			[]property{{"sprint_id", "integer", "Sprint id from list_sprints.", nil}, {"keys", "array", "Issue keys, like ABC-1 (1-50).", nil}},
			[]string{"sprint_id", "keys"}, []string{ScopeSprintWrite}, sprintMoveIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSprintMove}, sprintMoveResultIDs),
	}
}

func (c *Connector) jiraMoreWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolUpdateIssue: c.updateIssue, ToolAssignIssue: c.assignIssue, ToolEditComment: c.editComment, ToolAddWorklog: c.addWorklog,
		ToolLinkIssues: c.linkIssues, ToolAddWatcher: c.watch(true), ToolRemoveWatcher: c.watch(false), ToolAddIssuesToSprint: c.addIssuesToSprint,
	}
}

// --- identities -----------------------------------------------------------------------

// accountIDArg normalises an account id argument.
func accountIDArg(v any) (string, bool) {
	s, _ := v.(string)
	s = strings.TrimSpace(s)
	return s, accountIDRE.MatchString(s)
}

func assignIdentity(args map[string]any) map[string]string {
	out := jiraIdentity(args)
	if out["issue"] == "" {
		return out
	}
	out["assignee"] = unassigned
	if id, ok := accountIDArg(args["account_id"]); ok {
		out["assignee"] = id
	}
	return out
}

func commentIdentity(args map[string]any) map[string]string {
	out := jiraIdentity(args)
	if id, _ := args["comment_id"].(string); commentIDRE.MatchString(strings.TrimSpace(id)) {
		out["comment"] = strings.TrimSpace(id)
	}
	return out
}

func linkIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if in, ok := issueKeyArg(args["inward_key"]); ok {
		out["issue"], out["project"] = in, in[:strings.IndexByte(in, '-')]
	}
	if o, ok := issueKeyArg(args["outward_key"]); ok {
		out["linked_issue"] = o
	}
	if t, _ := args["link_type"].(string); strings.TrimSpace(t) != "" && len(t) <= 100 {
		out["link_type"] = strings.TrimSpace(t)
	}
	return out
}

func watcherIdentity(args map[string]any) map[string]string {
	out := jiraIdentity(args)
	if id, ok := accountIDArg(args["account_id"]); ok {
		out["watcher"] = id
	}
	return out
}

func sprintMoveIdentity(args map[string]any) map[string]string {
	out := jiraIdentity(args)
	if keys, err := issueKeysArg(args); err == nil {
		out["issues"] = strings.Join(keys, ",")
	}
	return out
}

// issueKeysArg reads the "keys" argument: 1..maxSprintIssues issue keys.
func issueKeysArg(args map[string]any) ([]string, error) {
	list, err := stringList(args, "keys")
	if err != nil {
		return nil, err
	}
	if len(list) == 0 || len(list) > maxSprintIssues {
		return nil, invalid("keys must list 1 to %d issue keys", maxSprintIssues)
	}
	out := make([]string, 0, len(list))
	for _, k := range list {
		key, ok := issueKeyArg(k)
		if !ok {
			return nil, invalid("keys: %q is not an issue key like ABC-123", k)
		}
		out = append(out, key)
	}
	return out, nil
}

// --- result ids -----------------------------------------------------------------------

func contentMap(res connectors.Result) map[string]string {
	m, ok := res.Content.(map[string]string)
	if !ok || len(m) == 0 {
		return nil
	}
	return m
}

func issueRefIDs(res connectors.Result) map[string]string {
	if v, ok := res.Content.(UpdatedIssue); ok && v.Issue != "" {
		return map[string]string{"issue": v.Issue, "url": v.URL}
	}
	return nil
}

func assignResultIDs(res connectors.Result) map[string]string     { return contentMap(res) }
func worklogResultIDs(res connectors.Result) map[string]string    { return contentMap(res) }
func linkResultIDs(res connectors.Result) map[string]string       { return contentMap(res) }
func watcherResultIDs(res connectors.Result) map[string]string    { return contentMap(res) }
func sprintMoveResultIDs(res connectors.Result) map[string]string { return contentMap(res) }

// UpdatedIssue is update_issue's result: the issue and the field ids sent.
type UpdatedIssue struct {
	Issue   string   `json:"issue"`
	Updated []string `json:"updated"`
	URL     string   `json:"url,omitempty"`
}

// --- shared field helpers -----------------------------------------------------------------

// extraFields copies the optional "fields" object argument.
func extraFields(args map[string]any) (map[string]any, error) {
	out := map[string]any{}
	v, ok := args["fields"]
	if !ok || v == nil {
		return out, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, invalid("fields must be an object of field id to value")
	}
	for k, val := range m {
		if strings.TrimSpace(k) == "" {
			return nil, invalid("fields: empty field id")
		}
		out[k] = val
	}
	return out, nil
}

// setNamedFields sets parent, priority and assignee from their named
// arguments (create_issue).
func setNamedFields(fields map[string]any, args map[string]any) error {
	if v, ok := args["parent_key"]; ok && v != nil {
		key, ok := issueKeyArg(v)
		if !ok {
			return invalid("parent_key must be an issue key like ABC-123")
		}
		fields["parent"] = map[string]string{"key": key}
	}
	if err := setPriority(fields, args); err != nil {
		return err
	}
	if v, ok := args["assignee_account_id"]; ok && v != nil {
		id, ok := accountIDArg(v)
		if !ok {
			return invalid("assignee_account_id must be an Atlassian account id")
		}
		fields["assignee"] = map[string]string{"accountId": id}
	}
	return nil
}

func setPriority(fields map[string]any, args map[string]any) error {
	p, err := optionalString(args, "priority")
	if err != nil {
		return err
	}
	if p = strings.TrimSpace(p); p != "" {
		fields["priority"] = map[string]string{"name": p}
	}
	return nil
}

// --- handlers -------------------------------------------------------------------------------

func (c *Connector) updateIssue(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	fields, err := extraFields(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if v, ok := call.Args["summary"]; ok && v != nil {
		summary, err := requiredString(call.Args, "summary")
		if err != nil {
			return connectors.Result{}, err
		}
		fields["summary"] = summary
	}
	if v, ok := call.Args["description"]; ok && v != nil {
		d, err := optionalString(call.Args, "description")
		if err != nil {
			return connectors.Result{}, err
		}
		fields["description"] = adfDocument(d)
	}
	if v, ok := call.Args["labels"]; ok && v != nil {
		labels, err := stringList(call.Args, "labels")
		if err != nil {
			return connectors.Result{}, err
		}
		if labels == nil {
			labels = []string{}
		}
		fields["labels"] = labels
	}
	if err := setPriority(fields, call.Args); err != nil {
		return connectors.Result{}, err
	}
	if len(fields) == 0 {
		return connectors.Result{}, invalid("nothing to update: give summary, description, labels, priority or fields")
	}
	if err := c.classifyWrite("update issue", s.putJSON(ctx, s.jiraURL("issue/"+key, nil), map[string]any{"fields": fields}, nil)); err != nil {
		return connectors.Result{}, err
	}
	out := UpdatedIssue{Issue: key, URL: browseURL(s.site, key)}
	for k := range fields {
		out.Updated = append(out.Updated, k)
	}
	slices.Sort(out.Updated)
	return connectors.Result{Content: out}, nil
}

func (c *Connector) assignIssue(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var id any
	assignee := unassigned
	if v, ok := call.Args["account_id"]; ok && v != nil && strings.TrimSpace(fmt.Sprint(v)) != "" {
		a, ok := accountIDArg(v)
		if !ok {
			return connectors.Result{}, invalid("account_id must be an Atlassian account id")
		}
		id, assignee = a, a
	}
	if err := c.classifyWrite("assign issue", s.putJSON(ctx, s.jiraURL("issue/"+key+"/assignee", nil), map[string]any{"accountId": id}, nil)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: map[string]string{"issue": key, "assignee": assignee}}, nil
}

func (c *Connector) editComment(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, _ := call.Args["comment_id"].(string)
	if id = strings.TrimSpace(id); !commentIDRE.MatchString(id) {
		return connectors.Result{}, invalid("comment_id is required: the comment id (digits)")
	}
	body, err := requiredString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	var edited struct {
		ID string `json:"id"`
	}
	req := map[string]any{"body": adfDocument(body, Marker(call.OperationID))}
	if err := c.classifyWrite("edit comment", s.putJSON(ctx, s.jiraURL("issue/"+key+"/comment/"+id, nil), req, &edited)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedComment{ID: id, Issue: key, URL: commentURL(s.site, key, id)}}, nil
}

func (c *Connector) addWorklog(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	spent, err := requiredString(call.Args, "time_spent")
	if err != nil {
		return connectors.Result{}, err
	}
	req := map[string]any{"timeSpent": spent}
	started, err := optionalString(call.Args, "started")
	if err != nil {
		return connectors.Result{}, err
	}
	if started = strings.TrimSpace(started); started != "" {
		t, err := time.Parse(time.RFC3339, started)
		if err != nil {
			return connectors.Result{}, invalid("started must be an RFC 3339 timestamp like 2026-10-01T09:00:00Z")
		}
		req["started"] = t.Format(jiraTimeLayout)
	}
	comment, err := optionalString(call.Args, "comment")
	if err != nil {
		return connectors.Result{}, err
	}
	req["comment"] = adfDocument(comment, Marker(call.OperationID))
	var created struct {
		ID string `json:"id"`
	}
	if err := c.classifyWrite("add worklog", s.postJSON(ctx, s.jiraURL("issue/"+key+"/worklog", nil), req, &created)); err != nil {
		return connectors.Result{}, err
	}
	if created.ID == "" {
		return connectors.Result{}, fmt.Errorf("%w: add worklog: Atlassian answered without a worklog id", connectors.ErrOutcomeUnknown)
	}
	return connectors.Result{Content: map[string]string{"id": created.ID, "issue": key}}, nil
}

func (c *Connector) linkIssues(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	typ, err := requiredString(call.Args, "link_type")
	if err != nil {
		return connectors.Result{}, err
	}
	in, ok := issueKeyArg(call.Args["inward_key"])
	if !ok {
		return connectors.Result{}, invalid("inward_key is required: an issue key like ABC-123")
	}
	out, ok := issueKeyArg(call.Args["outward_key"])
	if !ok {
		return connectors.Result{}, invalid("outward_key is required: an issue key like ABC-123")
	}
	if in == out {
		return connectors.Result{}, invalid("an issue cannot be linked to itself")
	}
	req := map[string]any{"type": map[string]string{"name": typ}, "inwardIssue": map[string]string{"key": in}, "outwardIssue": map[string]string{"key": out}}
	if err := c.classifyWrite("link issues", s.postJSON(ctx, s.jiraURL("issueLink", nil), req, nil)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: map[string]string{"link_type": typ, "inward_key": in, "outward_key": out}}, nil
}

func (c *Connector) watch(add bool) handler {
	return func(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
		key, err := keyArg(call.Args)
		if err != nil {
			return connectors.Result{}, err
		}
		id, ok := accountIDArg(call.Args["account_id"])
		if !ok {
			return connectors.Result{}, invalid("account_id is required: an Atlassian account id")
		}
		if add {
			err = c.classifyWrite("add watcher", s.postJSON(ctx, s.jiraURL("issue/"+key+"/watchers", nil), id, nil))
		} else {
			err = c.classifyWrite("remove watcher", s.deleteJSON(ctx, s.jiraURL("issue/"+key+"/watchers", url.Values{"accountId": {id}}), nil))
		}
		if err != nil {
			return connectors.Result{}, err
		}
		return connectors.Result{Content: map[string]string{"issue": key, "watcher": id}}, nil
	}
}

func (c *Connector) addIssuesToSprint(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	sprint, err := idArg(call.Args, "sprint_id")
	if err != nil {
		return connectors.Result{}, err
	}
	keys, err := issueKeysArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := c.classifyWrite("move issues to sprint", s.postJSON(ctx, s.agileURL("sprint/"+sprint+"/issue", nil), map[string]any{"issues": keys}, nil)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: map[string]string{"sprint_id": sprint, "issues": strings.Join(keys, ",")}}, nil
}

// --- reconciliation -------------------------------------------------------------------------

// identityIssue reads the issue key of a reconcile input's identity.
func identityIssue(in connectors.ReconcileInput) (string, error) {
	key, ok := issueKeyArg(in.ResourceIdentity["issue"])
	if !ok {
		return "", fmt.Errorf("%w: resource identity has no issue key", ErrNotReconcilable)
	}
	return key, nil
}

// checkAssignee: the issue's assignee is the identity's (found, the
// issue key) or someone else (not_found).
func (c *Connector) checkAssignee(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	key, err := identityIssue(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	want := in.ResourceIdentity["assignee"]
	if want == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no assignee", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	var is wireIssue
	if err := c.classify("reconcile: get assignee", tg.getJSON(ctx, tg.jiraURL("issue/"+key, url.Values{"fields": {"assignee"}}), &is)); err != nil {
		return connectors.ReconcileResult{}, err
	}
	got := unassigned
	if a := is.Fields.Assignee; a != nil && a.AccountID != "" {
		got = a.AccountID
	}
	if got == want {
		return found(key), nil
	}
	return notFound, nil
}

// checkEditedComment: the comment carries the operation's marker.
func (c *Connector) checkEditedComment(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	key, err := identityIssue(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	id := in.ResourceIdentity["comment"]
	if !commentIDRE.MatchString(id) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no comment id", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	var cm wireComment
	if err := c.classify("reconcile: get comment", tg.getJSON(ctx, tg.jiraURL("issue/"+key+"/comment/"+id, nil), &cm)); err != nil {
		return connectors.ReconcileResult{}, err
	}
	if hasMarker(adfText(cm.Body), tg.operationID) {
		return found(id), nil
	}
	return notFound, nil
}

// checkWorklog walks the issue's worklogs (bounded by
// MaxReconcilePages) for the marker in a comment.
func (c *Connector) checkWorklog(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	key, err := identityIssue(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	startAt := 0
	for page := 1; page <= MaxReconcilePages; page++ {
		var res struct {
			Total    int `json:"total"`
			Worklogs []struct {
				ID      string          `json:"id"`
				Comment json.RawMessage `json:"comment"`
			} `json:"worklogs"`
		}
		if err := c.classify("reconcile: list worklogs", tg.getJSON(ctx, tg.jiraURL("issue/"+key+"/worklog", offsetQuery(reconcilePageSize, startAt)), &res)); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, w := range res.Worklogs {
			if w.ID != "" && hasMarker(adfText(w.Comment), tg.operationID) {
				return found(w.ID), nil
			}
		}
		startAt += len(res.Worklogs)
		if len(res.Worklogs) == 0 || startAt >= res.Total {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("atlassian: reconcile: more than %d pages of worklogs on %s; cannot tell yet", MaxReconcilePages, key)
}

// checkLink: the inward issue has a link of the type to the outward
// issue (found: the link id).
func (c *Connector) checkLink(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	key, err := identityIssue(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	other, ok := issueKeyArg(in.ResourceIdentity["linked_issue"])
	typ := in.ResourceIdentity["link_type"]
	if !ok || typ == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no linked issue or link type", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	var is struct {
		Fields struct {
			IssueLinks []struct {
				ID   string `json:"id"`
				Type struct {
					Name string `json:"name"`
				} `json:"type"`
				InwardIssue  *struct{ Key string } `json:"inwardIssue"`
				OutwardIssue *struct{ Key string } `json:"outwardIssue"`
			} `json:"issuelinks"`
		} `json:"fields"`
	}
	if err := c.classify("reconcile: list links", tg.getJSON(ctx, tg.jiraURL("issue/"+key, url.Values{"fields": {"issuelinks"}}), &is)); err != nil {
		return connectors.ReconcileResult{}, err
	}
	for _, l := range is.Fields.IssueLinks {
		if !strings.EqualFold(l.Type.Name, typ) {
			continue
		}
		if (l.OutwardIssue != nil && l.OutwardIssue.Key == other) || (l.InwardIssue != nil && l.InwardIssue.Key == other) {
			return found(l.ID), nil
		}
	}
	return notFound, nil
}

// checkWatcher: the watcher is (add) or is not (remove) among the issue's
// watchers.
func (c *Connector) checkWatcher(add bool) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		key, err := identityIssue(in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		who := in.ResourceIdentity["watcher"]
		if who == "" {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no watcher", ErrNotReconcilable)
		}
		tg, err := c.target(ctx, in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		var res struct {
			Watchers []wireUser `json:"watchers"`
		}
		if err := c.classify("reconcile: get watchers", tg.getJSON(ctx, tg.jiraURL("issue/"+key+"/watchers", nil), &res)); err != nil {
			return connectors.ReconcileResult{}, err
		}
		watching := slices.ContainsFunc(res.Watchers, func(u wireUser) bool { return u.AccountID == who })
		if watching == add {
			return found(key), nil
		}
		return notFound, nil
	}
}

// checkSprintMove: every issue of the identity is in the sprint (found:
// the sprint id).
func (c *Connector) checkSprintMove(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	sprint, ok := positiveID(in.ResourceIdentity["sprint"])
	keys := strings.Split(in.ResourceIdentity["issues"], ",")
	if !ok || in.ResourceIdentity["issues"] == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no sprint or issues", ErrNotReconcilable)
	}
	for _, k := range keys {
		if !issueKeyRE.MatchString(k) {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has a bad issue key", ErrNotReconcilable)
		}
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	q := url.Values{"jql": {"key in (" + strings.Join(keys, ",") + ")"}, "fields": {"summary"}, "maxResults": {strconv.Itoa(maxSprintIssues)}}
	var res struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := c.classify("reconcile: sprint issues", tg.getJSON(ctx, tg.agileURL("sprint/"+sprint+"/issue", q), &res)); err != nil {
		return connectors.ReconcileResult{}, err
	}
	inSprint := map[string]bool{}
	for _, is := range res.Issues {
		inSprint[is.Key] = true
	}
	for _, k := range keys {
		if !inSprint[k] {
			return notFound, nil
		}
	}
	return found(sprint), nil
}
