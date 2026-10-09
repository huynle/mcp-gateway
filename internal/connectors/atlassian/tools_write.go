package atlassian

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Write tool names.
const (
	ToolCreateIssue     = "create_issue"
	ToolAddComment      = "add_comment"
	ToolTransitionIssue = "transition_issue"
)

// ErrMissingOperation is returned by every write called without
// Call.OperationID: the ledger stage sets it before dispatch, and the
// marker reconciliation derives from it, so a write without one could
// never be verified after an unknown outcome. It means a pipeline wiring
// bug (a write dispatched without the ledger), never a harness mistake.
var ErrMissingOperation = errors.New("atlassian: write called without a ledger operation id")

// transitionIDRE is the shape of a Jira transition id.
var transitionIDRE = regexp.MustCompile(`^[0-9]+$`)

// writeTools declares the app's write tools.
func (c *Connector) writeTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	if c.app == ConfluenceApp {
		return nil // confluence.create_page follows in the next increment
	}
	return []connectors.Tool{
		{
			App: JiraApp, Name: ToolCreateIssue, Kind: connectors.KindWrite,
			Description: "Create a Jira issue in a project (by project key) with an issue type (Task, Bug, Story, ...), a summary and an " +
				"optional plain-text description and labels. Returns the new issue's key, id and url.",
			InputSchema: objectSchema([]property{
				{"project_key", "string", "Key of the project to create the issue in, like ABC.", nil},
				{"issue_type", "string", "Issue type name, like Task or Bug.", nil},
				{"summary", "string", "Issue summary (title).", nil},
				{"description", "string", "Issue description as plain text (one paragraph per line).", nil},
				{"labels", "array", "Labels to apply.", nil},
			}, []string{"project_key", "issue_type", "summary"}),
			RequiredScopes:   []string{ScopeJiraWrite},
			ResourceIdentity: jiraIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkIssue},
			ResultIDs:        issueResultIDs,
			Bounds:           single,
		},
		{
			App: JiraApp, Name: ToolAddComment, Kind: connectors.KindWrite,
			Description: "Add a plain-text comment to a Jira issue (by key). Returns the new comment's id and url.",
			InputSchema: objectSchema([]property{
				{"key", "string", "The issue key, like ABC-123.", nil},
				{"body", "string", "Comment text (one paragraph per line).", nil},
			}, []string{"key", "body"}),
			RequiredScopes:   []string{ScopeJiraWrite},
			ResourceIdentity: jiraIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkComment},
			ResultIDs:        commentResultIDs,
			Bounds:           single,
		},
		{
			App: JiraApp, Name: ToolTransitionIssue, Kind: connectors.KindWrite,
			Description: "Move a Jira issue (by key) through a workflow transition; get the transition id from list_transitions. " +
				"The transition cannot be verified afterwards: if the outcome is unknown, check the issue's status in Jira.",
			InputSchema: objectSchema([]property{
				{"key", "string", "The issue key, like ABC-123.", nil},
				{"transition_id", "string", "Id of the transition to apply (from list_transitions).", nil},
			}, []string{"key", "transition_id"}),
			RequiredScopes:   []string{ScopeJiraWrite},
			ResourceIdentity: jiraIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        transitionResultIDs,
			Bounds:           single,
		},
	}
}

// writeHandlers maps the write tools' short names to their implementation.
func (c *Connector) writeHandlers() map[string]handler {
	if c.app == ConfluenceApp {
		return nil
	}
	return map[string]handler{ToolCreateIssue: c.createIssue, ToolAddComment: c.addComment, ToolTransitionIssue: c.transitionIssue}
}

// --- result ids -------------------------------------------------------------------

func issueResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedIssue)
	if !ok || v.Key == "" {
		return nil
	}
	return map[string]string{"key": v.Key, "id": v.ID, "url": v.URL}
}

func commentResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedComment)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "url": v.URL}
}

func transitionResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(Transitioned)
	if !ok || v.Issue == "" {
		return nil
	}
	return map[string]string{"issue": v.Issue, "transition_id": v.TransitionID}
}

// --- markers and shared write helpers ------------------------------------------------

// markerPhrase is the searchable prefix of the marker.
const markerPhrase = "mcp-gateway op:"

// Marker returns the marker text for a ledger operation:
// "mcp-gateway op:<operation id>". Neither the Atlassian Document
// Format nor Confluence storage format has a comment node that is
// guaranteed to survive a save, so the marker is a visible last
// paragraph of what the write creates; JQL and CQL text searches find
// it and the reconciler reads it back.
func Marker(operationID string) string { return markerPhrase + operationID }

// hasMarker reports whether text carries the operation's marker.
func hasMarker(text, operationID string) bool {
	return operationID != "" && strings.Contains(text, Marker(operationID))
}

// classifyWrite maps the error of the request that performs a write:
// an answer from Atlassian (4xx, rate limit) is a known outcome and is
// classified like a read's; anything that leaves the outcome open (5xx,
// a timeout, a cancelled context, a dropped connection, a 2xx reply
// that could not be read: the request may have been applied) wraps
// connectors.ErrOutcomeUnknown so the ledger marks the operation
// unknown and the reconciler checks it.
func (c *Connector) classifyWrite(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %s: Atlassian did not answer in time (%w)", connectors.ErrOutcomeUnknown, action, err)
	}
	var de *decodeError
	if errors.As(err, &de) {
		return fmt.Errorf("%w: %s: Atlassian's reply could not be read (%w)", connectors.ErrOutcomeUnknown, action, err)
	}
	classified := c.classify(action, err)
	var e *Error
	if errors.As(classified, &e) && e.Class == ClassUnavailable {
		return fmt.Errorf("%w: %w", connectors.ErrOutcomeUnknown, classified)
	}
	return classified
}

// --- handlers: jira -------------------------------------------------------------------

func (c *Connector) createIssue(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	project, _ := call.Args["project_key"].(string)
	if project = strings.ToUpper(strings.TrimSpace(project)); !projectKeyRE.MatchString(project) {
		return connectors.Result{}, invalid("project_key is required: a Jira project key like ABC")
	}
	issueType, err := requiredString(call.Args, "issue_type")
	if err != nil {
		return connectors.Result{}, err
	}
	summary, err := requiredString(call.Args, "summary")
	if err != nil {
		return connectors.Result{}, err
	}
	description, err := optionalString(call.Args, "description")
	if err != nil {
		return connectors.Result{}, err
	}
	labels, err := stringList(call.Args, "labels")
	if err != nil {
		return connectors.Result{}, err
	}
	fields := map[string]any{
		"project":     map[string]string{"key": project},
		"issuetype":   map[string]string{"name": issueType},
		"summary":     summary,
		"description": adfDocument(description, Marker(call.OperationID)),
	}
	if labels != nil {
		fields["labels"] = labels
	}
	var created struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := c.classifyWrite("create issue", s.postJSON(ctx, s.jiraURL("issue", nil), map[string]any{"fields": fields}, &created)); err != nil {
		return connectors.Result{}, err
	}
	if created.Key == "" {
		return connectors.Result{}, fmt.Errorf("%w: create issue: Atlassian answered without an issue key", connectors.ErrOutcomeUnknown)
	}
	return connectors.Result{Content: CreatedIssue{Key: created.Key, ID: created.ID, URL: browseURL(s.site, created.Key), Project: project}}, nil
}

func (c *Connector) addComment(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	body, err := requiredString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	var created struct {
		ID string `json:"id"`
	}
	req := map[string]any{"body": adfDocument(body, Marker(call.OperationID))}
	if err := c.classifyWrite("add comment", s.postJSON(ctx, s.jiraURL("issue/"+key+"/comment", nil), req, &created)); err != nil {
		return connectors.Result{}, err
	}
	if created.ID == "" {
		return connectors.Result{}, fmt.Errorf("%w: add comment: Atlassian answered without a comment id", connectors.ErrOutcomeUnknown)
	}
	return connectors.Result{Content: CreatedComment{ID: created.ID, Issue: key, URL: commentURL(s.site, key, created.ID)}}, nil
}

// commentURL links to the comment on the issue's page, "" when the site
// URL is unknown.
func commentURL(site Site, key, id string) string {
	if u := browseURL(site, key); u != "" {
		return u + "?focusedCommentId=" + url.QueryEscape(id)
	}
	return ""
}

func (c *Connector) transitionIssue(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var id string
	switch v := call.Args["transition_id"].(type) {
	case string:
		id = strings.TrimSpace(v)
	case nil:
	default:
		if n, err := toInt(v); err == nil && n > 0 {
			id = fmt.Sprint(n)
		}
	}
	if !transitionIDRE.MatchString(id) {
		return connectors.Result{}, invalid("transition_id is required: the id of a transition from list_transitions")
	}
	req := map[string]any{"transition": map[string]string{"id": id}}
	if err := c.classifyWrite("transition issue", s.postJSON(ctx, s.jiraURL("issue/"+key+"/transitions", nil), req, nil)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: Transitioned{Issue: key, TransitionID: id}}, nil
}
