package atlassian

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// The Jira reads added to close the gap with Atlassian's Rovo MCP server
// and sooperset/mcp-atlassian (design only, no code copied): the current
// user, projects and their create metadata, an issue's comments,
// changelog, links, worklogs and watchers, user lookup, versions,
// components, and Jira Software boards and sprints.

// More Jira read tool names.
const (
	ToolGetCurrentUser        = "get_current_user"
	ToolListProjects          = "list_projects"
	ToolListIssueTypes        = "list_issue_types"
	ToolGetCreateFields       = "get_create_fields"
	ToolGetIssueComments      = "get_issue_comments"
	ToolGetIssueChangelog     = "get_issue_changelog"
	ToolListIssueLinks        = "list_issue_links"
	ToolListLinkTypes         = "list_link_types"
	ToolListWorklogs          = "list_worklogs"
	ToolGetWatchers           = "get_watchers"
	ToolSearchUsers           = "search_users"
	ToolListAssignableUsers   = "list_assignable_users"
	ToolListProjectVersions   = "list_project_versions"
	ToolListProjectComponents = "list_project_components"
	ToolListBoards            = "list_boards"
	ToolListSprints           = "list_sprints"
	ToolGetSprintIssues       = "get_sprint_issues"
)

// Scopes of the added Jira tools. read:jira-user is classic; the Jira
// Software (agile) endpoints accept only granular scopes for OAuth 2.0
// (3LO), which an app may register next to its classic ones.
const (
	ScopeJiraUser       = "read:jira-user"
	ScopeBoardRead      = "read:board-scope:jira-software"
	ScopeProjectRead    = "read:project:jira"
	ScopeSprintRead     = "read:sprint:jira-software"
	ScopeIssueDetails   = "read:issue-details:jira"
	ScopeJQLRead        = "read:jql:jira"
	maxAllowedValues    = 50
	boardTypeValues     = "scrum,kanban,simple"
	sprintStateValues   = "active,future,closed"
	issueTypeIDArgument = "issue_type_id"
)

// pagingProps are the offset-pagination arguments of the added list tools.
var pagingProps = []property{
	{"max_results", "integer", "Results per page (1-100); clamped to the tool's maximum.", nil},
	{"start_at", "integer", "Offset of the first result, starting at 0.", nil},
}

var (
	keyProp        = property{"key", "string", "The issue key, like ABC-123.", nil}
	projectKeyProp = property{"project_key", "string", "The project key, like ABC.", nil}
)

func withPaging(props ...property) []property { return append(props, pagingProps...) }

// jiraMoreReadTools declares the added Jira reads.
func (c *Connector) jiraMoreReadTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	work := []string{ScopeJiraRead}
	tool := func(name, desc string, props []property, required []string, scopes []string, b connectors.Bounds) connectors.Tool {
		return connectors.Tool{App: JiraApp, Name: name, Kind: connectors.KindRead, Description: desc, InputSchema: objectSchema(props, required),
			RequiredScopes: scopes, ResourceIdentity: jiraIdentity, Bounds: b}
	}
	return []connectors.Tool{
		tool(ToolGetCurrentUser, "Get the connected Jira user: account id, display name, email (when visible), time zone, active. "+
			"Use the account id in JQL (assignee = <id>) or with assign_issue.", nil, nil, []string{ScopeJiraUser}, single),
		tool(ToolListProjects, "List the Jira projects this account can see: id, key, name, type and style (classic or next-gen), "+
			"optionally filtered by query (matches key or name). Paginated with start_at; has_more says whether another page exists.",
			withPaging(property{"query", "string", "Filter on project key or name.", nil}), nil, work, paged),
		tool(ToolListIssueTypes, "List the issue types that can be created in a Jira project: id, name, description, subtask. "+
			"Pass an id to get_create_fields, a name to create_issue.", withPaging(projectKeyProp), []string{"project_key"}, work, paged),
		tool(ToolGetCreateFields, "List the fields of one issue type in a project for creating an issue: field id, name, required, "+
			"type (and item type / custom type) and up to 50 allowed values. Use the ids as keys of create_issue / update_issue fields.",
			withPaging(projectKeyProp, property{issueTypeIDArgument, "string", "Issue type id from list_issue_types (digits).", nil}),
			[]string{"project_key", issueTypeIDArgument}, work, paged),
		tool(ToolGetIssueComments, "List the comments of a Jira issue, newest first: id, author, body as plain text, created, updated, url. "+
			"Paginated with start_at; long bodies are cut to the result bounds.", withPaging(keyProp), []string{"key"}, work, paged),
		tool(ToolGetIssueChangelog, "List the change history of a Jira issue, oldest first: who changed which field from what to what, and when. "+
			"Paginated with start_at.", withPaging(keyProp), []string{"key"}, work, paged),
		tool(ToolListIssueLinks, "List the links of a Jira issue to other issues: link id, link type, direction, relation phrase "+
			"(\"blocks\", \"is blocked by\"), the other issue's key, summary, status and url.", []property{keyProp}, []string{"key"}, work, single),
		tool(ToolListLinkTypes, "List the issue link types of the site (name, inward and outward phrases); pass a name to link_issues.",
			nil, nil, work, single),
		tool(ToolListWorklogs, "List the worklogs (time logged) of a Jira issue: id, author, time spent, start, comment. Paginated with start_at.",
			withPaging(keyProp), []string{"key"}, work, paged),
		tool(ToolGetWatchers, "List who watches a Jira issue (account id and name), the watch count and whether you watch it.",
			[]property{keyProp}, []string{"key"}, work, single),
		tool(ToolSearchUsers, "Find Jira users by display name or email: account id, display name, email (when visible), active, account type. "+
			"Use the account id for assignment, watchers and JQL.", withPaging(property{"query", "string", "Part of a display name or email.", nil}),
			[]string{"query"}, []string{ScopeJiraUser}, paged),
		tool(ToolListAssignableUsers, "List the users an issue (key) or a project (project_key) can be assigned to, optionally filtered by query. "+
			"Give key or project_key.", withPaging(projectKeyProp, keyProp, property{"query", "string", "Part of a display name or email.", nil}),
			nil, []string{ScopeJiraUser}, paged),
		tool(ToolListProjectVersions, "List the versions (releases, fix versions) of a Jira project: id, name, description, released, archived, dates.",
			[]property{projectKeyProp}, []string{"project_key"}, work, single),
		tool(ToolListProjectComponents, "List the components of a Jira project: id, name, description and lead.",
			[]property{projectKeyProp}, []string{"project_key"}, work, single),
		tool(ToolListBoards, "List the Jira Software boards this account can see: id, name, type (scrum, kanban, simple) and project, "+
			"optionally filtered by project, name or type. Paginated with start_at.",
			withPaging(projectKeyProp, property{"name", "string", "Filter on board name (contains).", nil},
				property{"type", "string", "Board type.", strings.Split(boardTypeValues, ",")}),
			nil, []string{ScopeBoardRead, ScopeProjectRead}, paged),
		tool(ToolListSprints, "List the sprints of a Jira Software board: id, name, state, start, end and completion dates, goal; "+
			"optionally only active, future or closed ones. Paginated with start_at.",
			withPaging(property{"board_id", "integer", "Board id from list_boards.", nil}, property{"state", "string", "Sprint state.", strings.Split(sprintStateValues, ",")}),
			[]string{"board_id"}, []string{ScopeSprintRead}, paged),
		tool(ToolGetSprintIssues, "List the issues in a sprint (same fields as search_issues), optionally narrowed by a JQL filter. Paginated with start_at.",
			withPaging(property{"sprint_id", "integer", "Sprint id from list_sprints.", nil}, property{"jql", "string", "Optional JQL filter.", nil}),
			[]string{"sprint_id"}, []string{ScopeSprintRead, ScopeIssueDetails, ScopeJQLRead}, paged),
	}
}

func (c *Connector) jiraMoreReadHandlers() map[string]handler {
	return map[string]handler{
		ToolGetCurrentUser: c.getCurrentUser, ToolListProjects: c.listProjects, ToolListIssueTypes: c.listIssueTypes,
		ToolGetCreateFields: c.getCreateFields, ToolGetIssueComments: c.getIssueComments, ToolGetIssueChangelog: c.getIssueChangelog,
		ToolListIssueLinks: c.listIssueLinks, ToolListLinkTypes: c.listLinkTypes, ToolListWorklogs: c.listWorklogs,
		ToolGetWatchers: c.getWatchers, ToolSearchUsers: c.searchUsers, ToolListAssignableUsers: c.listAssignableUsers,
		ToolListProjectVersions: c.listProjectVersions, ToolListProjectComponents: c.listProjectComponents,
		ToolListBoards: c.listBoards, ToolListSprints: c.listSprints, ToolGetSprintIssues: c.getSprintIssues,
	}
}

// --- result shapes ----------------------------------------------------------------

// Paging is the offset pagination of the added list results.
type Paging struct {
	StartAt    int  `json:"start_at"`
	MaxResults int  `json:"max_results"`
	Total      int  `json:"total,omitempty"`
	HasMore    bool `json:"has_more"`
	Truncated  bool `json:"truncated,omitempty"`
}

// JiraUser is one Jira user.
type JiraUser struct {
	AccountID   string `json:"account_id"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	TimeZone    string `json:"time_zone,omitempty"`
	Active      bool   `json:"active"`
	AccountType string `json:"account_type,omitempty"`
}

// ProjectSummary is one project of list_projects.
type ProjectSummary struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Name  string `json:"name"`
	Type  string `json:"type,omitempty"`
	Style string `json:"style,omitempty"`
}

// IssueType is one creatable issue type.
type IssueType struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Subtask     bool   `json:"subtask"`
}

// CreateField is one field of an issue type's create metadata.
type CreateField struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Required      bool     `json:"required"`
	Type          string   `json:"type,omitempty"`
	Items         string   `json:"items,omitempty"`
	Custom        string   `json:"custom,omitempty"`
	AllowedValues []string `json:"allowed_values,omitempty"`
	MoreValues    bool     `json:"more_values,omitempty"`
	HasDefault    bool     `json:"has_default,omitempty"`
}

// IssueComment is one comment of get_issue_comments.
type IssueComment struct {
	ID      string `json:"id"`
	Author  string `json:"author,omitempty"`
	Body    string `json:"body"`
	Created string `json:"created,omitempty"`
	Updated string `json:"updated,omitempty"`
	URL     string `json:"url,omitempty"`
}

// ChangeItem is one field change of a changelog entry.
type ChangeItem struct {
	Field string `json:"field"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
}

// ChangeHistory is one changelog entry.
type ChangeHistory struct {
	ID      string       `json:"id"`
	Author  string       `json:"author,omitempty"`
	Created string       `json:"created,omitempty"`
	Items   []ChangeItem `json:"items"`
}

// IssueLinkView is one link of list_issue_links.
type IssueLinkView struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Direction string `json:"direction"`
	Relation  string `json:"relation,omitempty"`
	Issue     string `json:"issue"`
	Summary   string `json:"summary,omitempty"`
	Status    string `json:"status,omitempty"`
	URL       string `json:"url,omitempty"`
}

// LinkType is one issue link type.
type LinkType struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Inward  string `json:"inward"`
	Outward string `json:"outward"`
}

// WorklogView is one worklog.
type WorklogView struct {
	ID               string `json:"id"`
	Author           string `json:"author,omitempty"`
	TimeSpent        string `json:"time_spent,omitempty"`
	TimeSpentSeconds int    `json:"time_spent_seconds"`
	Started          string `json:"started,omitempty"`
	Comment          string `json:"comment,omitempty"`
}

// VersionView is one project version.
type VersionView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Released    bool   `json:"released"`
	Archived    bool   `json:"archived"`
	Overdue     bool   `json:"overdue,omitempty"`
	StartDate   string `json:"start_date,omitempty"`
	ReleaseDate string `json:"release_date,omitempty"`
}

// ComponentView is one project component.
type ComponentView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Lead        string `json:"lead,omitempty"`
}

// Board is one Jira Software board.
type Board struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	Project string `json:"project,omitempty"`
}

// Sprint is one sprint.
type Sprint struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	State        string `json:"state,omitempty"`
	StartDate    string `json:"start_date,omitempty"`
	EndDate      string `json:"end_date,omitempty"`
	CompleteDate string `json:"complete_date,omitempty"`
	Goal         string `json:"goal,omitempty"`
}

// --- wire shapes ------------------------------------------------------------------------

type wireUser struct {
	AccountID    string `json:"accountId"`
	DisplayName  string `json:"displayName"`
	EmailAddress string `json:"emailAddress"`
	TimeZone     string `json:"timeZone"`
	Active       bool   `json:"active"`
	AccountType  string `json:"accountType"`
}

func (u wireUser) view() JiraUser {
	return JiraUser{AccountID: u.AccountID, DisplayName: u.DisplayName, Email: u.EmailAddress, TimeZone: u.TimeZone, Active: u.Active, AccountType: u.AccountType}
}

// wirePaged is the offset pagination envelope Jira's lists share.
type wirePaged struct {
	StartAt    int   `json:"startAt"`
	MaxResults int   `json:"maxResults"`
	Total      int   `json:"total"`
	IsLast     *bool `json:"isLast"`
}

// paging builds the result paging from the envelope and the number of
// items on this page.
func (w wirePaged) paging(start, size, n int) Paging {
	p := Paging{StartAt: start, MaxResults: size, Total: w.Total}
	switch {
	case w.IsLast != nil:
		p.HasMore = !*w.IsLast
	case w.Total > 0:
		p.HasMore = start+n < w.Total
	}
	return p
}

// --- helpers ------------------------------------------------------------------------------

// offsetArgs reads max_results (clamped) and start_at.
func (c *Connector) offsetArgs(args map[string]any) (size int, clamped bool, start int, err error) {
	if size, clamped, err = c.pageSizeArg(args, "max_results"); err != nil {
		return 0, false, 0, err
	}
	if v, ok := args["start_at"]; ok && v != nil {
		if start, err = toInt(v); err != nil || start < 0 {
			return 0, false, 0, invalid("start_at must be a non-negative integer")
		}
	}
	return size, clamped, start, nil
}

// offsetQuery is the startAt / maxResults query of an offset page.
func offsetQuery(size, start int) url.Values {
	return url.Values{"maxResults": {strconv.Itoa(size)}, "startAt": {strconv.Itoa(start)}}
}

// projectKeyArg reads the required project_key argument (upper-cased).
func projectKeyArg(args map[string]any) (string, error) {
	p, _ := args["project_key"].(string)
	if p = strings.ToUpper(strings.TrimSpace(p)); !projectKeyRE.MatchString(p) {
		return "", invalid("project_key is required: a Jira project key like ABC")
	}
	return p, nil
}

// idArg reads a required positive numeric id argument.
func idArg(args map[string]any, name string) (string, error) {
	id, ok := positiveID(args[name])
	if !ok {
		return "", invalid("%s is required: a positive number", name)
	}
	return id, nil
}

// enumArg reads an optional string argument restricted to the comma
// separated allowed values.
func enumArg(args map[string]any, name, allowed string) (string, error) {
	v, err := optionalString(args, name)
	if err != nil || strings.TrimSpace(v) == "" {
		return "", err
	}
	v = strings.ToLower(strings.TrimSpace(v))
	for _, a := range strings.Split(allowed, ",") {
		if v == a {
			return v, nil
		}
	}
	return "", invalid("%s must be one of %s", name, strings.ReplaceAll(allowed, ",", ", "))
}

// fitList drops trailing items of *list until obj serialises within max
// (never below one item) and reports whether it dropped any.
func fitList[T any](list *[]T, max int, obj func() any) bool {
	cut := false
	for encodedSize(obj()) > max && len(*list) > 1 {
		*list = (*list)[:len(*list)-1]
		cut = true
	}
	return cut
}

// listResult builds the result of a list read.
func listResult(content any, n int, partial bool) connectors.Result {
	return connectors.Result{Content: content, Empty: n == 0, Partial: partial}
}

// --- handlers -------------------------------------------------------------------------------

func (c *Connector) getCurrentUser(ctx context.Context, s *session, _ connectors.Call) (connectors.Result, error) {
	var u wireUser
	if err := c.classify("get current user", s.getJSON(ctx, s.jiraURL("myself", nil), &u)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: u.view()}, nil
}

func (c *Connector) listProjects(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q := offsetQuery(size, start)
	q.Set("orderBy", "key")
	if v, _ := optionalString(call.Args, "query"); strings.TrimSpace(v) != "" {
		q.Set("query", strings.TrimSpace(v))
	}
	var page struct {
		wirePaged
		Values []struct {
			ID             string `json:"id"`
			Key            string `json:"key"`
			Name           string `json:"name"`
			ProjectTypeKey string `json:"projectTypeKey"`
			Style          string `json:"style"`
		} `json:"values"`
	}
	if err := c.classify("list projects", s.getJSON(ctx, s.jiraURL("project/search", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Projects []ProjectSummary `json:"projects"`
		Paging
	}{Projects: make([]ProjectSummary, 0, len(page.Values)), Paging: page.paging(start, size, len(page.Values))}
	for _, p := range page.Values {
		out.Projects = append(out.Projects, ProjectSummary{ID: p.ID, Key: p.Key, Name: p.Name, Type: p.ProjectTypeKey, Style: p.Style})
	}
	out.Truncated = fitList(&out.Projects, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Projects), clamped || out.Truncated), nil
}

func (c *Connector) listIssueTypes(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	project, err := projectKeyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		wirePaged
		IssueTypes []IssueType `json:"issueTypes"`
	}
	if err := c.classify("list issue types", s.getJSON(ctx, s.jiraURL("issue/createmeta/"+project+"/issuetypes", offsetQuery(size, start)), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Project    string      `json:"project"`
		IssueTypes []IssueType `json:"issue_types"`
		Paging
	}{Project: project, IssueTypes: page.IssueTypes, Paging: page.paging(start, size, len(page.IssueTypes))}
	if out.IssueTypes == nil {
		out.IssueTypes = []IssueType{}
	}
	out.Truncated = fitList(&out.IssueTypes, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.IssueTypes), clamped || out.Truncated), nil
}

func (c *Connector) getCreateFields(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	project, err := projectKeyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	typeID, err := idArg(call.Args, issueTypeIDArgument)
	if err != nil {
		return connectors.Result{}, err
	}
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		wirePaged
		Fields []struct {
			FieldID  string `json:"fieldId"`
			Name     string `json:"name"`
			Required bool   `json:"required"`
			Schema   struct {
				Type   string `json:"type"`
				Items  string `json:"items"`
				Custom string `json:"custom"`
			} `json:"schema"`
			AllowedValues   []map[string]any `json:"allowedValues"`
			HasDefaultValue bool             `json:"hasDefaultValue"`
		} `json:"fields"`
	}
	path := "issue/createmeta/" + project + "/issuetypes/" + typeID
	if err := c.classify("get create fields", s.getJSON(ctx, s.jiraURL(path, offsetQuery(size, start)), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Project     string        `json:"project"`
		IssueTypeID string        `json:"issue_type_id"`
		Fields      []CreateField `json:"fields"`
		Paging
	}{Project: project, IssueTypeID: typeID, Fields: make([]CreateField, 0, len(page.Fields)), Paging: page.paging(start, size, len(page.Fields))}
	for _, f := range page.Fields {
		cf := CreateField{ID: f.FieldID, Name: f.Name, Required: f.Required, Type: f.Schema.Type, Items: f.Schema.Items, Custom: f.Schema.Custom, HasDefault: f.HasDefaultValue}
		for i, v := range f.AllowedValues {
			if i == maxAllowedValues {
				cf.MoreValues = true
				break
			}
			cf.AllowedValues = append(cf.AllowedValues, allowedLabel(v))
		}
		out.Fields = append(out.Fields, cf)
	}
	out.Truncated = fitList(&out.Fields, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Fields), clamped || out.Truncated), nil
}

// allowedLabel is the label of one allowed value: its name, value, key
// or id, whichever it has first.
func allowedLabel(v map[string]any) string {
	for _, k := range []string{"name", "value", "key", "id"} {
		if s, ok := v[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func (c *Connector) getIssueComments(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q := offsetQuery(size, start)
	q.Set("orderBy", "-created")
	var page struct {
		wirePaged
		Comments []struct {
			ID      string          `json:"id"`
			Author  *named          `json:"author"`
			Body    json.RawMessage `json:"body"`
			Created string          `json:"created"`
			Updated string          `json:"updated"`
		} `json:"comments"`
	}
	if err := c.classify("get comments", s.getJSON(ctx, s.jiraURL("issue/"+key+"/comment", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Issue    string         `json:"issue"`
		Comments []IssueComment `json:"comments"`
		Paging
	}{Issue: key, Comments: make([]IssueComment, 0, len(page.Comments)), Paging: page.paging(start, size, len(page.Comments))}
	for _, cm := range page.Comments {
		out.Comments = append(out.Comments, IssueComment{ID: cm.ID, Author: cm.Author.label(), Body: adfText(cm.Body),
			Created: timestamp(cm.Created), Updated: timestamp(cm.Updated), URL: commentURL(s.site, key, cm.ID)})
	}
	out.Truncated = fitList(&out.Comments, c.bounds.MaxResultBytes, func() any { return out })
	if len(out.Comments) == 1 {
		fitBody(&out.Comments[0].Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	}
	return listResult(out, len(out.Comments), clamped || out.Truncated), nil
}

func (c *Connector) getIssueChangelog(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		wirePaged
		Values    []wireHistory `json:"values"`
		Histories []wireHistory `json:"histories"`
	}
	if err := c.classify("get changelog", s.getJSON(ctx, s.jiraURL("issue/"+key+"/changelog", offsetQuery(size, start)), &page)); err != nil {
		return connectors.Result{}, err
	}
	hs := page.Values
	if len(hs) == 0 {
		hs = page.Histories
	}
	out := struct {
		Issue     string          `json:"issue"`
		Histories []ChangeHistory `json:"histories"`
		Paging
	}{Issue: key, Histories: make([]ChangeHistory, 0, len(hs)), Paging: page.paging(start, size, len(hs))}
	for _, h := range hs {
		ch := ChangeHistory{ID: h.ID, Author: h.Author.label(), Created: timestamp(h.Created), Items: make([]ChangeItem, 0, len(h.Items))}
		for _, it := range h.Items {
			ch.Items = append(ch.Items, ChangeItem{Field: it.Field, From: it.FromString, To: it.ToString})
		}
		out.Histories = append(out.Histories, ch)
	}
	out.Truncated = fitList(&out.Histories, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Histories), clamped || out.Truncated), nil
}

type wireHistory struct {
	ID      string `json:"id"`
	Author  *named `json:"author"`
	Created string `json:"created"`
	Items   []struct {
		Field      string `json:"field"`
		FromString string `json:"fromString"`
		ToString   string `json:"toString"`
	} `json:"items"`
}

func (c *Connector) listIssueLinks(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	type linked struct {
		Key    string `json:"key"`
		Fields struct {
			Summary string `json:"summary"`
			Status  *named `json:"status"`
		} `json:"fields"`
	}
	var is struct {
		Fields struct {
			IssueLinks []struct {
				ID   string `json:"id"`
				Type struct {
					Name, Inward, Outward string
				} `json:"type"`
				InwardIssue  *linked `json:"inwardIssue"`
				OutwardIssue *linked `json:"outwardIssue"`
			} `json:"issuelinks"`
		} `json:"fields"`
	}
	if err := c.classify("list issue links", s.getJSON(ctx, s.jiraURL("issue/"+key, url.Values{"fields": {"issuelinks"}}), &is)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Issue     string          `json:"issue"`
		Links     []IssueLinkView `json:"links"`
		Truncated bool            `json:"truncated,omitempty"`
	}{Issue: key, Links: []IssueLinkView{}}
	for _, l := range is.Fields.IssueLinks {
		v := IssueLinkView{ID: l.ID, Type: l.Type.Name}
		other := l.OutwardIssue
		v.Direction, v.Relation = "outward", l.Type.Outward
		if other == nil {
			other = l.InwardIssue
			v.Direction, v.Relation = "inward", l.Type.Inward
		}
		if other == nil {
			continue
		}
		v.Issue, v.Summary, v.Status, v.URL = other.Key, other.Fields.Summary, other.Fields.Status.label(), browseURL(s.site, other.Key)
		out.Links = append(out.Links, v)
	}
	out.Truncated = fitList(&out.Links, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Links), out.Truncated), nil
}

func (c *Connector) listLinkTypes(ctx context.Context, s *session, _ connectors.Call) (connectors.Result, error) {
	var res struct {
		IssueLinkTypes []LinkType `json:"issueLinkTypes"`
	}
	if err := c.classify("list link types", s.getJSON(ctx, s.jiraURL("issueLinkType", nil), &res)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		LinkTypes []LinkType `json:"link_types"`
		Truncated bool       `json:"truncated,omitempty"`
	}{LinkTypes: res.IssueLinkTypes}
	if out.LinkTypes == nil {
		out.LinkTypes = []LinkType{}
	}
	out.Truncated = fitList(&out.LinkTypes, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.LinkTypes), out.Truncated), nil
}

func (c *Connector) listWorklogs(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		wirePaged
		Worklogs []struct {
			ID               string          `json:"id"`
			Author           *named          `json:"author"`
			TimeSpent        string          `json:"timeSpent"`
			TimeSpentSeconds int             `json:"timeSpentSeconds"`
			Started          string          `json:"started"`
			Comment          json.RawMessage `json:"comment"`
		} `json:"worklogs"`
	}
	if err := c.classify("list worklogs", s.getJSON(ctx, s.jiraURL("issue/"+key+"/worklog", offsetQuery(size, start)), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Issue    string        `json:"issue"`
		Worklogs []WorklogView `json:"worklogs"`
		Paging
	}{Issue: key, Worklogs: make([]WorklogView, 0, len(page.Worklogs)), Paging: page.paging(start, size, len(page.Worklogs))}
	for _, w := range page.Worklogs {
		out.Worklogs = append(out.Worklogs, WorklogView{ID: w.ID, Author: w.Author.label(), TimeSpent: w.TimeSpent, TimeSpentSeconds: w.TimeSpentSeconds,
			Started: timestamp(w.Started), Comment: adfText(w.Comment)})
	}
	out.Truncated = fitList(&out.Worklogs, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Worklogs), clamped || out.Truncated), nil
}

func (c *Connector) getWatchers(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	key, err := keyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var res struct {
		IsWatching bool       `json:"isWatching"`
		WatchCount int        `json:"watchCount"`
		Watchers   []wireUser `json:"watchers"`
	}
	if err := c.classify("get watchers", s.getJSON(ctx, s.jiraURL("issue/"+key+"/watchers", nil), &res)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Issue      string     `json:"issue"`
		IsWatching bool       `json:"is_watching"`
		WatchCount int        `json:"watch_count"`
		Watchers   []JiraUser `json:"watchers"`
		Truncated  bool       `json:"truncated,omitempty"`
	}{Issue: key, IsWatching: res.IsWatching, WatchCount: res.WatchCount, Watchers: make([]JiraUser, 0, len(res.Watchers))}
	for _, u := range res.Watchers {
		out.Watchers = append(out.Watchers, u.view())
	}
	out.Truncated = fitList(&out.Watchers, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Watchers), out.Truncated), nil
}

// userList runs a user search endpoint that answers a bare array.
func (c *Connector) userList(ctx context.Context, s *session, action, path string, q url.Values, start, size int, clamped bool) (connectors.Result, error) {
	var users []wireUser
	if err := c.classify(action, s.getJSON(ctx, s.jiraURL(path, q), &users)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Users []JiraUser `json:"users"`
		Paging
	}{Users: make([]JiraUser, 0, len(users)), Paging: Paging{StartAt: start, MaxResults: size, HasMore: len(users) >= size}}
	for _, u := range users {
		out.Users = append(out.Users, u.view())
	}
	out.Truncated = fitList(&out.Users, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Users), clamped || out.Truncated), nil
}

func (c *Connector) searchUsers(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	query, err := requiredString(call.Args, "query")
	if err != nil {
		return connectors.Result{}, err
	}
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q := offsetQuery(size, start)
	q.Set("query", query)
	return c.userList(ctx, s, "search users", "user/search", q, start, size, clamped)
}

func (c *Connector) listAssignableUsers(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q := offsetQuery(size, start)
	if key, ok := issueKeyArg(call.Args["key"]); ok {
		q.Set("issueKey", key)
	} else if p, err := projectKeyArg(call.Args); err == nil {
		q.Set("project", p)
	} else {
		return connectors.Result{}, invalid("give key (an issue key like ABC-123) or project_key (a project key like ABC)")
	}
	if v, _ := optionalString(call.Args, "query"); strings.TrimSpace(v) != "" {
		q.Set("query", strings.TrimSpace(v))
	}
	return c.userList(ctx, s, "list assignable users", "user/assignable/search", q, start, size, clamped)
}

func (c *Connector) listProjectVersions(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	project, err := projectKeyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var vs []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Released    bool   `json:"released"`
		Archived    bool   `json:"archived"`
		Overdue     bool   `json:"overdue"`
		StartDate   string `json:"startDate"`
		ReleaseDate string `json:"releaseDate"`
	}
	if err := c.classify("list versions", s.getJSON(ctx, s.jiraURL("project/"+project+"/versions", nil), &vs)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Project   string        `json:"project"`
		Versions  []VersionView `json:"versions"`
		Truncated bool          `json:"truncated,omitempty"`
	}{Project: project, Versions: make([]VersionView, 0, len(vs))}
	for _, v := range vs {
		out.Versions = append(out.Versions, VersionView{ID: v.ID, Name: v.Name, Description: v.Description, Released: v.Released, Archived: v.Archived,
			Overdue: v.Overdue, StartDate: v.StartDate, ReleaseDate: v.ReleaseDate})
	}
	out.Truncated = fitList(&out.Versions, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Versions), out.Truncated), nil
}

func (c *Connector) listProjectComponents(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	project, err := projectKeyArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var cs []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Lead        *named `json:"lead"`
	}
	if err := c.classify("list components", s.getJSON(ctx, s.jiraURL("project/"+project+"/components", nil), &cs)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Project    string          `json:"project"`
		Components []ComponentView `json:"components"`
		Truncated  bool            `json:"truncated,omitempty"`
	}{Project: project, Components: make([]ComponentView, 0, len(cs))}
	for _, cp := range cs {
		out.Components = append(out.Components, ComponentView{ID: cp.ID, Name: cp.Name, Description: cp.Description, Lead: cp.Lead.label()})
	}
	out.Truncated = fitList(&out.Components, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Components), out.Truncated), nil
}

func (c *Connector) listBoards(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	typ, err := enumArg(call.Args, "type", boardTypeValues)
	if err != nil {
		return connectors.Result{}, err
	}
	q := offsetQuery(size, start)
	if typ != "" {
		q.Set("type", typ)
	}
	if _, ok := call.Args["project_key"]; ok {
		p, err := projectKeyArg(call.Args)
		if err != nil {
			return connectors.Result{}, err
		}
		q.Set("projectKeyOrId", p)
	}
	if v, _ := optionalString(call.Args, "name"); strings.TrimSpace(v) != "" {
		q.Set("name", strings.TrimSpace(v))
	}
	var page struct {
		wirePaged
		Values []struct {
			ID       int    `json:"id"`
			Name     string `json:"name"`
			Type     string `json:"type"`
			Location *struct {
				ProjectKey string `json:"projectKey"`
			} `json:"location"`
		} `json:"values"`
	}
	if err := c.classify("list boards", s.getJSON(ctx, s.agileURL("board", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	out := struct {
		Boards []Board `json:"boards"`
		Paging
	}{Boards: make([]Board, 0, len(page.Values)), Paging: page.paging(start, size, len(page.Values))}
	for _, b := range page.Values {
		v := Board{ID: b.ID, Name: b.Name, Type: b.Type}
		if b.Location != nil {
			v.Project = b.Location.ProjectKey
		}
		out.Boards = append(out.Boards, v)
	}
	out.Truncated = fitList(&out.Boards, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Boards), clamped || out.Truncated), nil
}

func (c *Connector) listSprints(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	board, err := idArg(call.Args, "board_id")
	if err != nil {
		return connectors.Result{}, err
	}
	state, err := enumArg(call.Args, "state", sprintStateValues)
	if err != nil {
		return connectors.Result{}, err
	}
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q := offsetQuery(size, start)
	if state != "" {
		q.Set("state", state)
	}
	var page struct {
		wirePaged
		Values []struct {
			ID           int    `json:"id"`
			Name         string `json:"name"`
			State        string `json:"state"`
			StartDate    string `json:"startDate"`
			EndDate      string `json:"endDate"`
			CompleteDate string `json:"completeDate"`
			Goal         string `json:"goal"`
		} `json:"values"`
	}
	if err := c.classify("list sprints", s.getJSON(ctx, s.agileURL("board/"+board+"/sprint", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	boardID, _ := strconv.Atoi(board)
	out := struct {
		BoardID int      `json:"board_id"`
		Sprints []Sprint `json:"sprints"`
		Paging
	}{BoardID: boardID, Sprints: make([]Sprint, 0, len(page.Values)), Paging: page.paging(start, size, len(page.Values))}
	for _, sp := range page.Values {
		out.Sprints = append(out.Sprints, Sprint{ID: sp.ID, Name: sp.Name, State: sp.State, StartDate: timestamp(sp.StartDate),
			EndDate: timestamp(sp.EndDate), CompleteDate: timestamp(sp.CompleteDate), Goal: sp.Goal})
	}
	out.Truncated = fitList(&out.Sprints, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Sprints), clamped || out.Truncated), nil
}

func (c *Connector) getSprintIssues(ctx context.Context, s *session, call connectors.Call) (connectors.Result, error) {
	sprint, err := idArg(call.Args, "sprint_id")
	if err != nil {
		return connectors.Result{}, err
	}
	size, clamped, start, err := c.offsetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	q := offsetQuery(size, start)
	q.Set("fields", strings.Join(issueFieldNames, ","))
	if jql, _ := optionalString(call.Args, "jql"); strings.TrimSpace(jql) != "" {
		q.Set("jql", strings.TrimSpace(jql))
	}
	var page struct {
		wirePaged
		Issues []wireIssue `json:"issues"`
	}
	if err := c.classify("get sprint issues", s.getJSON(ctx, s.agileURL("sprint/"+sprint+"/issue", q), &page)); err != nil {
		return connectors.Result{}, err
	}
	sprintID, _ := strconv.Atoi(sprint)
	out := struct {
		SprintID int            `json:"sprint_id"`
		Issues   []IssueSummary `json:"issues"`
		Paging
	}{SprintID: sprintID, Issues: make([]IssueSummary, 0, len(page.Issues)), Paging: page.paging(start, size, len(page.Issues))}
	for _, is := range page.Issues {
		out.Issues = append(out.Issues, toIssueSummary(is, s.site))
	}
	out.Truncated = fitList(&out.Issues, c.bounds.MaxResultBytes, func() any { return out })
	return listResult(out, len(out.Issues), clamped || out.Truncated), nil
}
