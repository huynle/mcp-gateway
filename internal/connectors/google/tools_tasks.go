package google

import (
	"context"
	"strings"

	"google.golang.org/api/tasks/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Tasks tool names.
const (
	ToolListTasks  = "list"
	ToolCreateTask = "create"
)

// DefaultTasklist is the tasklist when the harness gives none: the
// account's default list.
const DefaultTasklist = "@default"

// defaultTasksPerPage is tasks.list's page size when the harness gives
// none, capped by the bounds (the Tasks API's own default and maximum
// is 100).
const defaultTasksPerPage = 50

var tasklistProperty = property{"tasklist", "string", "Task list id: \"@default\" (default) for the account's default list.", nil}

// Task is one tasks.list item. Due is a date (YYYY-MM-DD): the Tasks
// API keeps no time of day.
type Task struct {
	ID        string `json:"id"`
	Tasklist  string `json:"tasklist"`
	Title     string `json:"title"`
	Notes     string `json:"notes,omitempty"`
	Status    string `json:"status"`
	Due       string `json:"due,omitempty"`
	Completed string `json:"completed,omitempty"`
	Updated   string `json:"updated,omitempty"`
	Parent    string `json:"parent,omitempty"`
	Position  string `json:"position,omitempty"`
	Hidden    bool   `json:"hidden,omitempty"`
	URL       string `json:"url,omitempty"`
}

// TasksPage is tasks.list's result.
type TasksPage struct {
	Tasklist      string `json:"tasklist"`
	MaxResults    int    `json:"max_results"`
	ShowCompleted bool   `json:"show_completed"`
	NextPageToken string `json:"next_page_token,omitempty"`
	HasMore       bool   `json:"has_more"`
	Truncated     bool   `json:"truncated,omitempty"`
	Items         []Task `json:"items"`
}

// CreatedTask is tasks.create's result: the identifiers of the new task.
type CreatedTask struct {
	ID       string `json:"id"`
	Tasklist string `json:"tasklist"`
	URL      string `json:"url,omitempty"`
	Status   string `json:"status,omitempty"`
}

func toTask(t *tasks.Task, tasklist string) Task {
	return Task{
		ID: t.Id, Tasklist: tasklist, Title: t.Title, Notes: t.Notes, Status: t.Status, Due: dateOf(t.Due),
		Completed: normalizeTimestamp(ptrString(t.Completed)), Updated: normalizeTimestamp(t.Updated),
		Parent: t.Parent, Position: t.Position, Hidden: t.Hidden, URL: t.WebViewLink,
	}
}

func ptrString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// dateOf renders a Tasks "due" timestamp (always midnight UTC) as its
// date; other strings pass through.
func dateOf(s string) string {
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' {
		return s[:10]
	}
	return s
}

// tasksReadTools declares the Tasks read.
func (c *Connector) tasksReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppTasks, Name: ToolListTasks, Kind: connectors.KindRead,
			Description: "List the tasks of a Google Tasks list (the default list unless tasklist is given): id, title, notes, status " +
				"(needsAction or completed), due date and parent. Completed and hidden tasks are left out unless show_completed is true. " +
				"has_more and next_page_token say whether another page exists (pass page_token).",
			InputSchema: objectSchema([]property{
				tasklistProperty,
				{"show_completed", "boolean", "Include completed (and hidden) tasks. Default false.", nil},
				{"max_results", "integer", "Tasks per page (1-100; default 50); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes:   []string{ScopeTasksReadonly},
			ResourceIdentity: tasksIdentity,
			Bounds:           c.pagedBounds(),
		},
	}
}

// tasksReadHandlers maps the Tasks read's short name to its
// implementation.
func (c *Connector) tasksReadHandlers() map[string]handler {
	return map[string]handler{ToolListTasks: c.listTasks}
}

// tasksIdentity extracts tasklist ("@default" when absent) from the
// arguments; never argument content.
func tasksIdentity(args map[string]any) map[string]string {
	id, _ := args["tasklist"].(string)
	if id = strings.TrimSpace(id); id == "" {
		id = DefaultTasklist
	}
	return map[string]string{"tasklist": id}
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) listTasks(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, err := idArgDefault(call.Args, "tasklist", DefaultTasklist)
	if err != nil {
		return connectors.Result{}, err
	}
	showCompleted, err := optionalBool(call.Args, "show_completed", false)
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultTasksPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Tasks.List(tasklist).Context(ctx).ShowCompleted(showCompleted).ShowHidden(showCompleted).MaxResults(int64(maxResults))
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list tasks", err); err != nil {
		return connectors.Result{}, err
	}
	out := TasksPage{Tasklist: tasklist, MaxResults: maxResults, ShowCompleted: showCompleted, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]Task, 0, len(list.Items))}
	for _, t := range list.Items {
		if t != nil {
			out.Items = append(out.Items, toTask(t, tasklist))
		}
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}
