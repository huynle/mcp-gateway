package google

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/api/tasks/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Tasks management tool names.
const (
	ToolListTasklists = "list_tasklists"
	ToolGetTask       = "get"
	ToolUpdateTask    = "update"
	ToolCompleteTask  = "complete"
	ToolDeleteTask    = "delete"
)

// Task statuses.
const (
	TaskNeedsAction = "needsAction"
	TaskCompleted   = "completed"
)

// Tasklist is one list_tasklists item.
type Tasklist struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Updated string `json:"updated,omitempty"`
}

// TasklistsPage is list_tasklists's result.
type TasklistsPage struct {
	MaxResults    int        `json:"max_results"`
	NextPageToken string     `json:"next_page_token,omitempty"`
	HasMore       bool       `json:"has_more"`
	Truncated     bool       `json:"truncated,omitempty"`
	Items         []Tasklist `json:"items"`
}

// ChangedTask is the result of update, complete and delete.
type ChangedTask struct {
	ID       string `json:"id"`
	Tasklist string `json:"tasklist"`
	Status   string `json:"status,omitempty"`
	URL      string `json:"url,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
}

var taskIDProperty = property{"task_id", "string", "The task's id (from tasks.list).", nil}

func (c *Connector) tasksManageReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppTasks, Name: ToolListTasklists, Kind: connectors.KindRead,
			Description: "List the account's Google Tasks lists: id, title and updated. Pass an id as tasklist of the other tasks tools. " +
				"has_more and next_page_token say whether another page exists.",
			InputSchema: objectSchema([]property{
				{"max_results", "integer", "Lists per page (1-100; default 50); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes:   []string{ScopeTasksReadonly},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppTasks, Name: ToolGetTask, Kind: connectors.KindRead,
			Description:      "Get one task by id: title, notes, status, due date, completed, parent and url.",
			InputSchema:      objectSchema([]property{tasklistProperty, taskIDProperty}, []string{"task_id"}),
			RequiredScopes:   []string{ScopeTasksReadonly},
			ResourceIdentity: taskIdentity,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) tasksManageReadHandlers() map[string]handler {
	return map[string]handler{ToolListTasklists: c.listTasklists, ToolGetTask: c.getTask}
}

func (c *Connector) tasksManageWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppTasks, Name: ToolUpdateTask, Kind: connectors.KindWrite,
			Description: "Change a task: only the fields given change (title, notes, due date YYYY-MM-DD, status needsAction or completed). " +
				"Returns the task's id. Cannot be verified after an unknown outcome: check the task.",
			InputSchema: objectSchema([]property{
				tasklistProperty, taskIDProperty,
				{"title", "string", "New title.", nil},
				{"notes", "string", "New notes (empty clears them).", nil},
				{"due", "string", "New due date, YYYY-MM-DD.", nil},
				{"status", "string", "needsAction (reopen) or completed.", []string{TaskNeedsAction, TaskCompleted}},
			}, []string{"task_id"}),
			RequiredScopes:   []string{ScopeTasks},
			ResourceIdentity: taskIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        changedTaskResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppTasks, Name: ToolCompleteTask, Kind: connectors.KindWrite,
			Description:      "Mark a task completed. Returns the task's id and status.",
			InputSchema:      objectSchema([]property{tasklistProperty, taskIDProperty}, []string{"task_id"}),
			RequiredScopes:   []string{ScopeTasks},
			ResourceIdentity: taskIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkTaskCompleted},
			ResultIDs:        changedTaskResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppTasks, Name: ToolDeleteTask, Kind: connectors.KindWrite,
			Description:      "Delete a task from its list.",
			InputSchema:      objectSchema([]property{tasklistProperty, taskIDProperty}, []string{"task_id"}),
			RequiredScopes:   []string{ScopeTasks},
			ResourceIdentity: taskIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkTaskDeleted},
			ResultIDs:        changedTaskResultIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) tasksManageWriteHandlers() map[string]handler {
	return map[string]handler{ToolUpdateTask: c.updateTask, ToolCompleteTask: c.completeTask, ToolDeleteTask: c.deleteTask}
}

// taskIdentity is tasksIdentity plus task_id.
func taskIdentity(args map[string]any) map[string]string {
	out := tasksIdentity(args)
	if id, _ := args["task_id"].(string); strings.TrimSpace(id) != "" {
		out["task_id"] = strings.TrimSpace(id)
	}
	return out
}

func changedTaskResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(ChangedTask)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "tasklist": v.Tasklist}
}

// taskArgs reads tasklist and task_id.
func taskArgs(args map[string]any) (tasklist, taskID string, err error) {
	if tasklist, err = idArgDefault(args, "tasklist", DefaultTasklist); err != nil {
		return "", "", err
	}
	taskID, err = idArg(args, "task_id")
	return tasklist, taskID, err
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) listTasklists(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Tasklists.List().Context(ctx).MaxResults(int64(maxResults))
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list task lists", err); err != nil {
		return connectors.Result{}, err
	}
	out := TasklistsPage{MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]Tasklist, 0, len(list.Items))}
	for _, l := range list.Items {
		if l != nil {
			out.Items = append(out.Items, Tasklist{ID: l.Id, Title: l.Title, Updated: normalizeTimestamp(l.Updated)})
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

func (c *Connector) getTask(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, taskID, err := taskArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	t, err := svc.Tasks.Get(tasklist, taskID).Context(ctx).Do()
	if err := classify("get task", err); err != nil {
		return connectors.Result{}, err
	}
	out := toTask(t, tasklist)
	truncated := false
	fitBody(&out.Notes, &truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: truncated}, nil
}

func (c *Connector) updateTask(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, taskID, err := taskArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	patch := &tasks.Task{}
	changed := false
	if _, ok := call.Args["title"]; ok {
		if patch.Title, err = requiredString(call.Args, "title"); err != nil {
			return connectors.Result{}, invalid("title must not be blank")
		}
		changed = true
	}
	if _, ok := call.Args["notes"]; ok {
		if patch.Notes, err = optionalString(call.Args, "notes"); err != nil {
			return connectors.Result{}, err
		}
		if patch.Notes == "" {
			patch.ForceSendFields = append(patch.ForceSendFields, "Notes")
		}
		changed = true
	}
	if due, _ := call.Args["due"].(string); strings.TrimSpace(due) != "" {
		d, err := time.Parse("2006-01-02", strings.TrimSpace(due))
		if err != nil {
			return connectors.Result{}, invalid("due must be a date (2026-10-10)")
		}
		patch.Due, changed = d.Format("2006-01-02")+"T00:00:00Z", true
	}
	if _, ok := call.Args["status"]; ok {
		status, _ := optionalString(call.Args, "status")
		switch status {
		case TaskCompleted:
		case TaskNeedsAction:
			patch.NullFields = append(patch.NullFields, "Completed")
		default:
			return connectors.Result{}, invalid("status must be needsAction or completed")
		}
		patch.Status, changed = status, true
	}
	if !changed {
		return connectors.Result{}, invalid("nothing to change: give at least one of title, notes, due or status")
	}
	return c.patchTask(ctx, cl, tasklist, taskID, patch, "update task")
}

func (c *Connector) completeTask(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, taskID, err := taskArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	return c.patchTask(ctx, cl, tasklist, taskID, &tasks.Task{Status: TaskCompleted}, "complete task")
}

func (c *Connector) patchTask(ctx context.Context, cl *client, tasklist, taskID string, patch *tasks.Task, action string) (connectors.Result, error) {
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	t, err := svc.Tasks.Patch(tasklist, taskID, patch).Context(ctx).Do()
	if err := classifyWrite(action, err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ChangedTask{ID: taskID, Tasklist: tasklist, Status: t.Status, URL: t.WebViewLink}}, nil
}

func (c *Connector) deleteTask(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, taskID, err := taskArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("delete task", svc.Tasks.Delete(tasklist, taskID).Context(ctx).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ChangedTask{ID: taskID, Tasklist: tasklist, Deleted: true}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// taskTarget fetches the task the resource identity names; a 404 or 410
// is gone.
func (c *Connector) taskTarget(ctx context.Context, in connectors.ReconcileInput) (t *tasks.Task, gone bool, err error) {
	tg, err := c.target(in)
	if err != nil {
		return nil, false, err
	}
	tasklist, taskID := strings.TrimSpace(in.ResourceIdentity["tasklist"]), strings.TrimSpace(in.ResourceIdentity["task_id"])
	if tasklist == "" || taskID == "" || !idRE.MatchString(tasklist) || !idRE.MatchString(taskID) {
		return nil, false, fmt.Errorf("%w: resource identity has no tasklist or task", ErrNotReconcilable)
	}
	svc, err := tg.client.tasks(ctx)
	if err != nil {
		return nil, false, err
	}
	t, err = svc.Tasks.Get(tasklist, taskID).Context(ctx).Do()
	if err := classify("reconcile: get task", err); err != nil {
		if s := statusOf(err); s == http.StatusNotFound || s == http.StatusGone {
			return nil, true, nil
		}
		return nil, false, err
	}
	return t, false, nil
}

// checkTaskCompleted: status completed is found, another status
// not_found, the task gone cannot tell.
func (c *Connector) checkTaskCompleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	t, gone, err := c.taskTarget(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the task is gone; cannot tell whether it was completed")
	}
	if t.Status == TaskCompleted {
		return found(in.ResourceIdentity["task_id"]), nil
	}
	return notFound, nil
}

// checkTaskDeleted: gone (404, 410) or marked deleted is found; present
// is not_found.
func (c *Connector) checkTaskDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	t, gone, err := c.taskTarget(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone || t.Deleted {
		return found(in.ResourceIdentity["task_id"]), nil
	}
	return notFound, nil
}
