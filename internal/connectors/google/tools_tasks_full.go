package google

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/tasks/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Increment 5 (Brain decision 9jfy0gb8): the rest of the Tasks API:
// task lists (create, rename, delete), moving a task (reorder, make it a
// subtask, move it to another list) and clearing completed tasks.
// Subtasks are created with tasks.create's parent. Every new write
// defaults to Ask (migration 00037).

// Tasks tool names (increment 5).
const (
	ToolCreateTasklist = "create_tasklist"
	ToolUpdateTasklist = "update_tasklist"
	ToolDeleteTasklist = "delete_tasklist"
	ToolMoveTask       = "move"
	ToolClearCompleted = "clear_completed"
)

// TasklistChange is the result of the task-list writes and
// clear_completed.
type TasklistChange struct {
	ID      string `json:"id"`
	Updated string `json:"updated,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
	Cleared bool   `json:"cleared,omitempty"`
}

// MovedTask is tasks.move's result.
type MovedTask struct {
	ID       string `json:"id"`
	Tasklist string `json:"tasklist"`
	Parent   string `json:"parent,omitempty"`
	Position string `json:"position,omitempty"`
	URL      string `json:"url,omitempty"`
}

func tasklistChangeResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(TasklistChange)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID}
}

func movedTaskResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(MovedTask)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "tasklist": v.Tasklist}
}

// subtaskProperties are tasks.create's parent and previous.
var subtaskProperties = []property{
	{"parent", "string", "Id of the task to nest this one under (a subtask); top level when omitted.", nil},
	{"previous", "string", "Id of the sibling task to place this one after; first among its siblings when omitted.", nil},
}

func (c *Connector) tasksFullWriteTools() []connectors.Tool {
	tool := func(name, description string, props []property, required []string, identity func(map[string]any) map[string]string,
		rec connectors.Reconciliation, ids func(connectors.Result) map[string]string) connectors.Tool {
		return connectors.Tool{
			App: AppTasks, Name: name, Kind: connectors.KindWrite, Description: description,
			InputSchema: objectSchema(props, required), RequiredScopes: []string{ScopeTasks}, ResourceIdentity: identity,
			Reconcile: rec, ResultIDs: ids, Bounds: c.singleBounds(),
		}
	}
	listProp := property{"tasklist", "string", "The task list's id (from list_tasklists).", nil}
	return []connectors.Tool{
		tool(ToolCreateTasklist,
			"Create a Google Tasks list with a title. Returns its id (use it as tasklist). Cannot be verified after an unknown "+
				"outcome (Google picks the id; a list has no hidden field): check list_tasklists before retrying.",
			[]property{{"title", "string", "The list's title.", nil}}, []string{"title"},
			func(map[string]any) map[string]string { return map[string]string{} },
			connectors.Reconciliation{Kind: connectors.ReconcileNone}, tasklistChangeResultIDs),
		tool(ToolUpdateTasklist, "Rename a Google Tasks list.",
			[]property{listProp, {"title", "string", "The new title.", nil}}, []string{"tasklist", "title"}, tasksIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileNone}, tasklistChangeResultIDs),
		tool(ToolDeleteTasklist,
			"Delete a Google Tasks list with all its tasks. The default list cannot be deleted.",
			[]property{listProp}, []string{"tasklist"}, tasksIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkTasklistDeleted}, tasklistChangeResultIDs),
		tool(ToolMoveTask,
			"Move a task: under another task (parent: it becomes a subtask), after a sibling (previous), to the top level "+
				"(no parent), or to another list (destination_tasklist; with its subtasks). Without parent and previous the task "+
				"goes first in its level. Returns the task's id, list, parent and position.",
			append([]property{tasklistProperty, taskIDProperty,
				{"destination_tasklist", "string", "Id of the list to move the task to; the same list when omitted.", nil}},
				subtaskProperties...),
			[]string{"task_id"}, moveTaskIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkTaskMoved}, movedTaskResultIDs),
		tool(ToolClearCompleted,
			"Clear the completed tasks of a list: Google hides them (they stay readable with show_completed and can be reopened).",
			[]property{tasklistProperty}, nil, tasksIdentity,
			connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkTasksCleared}, tasklistChangeResultIDs),
	}
}

func (c *Connector) tasksFullWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolCreateTasklist: c.createTasklist, ToolUpdateTasklist: c.updateTasklist, ToolDeleteTasklist: c.deleteTasklist,
		ToolMoveTask: c.moveTask, ToolClearCompleted: c.clearCompleted,
	}
}

// moveTaskIdentity is taskIdentity plus parent, previous and
// destination_tasklist (ids) when given.
func moveTaskIdentity(args map[string]any) map[string]string {
	out := taskIdentity(args)
	for _, k := range []string{"parent", "previous", "destination_tasklist"} {
		if v, _ := args[k].(string); idRE.MatchString(strings.TrimSpace(v)) {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// subtaskArgs reads parent and previous (optional ids).
func subtaskArgs(args map[string]any) (parent, previous string, err error) {
	if parent, err = idArgDefault(args, "parent", ""); err != nil {
		return "", "", err
	}
	previous, err = idArgDefault(args, "previous", "")
	return parent, previous, err
}

// --- handlers -------------------------------------------------------------------------

func (c *Connector) createTasklist(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Tasklists.Insert(&tasks.TaskList{Title: title}).Context(ctx).Do()
	if err := classifyWrite("create task list", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: TasklistChange{ID: created.Id, Updated: normalizeTimestamp(created.Updated)}}, nil
}

func (c *Connector) updateTasklist(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, err := idArg(call.Args, "tasklist")
	if err != nil {
		return connectors.Result{}, err
	}
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	updated, err := svc.Tasklists.Patch(tasklist, &tasks.TaskList{Title: title}).Context(ctx).Do()
	if err := classifyWrite("rename task list", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: TasklistChange{ID: tasklist, Updated: normalizeTimestamp(updated.Updated)}}, nil
}

func (c *Connector) deleteTasklist(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, err := idArg(call.Args, "tasklist")
	if err != nil {
		return connectors.Result{}, err
	}
	if tasklist == DefaultTasklist {
		return connectors.Result{}, invalid("the default task list cannot be deleted")
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("delete task list", svc.Tasklists.Delete(tasklist).Context(ctx).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: TasklistChange{ID: tasklist, Deleted: true}}, nil
}

func (c *Connector) moveTask(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, taskID, err := taskArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	parent, previous, err := subtaskArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if parent == taskID || previous == taskID {
		return connectors.Result{}, invalid("a task cannot be its own parent or previous sibling")
	}
	destination, err := idArgDefault(call.Args, "destination_tasklist", "")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Tasks.Move(tasklist, taskID).Context(ctx)
	if parent != "" {
		req = req.Parent(parent)
	}
	if previous != "" {
		req = req.Previous(previous)
	}
	in := tasklist
	if destination != "" && destination != tasklist {
		req, in = req.DestinationTasklist(destination), destination
	}
	moved, err := req.Do()
	if err := classifyWrite("move task", err); err != nil {
		return connectors.Result{}, err
	}
	id := moved.Id
	if id == "" {
		id = taskID
	}
	return connectors.Result{Content: MovedTask{ID: id, Tasklist: in, Parent: moved.Parent, Position: moved.Position, URL: moved.WebViewLink}}, nil
}

func (c *Connector) clearCompleted(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, err := idArgDefault(call.Args, "tasklist", DefaultTasklist)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("clear completed tasks", svc.Tasks.Clear(tasklist).Context(ctx).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: TasklistChange{ID: tasklist, Cleared: true}}, nil
}

// --- reconciliation ------------------------------------------------------------------

// identityTasklist reads a task-list id the identity holds under key.
func identityTasklist(in connectors.ReconcileInput, key string) (string, error) {
	id := strings.TrimSpace(in.ResourceIdentity[key])
	if id == "" || !idRE.MatchString(id) {
		return "", fmt.Errorf("%w: resource identity has no %s", ErrNotReconcilable, key)
	}
	return id, nil
}

// checkTasklistDeleted: tasklists.get 404/410 is found; present is
// not_found.
func (c *Connector) checkTasklistDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tasklist, err := identityTasklist(in, "tasklist")
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.tasks(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	_, err = svc.Tasklists.Get(tasklist).Context(ctx).Do()
	if err := classify("reconcile: get task list", err); err != nil {
		if isGone(err) {
			return found(tasklist), nil
		}
		return connectors.ReconcileResult{}, err
	}
	return notFound, nil
}

// checkTaskMoved: a move to another list is found when the task is in
// the destination, not_found when it is still in the source only, and
// "cannot tell" when it is in neither (Google may have given it a new
// id). A move within a list (reorder, new parent) leaves nothing that
// tells it from the state before, so it is always "cannot tell" (the
// operation ends unresolved).
func (c *Connector) checkTaskMoved(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	source, err := identityTasklist(in, "tasklist")
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	taskID, err := identityTasklist(in, "task_id")
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	destination := strings.TrimSpace(in.ResourceIdentity["destination_tasklist"])
	if destination == "" || destination == source {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: a move within a list leaves no trace to check; cannot tell")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.tasks(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	_, err = svc.Tasks.Get(destination, taskID).Context(ctx).Do()
	if err := classify("reconcile: get task in the destination", err); err == nil {
		return found(taskID), nil
	} else if !isGone(err) {
		return connectors.ReconcileResult{}, err
	}
	_, err = svc.Tasks.Get(source, taskID).Context(ctx).Do()
	if err := classify("reconcile: get task in the source", err); err != nil {
		if isGone(err) {
			return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the task is in neither list; cannot tell")
		}
		return connectors.ReconcileResult{}, err
	}
	return notFound, nil
}

// checkTasksCleared: no completed task left visible (hidden ones are
// cleared) is found; one still visible may have been completed after the
// clear, so it is "cannot tell", like running out of pages.
func (c *Connector) checkTasksCleared(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tasklist, err := identityTasklist(in, "tasklist")
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.tasks(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	pageToken := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		req := svc.Tasks.List(tasklist).Context(ctx).ShowCompleted(true).ShowHidden(false).MaxResults(reconcilePerPage)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		list, err := req.Do()
		if err := classify("reconcile: list tasks", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, t := range list.Items {
			if t != nil && t.Status == TaskCompleted && !t.Hidden {
				return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: a completed task is still visible (perhaps completed since); cannot tell")
			}
		}
		if pageToken = list.NextPageToken; pageToken == "" {
			return found(tasklist), nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: more than %d pages of tasks in list %s; cannot tell yet", MaxReconcilePages, tasklist)
}
