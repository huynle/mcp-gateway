package microsoft

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Microsoft To Do tools: task lists and tasks (list, create, update,
// complete).
const (
	ToolTodoListLists    = "todo_list_lists"
	ToolTodoListTasks    = "todo_list_tasks"
	ToolTodoCreateTask   = "todo_create_task"
	ToolTodoUpdateTask   = "todo_update_task"
	ToolTodoCompleteTask = "todo_complete_task"
)

var (
	todoStatuses    = []string{"notStarted", "inProgress", "completed", "waitingOnOthers", "deferred"}
	todoImportances = []string{"low", "normal", "high"}
)

// TodoList is one todo_list_lists item.
type TodoList struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	IsOwner     bool   `json:"is_owner"`
	WellKnown   string `json:"well_known,omitempty"`
}

type graphTodoList struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	IsOwner           bool   `json:"isOwner"`
	WellknownListName string `json:"wellknownListName"`
}

// TodoTask is one todo_list_tasks item.
type TodoTask struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Status          string `json:"status"`
	Importance      string `json:"importance,omitempty"`
	Due             string `json:"due,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	CompletedAt     string `json:"completed_at,omitempty"`
	BodyContentType string `json:"body_content_type,omitempty"`
	Body            string `json:"body,omitempty"`
}

type graphTodoTask struct {
	ID                string             `json:"id"`
	Title             string             `json:"title"`
	Status            string             `json:"status"`
	Importance        string             `json:"importance"`
	CreatedDateTime   string             `json:"createdDateTime"`
	DueDateTime       *graphDateTimeZone `json:"dueDateTime"`
	CompletedDateTime *graphDateTimeZone `json:"completedDateTime"`
	Body              *graphBody         `json:"body"`
}

func toTodoTask(g graphTodoTask) TodoTask {
	out := TodoTask{ID: g.ID, Title: g.Title, Status: g.Status, Importance: g.Importance, CreatedAt: g.CreatedDateTime}
	if g.DueDateTime != nil {
		out.Due = g.DueDateTime.DateTime
	}
	if g.CompletedDateTime != nil {
		out.CompletedAt = g.CompletedDateTime.DateTime
	}
	if g.Body != nil {
		out.BodyContentType, out.Body = strings.ToLower(g.Body.ContentType), g.Body.Content
	}
	return out
}

// TaskChange is the result of the To Do writes.
type TaskChange struct {
	ID     string `json:"id"`
	ListID string `json:"list_id"`
	Title  string `json:"title,omitempty"`
	Status string `json:"status,omitempty"`
}

func (c *Connector) todoDefs() []toolDef {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	list := property{"list_id", "string", "The To Do list id (from todo_list_lists).", nil}
	task := property{"task_id", "string", "The task id (from todo_list_tasks).", nil}
	fields := []property{
		{"title", "string", "Task title.", nil},
		{"body", "string", "Notes in plain text.", nil},
		{"due", "string", "Due date, YYYY-MM-DD (or an ISO 8601 timestamp).", nil},
		{"importance", "string", "low, normal or high.", todoImportances},
	}
	taskIdentity := identity("list_id", "list", "task_id", "task")
	none := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	ids := resultIDs("id", "list_id")
	return []toolDef{
		{Tool: connectors.Tool{
			App: App, Name: ToolTodoListLists, Kind: connectors.KindRead,
			Description:      "List the user's Microsoft To Do task lists (id, name, whether the user owns it, the default list).",
			InputSchema:      objectSchema([]property{topProperty}, nil),
			RequiredScopes:   []string{ScopeTasksRead},
			ResourceIdentity: identity(),
			Bounds:           paged,
		}, run: c.todoListLists},
		{Tool: connectors.Tool{
			App: App, Name: ToolTodoListTasks, Kind: connectors.KindRead,
			Description: "List the tasks of a To Do list (title, status, importance, due date, notes); status filters to notStarted, " +
				"inProgress, completed, waitingOnOthers or deferred.",
			InputSchema:      objectSchema([]property{list, {"status", "string", "Only tasks with this status.", todoStatuses}, topProperty}, []string{"list_id"}),
			RequiredScopes:   []string{ScopeTasksRead},
			ResourceIdentity: identity("list_id", "list"),
			Bounds:           paged,
		}, run: c.todoListTasks},
		{Tool: connectors.Tool{
			App: App, Name: ToolTodoCreateTask, Kind: connectors.KindWrite,
			Description: "Create a task in a To Do list: title, optional notes, due date and importance. The outcome of a lost reply cannot " +
				"be verified afterwards.",
			InputSchema:      objectSchema(append([]property{list}, fields...), []string{"list_id", "title"}),
			RequiredScopes:   []string{ScopeTasksReadWrite},
			ResourceIdentity: identity("list_id", "list"),
			Reconcile:        none,
			ResultIDs:        ids,
			Bounds:           single,
		}, run: c.todoCreateTask},
		{Tool: connectors.Tool{
			App: App, Name: ToolTodoUpdateTask, Kind: connectors.KindWrite,
			Description:      "Change a To Do task: any of title, notes, due date, importance and status.",
			InputSchema:      objectSchema(append([]property{list, task, {"status", "string", "New status.", todoStatuses}}, fields...), []string{"list_id", "task_id"}),
			RequiredScopes:   []string{ScopeTasksReadWrite},
			ResourceIdentity: taskIdentity,
			Reconcile:        none,
			ResultIDs:        ids,
			Bounds:           single,
		}, run: c.todoUpdateTask},
		{Tool: connectors.Tool{
			App: App, Name: ToolTodoCompleteTask, Kind: connectors.KindWrite,
			Description:      "Mark a To Do task completed.",
			InputSchema:      objectSchema([]property{list, task}, []string{"list_id", "task_id"}),
			RequiredScopes:   []string{ScopeTasksReadWrite},
			ResourceIdentity: taskIdentity,
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileStableID,
				Check: c.stateCheck("task", identityPath("me/todo/lists/%[2]s/tasks/%[1]s", "list"), "id,status", decideCompleted)},
			ResultIDs: ids,
			Bounds:    single,
		}, run: c.todoCompleteTask},
	}
}

// decideCompleted: the task's status is completed.
func decideCompleted(ident map[string]string, body map[string]any, gone bool) (connectors.ReconcileResult, bool) {
	status, ok := body["status"].(string)
	if gone || !ok {
		return connectors.ReconcileResult{}, false
	}
	if status == "completed" {
		return found(ident["task"]), true
	}
	return notFound, true
}

// enumArg reads an optional argument that must be one of values
// (case-insensitive; Graph's spelling is returned).
func enumArg(args map[string]any, name string, values []string) (string, error) {
	s, err := optionalString(args, name)
	if err != nil {
		return "", err
	}
	if s = strings.TrimSpace(s); s == "" {
		return "", nil
	}
	for _, v := range values {
		if strings.EqualFold(s, v) {
			return v, nil
		}
	}
	return "", invalid("%s must be one of %s", name, strings.Join(values, ", "))
}

// taskFields reads the optional task fields into a Graph patch.
func taskFields(args map[string]any) (map[string]any, error) {
	out := map[string]any{}
	if v, err := optionalString(args, "title"); err != nil {
		return nil, err
	} else if v = strings.TrimSpace(v); v != "" {
		if len(v) > maxSubjectSize {
			return nil, invalid("title is too long")
		}
		out["title"] = v
	}
	if v, err := textArg(args, "body", false); err != nil {
		return nil, err
	} else if strings.TrimSpace(v) != "" {
		out["body"] = map[string]string{"contentType": "text", "content": v}
	}
	if v, err := optionalString(args, "due"); err != nil {
		return nil, err
	} else if v = strings.TrimSpace(v); v != "" {
		due, ok := parseDue(v)
		if !ok {
			return nil, invalid("due must be a date (2026-10-20) or an ISO 8601 timestamp")
		}
		out["dueDateTime"] = eventTime{DateTime: due.UTC().Format("2006-01-02T15:04:05"), TimeZone: "UTC"}
	}
	if v, err := enumArg(args, "importance", todoImportances); err != nil {
		return nil, err
	} else if v != "" {
		out["importance"] = v
	}
	return out, nil
}

// parseDue reads a date or an ISO 8601 timestamp.
func parseDue(v string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (c *Connector) todoListLists(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	return listRead(ctx, c, client, "list To Do lists", "me/todo/lists", url.Values{"$top": {strconv.Itoa(top)}}, nil, top, clamped, func(g graphTodoList) TodoList {
		return TodoList{ID: g.ID, DisplayName: g.DisplayName, IsOwner: g.IsOwner, WellKnown: g.WellknownListName}
	})
}

func (c *Connector) todoListTasks(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	list, err := requiredID(call.Args, "list_id")
	if err != nil {
		return connectors.Result{}, err
	}
	status, err := enumArg(call.Args, "status", todoStatuses)
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	q := url.Values{"$top": {strconv.Itoa(top)}}
	if status != "" {
		q.Set("$filter", "status eq "+graph.Quote(status))
	}
	return listRead(ctx, c, client, "list To Do tasks", "me/todo/lists/"+list+"/tasks", q, nil, top, clamped, toTodoTask)
}

func (c *Connector) todoCreateTask(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	list, err := requiredID(call.Args, "list_id")
	if err != nil {
		return connectors.Result{}, err
	}
	if _, err := requiredString(call.Args, "title"); err != nil {
		return connectors.Result{}, err
	}
	body, err := taskFields(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	var created graphTodoTask
	if _, err := client.Post(ctx, "me/todo/lists/"+list+"/tasks", body, &created); err != nil {
		return connectors.Result{}, classifyWrite("create task", err)
	}
	if created.ID == "" {
		return connectors.Result{}, errNoID("create task", "task")
	}
	return connectors.Result{Content: TaskChange{ID: created.ID, ListID: list, Title: created.Title, Status: created.Status}}, nil
}

// patchTask PATCHes a task and reports the change.
func patchTask(ctx context.Context, client *graph.Client, call connectors.Call, patch map[string]any, action string) (connectors.Result, error) {
	list, err := requiredID(call.Args, "list_id")
	if err != nil {
		return connectors.Result{}, err
	}
	task, err := requiredID(call.Args, "task_id")
	if err != nil {
		return connectors.Result{}, err
	}
	var updated graphTodoTask
	if err := client.Patch(ctx, "me/todo/lists/"+list+"/tasks/"+task, patch, &updated); err != nil {
		return connectors.Result{}, classifyWrite(action, err)
	}
	return connectors.Result{Content: TaskChange{ID: task, ListID: list, Title: updated.Title, Status: updated.Status}}, nil
}

func (c *Connector) todoUpdateTask(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	patch, err := taskFields(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	status, err := enumArg(call.Args, "status", todoStatuses)
	if err != nil {
		return connectors.Result{}, err
	}
	if status != "" {
		patch["status"] = status
	}
	if len(patch) == 0 {
		return connectors.Result{}, invalid("nothing to change: give title, body, due, importance or status")
	}
	return patchTask(ctx, client, call, patch, "update task")
}

func (c *Connector) todoCompleteTask(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	return patchTask(ctx, client, call, map[string]any{"status": "completed"}, "complete task")
}
