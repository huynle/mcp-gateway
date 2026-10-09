package google_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

const listTasksPath = "GET /tasks/v1/lists/@default/tasks"

func TestTasksList(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listTasksPath: {status: 200, body: "tasks_list.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("tasks.list", map[string]any{"show_completed": true, "max_results": 10}))
	if err != nil {
		t.Fatalf("tasks.list: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	q := query(t, srv, "/tasks/v1/lists/@default/tasks")
	for k, want := range map[string]string{"showCompleted": "true", "showHidden": "true", "maxResults": "10"} {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	var page google.TasksPage
	decode(t, res, &page)
	if page.Tasklist != "@default" || !page.HasMore || page.NextPageToken != "tasks-page-two" || len(page.Items) != 2 {
		t.Fatalf("page = %+v", page)
	}
	first, second := page.Items[0], page.Items[1]
	if first.ID != "task_001" || first.Title != "Write the report" || first.Notes != "Due before the offsite." || first.Status != "needsAction" ||
		first.Due != "2026-10-10" || first.Updated != "2026-10-07T18:00:00Z" || first.URL != "https://tasks.google.com/task/task_001" || first.Completed != "" {
		t.Errorf("first = %+v", first)
	}
	if second.ID != "task_002" || second.Status != "completed" || second.Completed != "2026-10-06T12:00:00Z" || second.Parent != "task_001" || !second.Hidden {
		t.Errorf("second = %+v", second)
	}
}

func TestTasksListDefaultsHideCompleted(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /tasks/v1/lists/MTIzNDU/tasks": {status: 200, body: "tasks_list_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("tasks.list", map[string]any{"tasklist": "MTIzNDU", "page_token": "tasks-page-two"}))
	if err != nil {
		t.Fatalf("tasks.list: %v", err)
	}
	if !res.Empty {
		t.Errorf("markers = %+v, want Empty", res)
	}
	q := query(t, srv, "/tasks/v1/lists/MTIzNDU/tasks")
	for k, want := range map[string]string{"showCompleted": "false", "showHidden": "false", "maxResults": "50", "pageToken": "tasks-page-two"} {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	var page google.TasksPage
	decode(t, res, &page)
	if page.Tasklist != "MTIzNDU" || page.HasMore || len(page.Items) != 0 {
		t.Errorf("page = %+v", page)
	}
}

func TestTasksListClampAndTruncate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listTasksPath: {status: 200, body: "tasks_list.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 5, MaxResultBytes: 400})
	res, err := run(t, c, call("tasks.list", map[string]any{"max_results": 99}))
	if err != nil {
		t.Fatal(err)
	}
	var page google.TasksPage
	decode(t, res, &page)
	if !res.Partial || !page.Truncated || len(page.Items) != 1 {
		t.Errorf("res = %+v page = %+v, want clamped+truncated to one item", res, page)
	}
	if got := query(t, srv, "/tasks/v1/lists/@default/tasks").Get("maxResults"); got != "5" {
		t.Errorf("maxResults = %q, want 5", got)
	}
}

func TestTasksListArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"bad tasklist":       {"tasklist": "a/b"},
		"bad show_completed": {"show_completed": "yes"},
		"max_results 0":      {"max_results": 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call("tasks.list", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listTasksPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("tasks.list", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestTasksResourceIdentityAndScopes(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	list := toolOf(t, c, "tasks.list")
	if got := list.ResourceIdentity(map[string]any{}); got["tasklist"] != "@default" || len(got) != 1 {
		t.Errorf("identity(default) = %v", got)
	}
	if got := list.ResourceIdentity(map[string]any{"tasklist": " MTIzNDU "}); got["tasklist"] != "MTIzNDU" {
		t.Errorf("identity = %v", got)
	}
	if list.RequiredScopes[0] != google.ScopeTasksReadonly || list.Kind != connectors.KindRead || list.Bounds.MaxPageSize == 0 {
		t.Errorf("tool = %+v", list)
	}
}
