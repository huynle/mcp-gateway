package google_test

import (
	"context"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: the full Tasks API (task lists, moving tasks and
// subtasks, clearing completed tasks).

const (
	createTasklistPath = "POST /tasks/v1/users/@me/lists"
	backlogListPath    = "/tasks/v1/users/@me/lists/QkFDS0xPRw"
	moveTaskPath       = "POST /tasks/v1/lists/@default/tasks/task_001/move"
	clearTasksPath     = "POST /tasks/v1/lists/@default/clear"
	defaultTasksGet    = "GET /tasks/v1/lists/@default/tasks"
	scopeTasks         = "https://www.googleapis.com/auth/tasks"
)

func TestTasksFullDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	w := connectors.KindWrite
	declared(t, c, "tasks.create_tasklist", w, []string{scopeTasks}, connectors.ReconcileNone)
	declared(t, c, "tasks.update_tasklist", w, []string{scopeTasks}, connectors.ReconcileNone)
	declared(t, c, "tasks.delete_tasklist", w, []string{scopeTasks}, connectors.ReconcileStableID)
	declared(t, c, "tasks.move", w, []string{scopeTasks}, connectors.ReconcileStableID)
	declared(t, c, "tasks.clear_completed", w, []string{scopeTasks}, connectors.ReconcileStableID)
	if id := toolOf(t, c, "tasks.create_tasklist").ResourceIdentity(map[string]any{"title": "Secret"}); len(id) != 0 {
		t.Errorf("create_tasklist identity = %v", id)
	}
	if id := toolOf(t, c, "tasks.update_tasklist").ResourceIdentity(map[string]any{"tasklist": "QkFDS0xPRw", "title": "Secret"}); len(id) != 1 || id["tasklist"] != "QkFDS0xPRw" {
		t.Errorf("update_tasklist identity = %v", id)
	}
	id := toolOf(t, c, "tasks.move").ResourceIdentity(map[string]any{"task_id": "task_001", "parent": "task_000", "destination_tasklist": "QkFDS0xPRw"})
	if id["tasklist"] != "@default" || id["task_id"] != "task_001" || id["parent"] != "task_000" || id["destination_tasklist"] != "QkFDS0xPRw" {
		t.Errorf("move identity = %v", id)
	}
}

func TestTasklistWrites(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		createTasklistPath:          {status: 200, body: "tasklist.json"},
		"PATCH " + backlogListPath:  {status: 200, body: "tasklist.json"},
		"DELETE " + backlogListPath: {status: 204, body: ""},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("tasks.create_tasklist", map[string]any{"title": "Groceries"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "tasks.create_tasklist").ResultIDs(res); ids["id"] != "TkVXTElTVA" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if b := bodyOf(t, srv.Last(t, createTasklistPath)); b["title"] != "Groceries" {
		t.Errorf("body = %v", b)
	}
	if _, err := run(t, c, write("tasks.update_tasklist", map[string]any{"tasklist": "QkFDS0xPRw", "title": "Later"})); err != nil {
		t.Fatal(err)
	}
	if b := bodyOf(t, srv.Last(t, "PATCH "+backlogListPath)); b["title"] != "Later" {
		t.Errorf("patch body = %v", b)
	}
	res, err = run(t, c, write("tasks.delete_tasklist", map[string]any{"tasklist": "QkFDS0xPRw"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "tasks.delete_tasklist").ResultIDs(res); ids["id"] != "QkFDS0xPRw" {
		t.Errorf("ResultIDs = %v", ids)
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"tasks.create_tasklist", map[string]any{}},
		{"tasks.create_tasklist", map[string]any{"title": " "}},
		{"tasks.update_tasklist", map[string]any{"tasklist": "QkFDS0xPRw"}},
		{"tasks.update_tasklist", map[string]any{"title": "x"}},
		{"tasks.delete_tasklist", map[string]any{}},
		{"tasks.delete_tasklist", map[string]any{"tasklist": "@default"}},
		{"tasks.delete_tasklist", map[string]any{"tasklist": "a/b"}},
	} {
		_, err := run(t, c, write(tc.tool, tc.args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"404":     {route{status: 404, body: "error_not_found.json"}, "found"},
		"present": {route{status: 200, body: "tasklist.json"}, "not_found"},
		"500":     {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + backlogListPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "tasks.delete_tasklist", map[string]any{"tasklist": "QkFDS0xPRw"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "QkFDS0xPRw")
		})
	}
}

func TestMoveTask(t *testing.T) {
	srv := newAPIServer(t, map[string]route{moveTaskPath: {status: 200, body: "task_moved.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("tasks.move", map[string]any{"task_id": "task_001", "parent": "task_000", "previous": "task_002"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID, Tasklist, Parent, Position string
	}
	decode(t, res, &out)
	if out.ID != "task_001" || out.Tasklist != "@default" || out.Parent != "task_000" || out.Position == "" {
		t.Errorf("out = %+v", out)
	}
	q := query(t, srv, "/tasks/v1/lists/@default/tasks/task_001/move")
	if q.Get("parent") != "task_000" || q.Get("previous") != "task_002" || q.Has("destinationTasklist") {
		t.Errorf("query = %v", q)
	}
	if _, err := run(t, c, write("tasks.move", map[string]any{"task_id": "task_001", "destination_tasklist": "QkFDS0xPRw"})); err != nil {
		t.Fatal(err)
	}
	if q := query(t, srv, "/tasks/v1/lists/@default/tasks/task_001/move"); q.Get("destinationTasklist") != "QkFDS0xPRw" {
		t.Errorf("query = %v", q)
	}
	for _, args := range []map[string]any{{}, {"task_id": "task_001", "parent": "task_001"}, {"task_id": "task_001", "previous": "a/b"}} {
		_, err := run(t, c, write("tasks.move", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	cross := map[string]any{"task_id": "task_001", "destination_tasklist": "QkFDS0xPRw"}
	destGet := "GET /tasks/v1/lists/QkFDS0xPRw/tasks/task_001"
	srcGet := "GET /tasks/v1/lists/@default/tasks/task_001"
	for name, tc := range map[string]struct {
		args      map[string]any
		dest, src route
		want      string
	}{
		"in destination":  {cross, route{status: 200, body: "task.json"}, route{status: 404, body: "error_not_found.json"}, "found"},
		"still in source": {cross, route{status: 404, body: "error_not_found.json"}, route{status: 200, body: "task.json"}, "not_found"},
		"in neither":      {cross, route{status: 404, body: "error_not_found.json"}, route{status: 404, body: "error_not_found.json"}, "cannot"},
		"dest 500":        {cross, route{status: 500, body: "error_server.json"}, route{status: 200, body: "task.json"}, "cannot"},
		"same list":       {map[string]any{"task_id": "task_001", "parent": "task_000"}, route{}, route{status: 200, body: "task_moved.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{destGet: tc.dest, srcGet: tc.src})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "tasks.move", tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "task_001")
		})
	}
}

func TestClearCompletedTasks(t *testing.T) {
	srv := newAPIServer(t, map[string]route{clearTasksPath: {status: 204, body: ""}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("tasks.clear_completed", nil))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "tasks.clear_completed").ResultIDs(res); ids["id"] != "@default" {
		t.Errorf("ResultIDs = %v", ids)
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"none visible":      {route{status: 200, body: "tasks_open_only.json"}, "found"},
		"completed visible": {route{status: 200, body: "tasks_completed_visible.json"}, "cannot"},
		"500":               {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{defaultTasksGet: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "tasks.clear_completed", nil)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "@default")
			if tc.want == "found" {
				if q := query(t, srv, "/tasks/v1/lists/@default/tasks"); q.Get("showCompleted") != "true" || q.Get("showHidden") != "false" {
					t.Errorf("query = %v", q)
				}
			}
		})
	}
}

func TestCreateSubtask(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createTaskPath: {status: 200, body: "created_task.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	if _, err := run(t, c, write("tasks.create", map[string]any{"title": "Sub", "parent": "task_001", "previous": "task_002"})); err != nil {
		t.Fatal(err)
	}
	q := query(t, srv, "/tasks/v1/lists/@default/tasks")
	if q.Get("parent") != "task_001" || q.Get("previous") != "task_002" {
		t.Errorf("query = %v", q)
	}
	_, err := run(t, c, write("tasks.create", map[string]any{"title": "Sub", "parent": "a b"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
}

func TestTasksFullWriteErrors(t *testing.T) {
	for _, w := range []struct {
		tool, path, okBody string
		args               map[string]any
	}{
		{"tasks.create_tasklist", createTasklistPath, "tasklist.json", map[string]any{"title": "x"}},
		{"tasks.update_tasklist", "PATCH " + backlogListPath, "tasklist.json", map[string]any{"tasklist": "QkFDS0xPRw", "title": "x"}},
		{"tasks.delete_tasklist", "DELETE " + backlogListPath, "", map[string]any{"tasklist": "QkFDS0xPRw"}},
		{"tasks.move", moveTaskPath, "task_moved.json", map[string]any{"task_id": "task_001"}},
		{"tasks.clear_completed", clearTasksPath, "", nil},
	} {
		for _, tc := range writeErrorCases(w.okBody) {
			t.Run(w.tool+" "+tc.name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{w.path: tc.rt})
				res, err := run(t, shortTimeout(t, srv), write(w.tool, w.args))
				checkWriteError(t, tc, res, err)
			})
		}
	}
}
