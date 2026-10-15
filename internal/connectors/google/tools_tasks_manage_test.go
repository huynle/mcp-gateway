package google_test

import (
	"context"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Tasks management (list_tasklists, get, update, complete, delete) and
// Contacts reads (get, list).

const (
	tasklistsPath = "GET /tasks/v1/users/@me/lists"
	task1Path     = "/tasks/v1/lists/@default/tasks/task_001"
	personPath    = "GET /v1/people/c1234567890"
	connsPath     = "GET /v1/people/me/connections"
)

func TestTasksManageDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "tasks.list_tasklists", r, []string{google.ScopeTasksReadonly}, "")
	declared(t, c, "tasks.get", r, []string{google.ScopeTasksReadonly}, "")
	declared(t, c, "tasks.update", w, []string{google.ScopeTasks}, connectors.ReconcileNone)
	declared(t, c, "tasks.complete", w, []string{google.ScopeTasks}, connectors.ReconcileStableID)
	declared(t, c, "tasks.delete", w, []string{google.ScopeTasks}, connectors.ReconcileStableID)
	declared(t, c, "contacts.get", r, []string{google.ScopeContactsReadonly}, "")
	declared(t, c, "contacts.list", r, []string{google.ScopeContactsReadonly}, "")
	id := toolOf(t, c, "tasks.update").ResourceIdentity(map[string]any{"task_id": "task_001", "title": "secret"})
	if id["tasklist"] != "@default" || id["task_id"] != "task_001" || len(id) != 2 {
		t.Errorf("tasks.update identity = %v", id)
	}
	if id := toolOf(t, c, "contacts.get").ResourceIdentity(map[string]any{"resource_name": "people/c1"}); id["resource_name"] != "people/c1" {
		t.Errorf("contacts.get identity = %v", id)
	}
}

func TestListTasklists(t *testing.T) {
	srv := newAPIServer(t, map[string]route{tasklistsPath: {status: 200, body: "tasklists.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("tasks.list_tasklists", map[string]any{"max_results": 10}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Items   []struct{ ID, Title, Updated string } `json:"items"`
		HasMore bool                                  `json:"has_more"`
	}
	decode(t, res, &out)
	if len(out.Items) != 2 || out.Items[1].ID != "QkFDS0xPRw" || out.Items[0].Updated != "2026-10-07T18:00:00Z" || !out.HasMore {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/tasks/v1/users/@me/lists"); q.Get("maxResults") != "10" {
		t.Errorf("query = %v", q)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{tasklistsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("tasks.list_tasklists", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestGetTask(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + task1Path: {status: 200, body: "task.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("tasks.get", map[string]any{"task_id": "task_001"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ ID, Title, Due, Status string }
	decode(t, res, &out)
	if out.ID != "task_001" || out.Due != "2026-10-10" || out.Status != "needsAction" {
		t.Errorf("out = %+v", out)
	}
	_, err = run(t, c, call("tasks.get", nil))
	wantClass(t, err, google.ClassInvalidArgument, 0)
}

func TestUpdateTask(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"PATCH " + task1Path: {status: 200, body: "task.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("tasks.update", map[string]any{"task_id": "task_001", "title": "Write it", "notes": "", "due": "2026-10-12"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "tasks.update").ResultIDs(res); ids["id"] != "task_001" {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := bodyOf(t, srv.Last(t, "PATCH "+task1Path))
	if body["title"] != "Write it" || body["notes"] != "" || body["due"] != "2026-10-12T00:00:00Z" {
		t.Errorf("patch body = %v", body)
	}
	if _, ok := body["status"]; ok {
		t.Errorf("status sent although not given: %v", body)
	}
	for _, args := range []map[string]any{
		{"task_id": "task_001"},
		{"title": "x"},
		{"task_id": "task_001", "due": "soon"},
		{"task_id": "task_001", "status": "done"},
		{"task_id": "task_001", "title": " "},
	} {
		_, err := run(t, c, write("tasks.update", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases("task.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"PATCH " + task1Path: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("tasks.update", map[string]any{"task_id": "task_001", "status": "needsAction"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestCompleteTask(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"PATCH " + task1Path: {status: 200, body: "task_completed.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("tasks.complete", map[string]any{"task_id": "task_001"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ ID, Status string }
	decode(t, res, &out)
	if out.ID != "task_001" || out.Status != "completed" {
		t.Errorf("out = %+v", out)
	}
	if body := bodyOf(t, srv.Last(t, "PATCH "+task1Path)); body["status"] != "completed" {
		t.Errorf("body = %v", body)
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"completed": {route{status: 200, body: "task_completed.json"}, "found"},
		"open":      {route{status: 200, body: "task.json"}, "not_found"},
		"404":       {route{status: 404, body: "error_not_found.json"}, "cannot"},
		"500":       {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + task1Path: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "tasks.complete", map[string]any{"task_id": "task_001"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "task_001")
		})
	}
}

func TestDeleteTask(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"DELETE " + task1Path: {status: 204, body: ""}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("tasks.delete", map[string]any{"task_id": "task_001"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "tasks.delete").ResultIDs(res); ids["id"] != "task_001" {
		t.Errorf("ResultIDs = %v", ids)
	}
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"DELETE " + task1Path: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("tasks.delete", map[string]any{"task_id": "task_001"}))
			checkWriteError(t, tc, res, err)
		})
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"404":     {route{status: 404, body: "error_not_found.json"}, "found"},
		"deleted": {route{status: 200, body: "task_deleted.json"}, "found"},
		"present": {route{status: 200, body: "task.json"}, "not_found"},
		"500":     {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + task1Path: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "tasks.delete", map[string]any{"task_id": "task_001"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "task_001")
		})
	}
}

func TestContactsGetAndList(t *testing.T) {
	srv := newAPIServer(t, map[string]route{personPath: {status: 200, body: "person.json"}, connsPath: {status: 200, body: "connections.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("contacts.get", map[string]any{"resource_name": "people/c1234567890"}))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		ResourceName string   `json:"resource_name"`
		Name         string   `json:"name"`
		Emails       []string `json:"emails"`
		Phones       []string `json:"phones"`
		Organization string   `json:"organization"`
	}
	decode(t, res, &p)
	if p.ResourceName != "people/c1234567890" || p.Name != "Bob Example" || len(p.Emails) != 2 || len(p.Phones) != 1 || p.Organization != "Example Corp" {
		t.Errorf("person = %+v", p)
	}
	if q := query(t, srv, "/v1/people/c1234567890"); q.Get("personFields") == "" {
		t.Errorf("personFields missing: %v", q)
	}
	for _, bad := range []string{"c123", "people/../x", "people/c 1"} {
		_, err := run(t, c, call("contacts.get", map[string]any{"resource_name": bad}))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}

	res, err = run(t, c, call("contacts.list", map[string]any{"max_results": 2}))
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Items         []struct{ Name string } `json:"items"`
		NextPageToken string                  `json:"next_page_token"`
		HasMore       bool                    `json:"has_more"`
		Total         int                     `json:"total"`
	}
	decode(t, res, &page)
	if len(page.Items) != 2 || !page.HasMore || page.NextPageToken != "conn-2" || page.Total != 7 {
		t.Errorf("page = %+v", page)
	}
	q := query(t, srv, "/v1/people/me/connections")
	if q.Get("pageSize") != "2" || q.Get("personFields") != "names,emailAddresses,organizations" {
		t.Errorf("query = %v", q)
	}
}
