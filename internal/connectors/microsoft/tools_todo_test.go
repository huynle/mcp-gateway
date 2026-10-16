package microsoft_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

func TestTodoAndPeopleToolsMetadata(t *testing.T) {
	r, w := connectors.KindRead, connectors.KindWrite
	checkMeta(t, []toolMeta{
		{tool: "todo_list_lists", kind: r, scopes: []string{"Tasks.Read"}, identity: map[string]string{}},
		{tool: "todo_list_tasks", kind: r, scopes: []string{"Tasks.Read"}, required: []string{"list_id"},
			args: map[string]any{"list_id": "l-1"}, identity: map[string]string{"list": "l-1"}},
		{tool: "todo_create_task", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"Tasks.ReadWrite"}, required: []string{"list_id", "title"},
			args: map[string]any{"list_id": "l-1", "title": "secret"}, identity: map[string]string{"list": "l-1"}},
		{tool: "todo_update_task", kind: w, reconcile: connectors.ReconcileNone, scopes: []string{"Tasks.ReadWrite"}, required: []string{"list_id", "task_id"},
			args: map[string]any{"list_id": "l-1", "task_id": "t-1", "title": "secret"}, identity: map[string]string{"list": "l-1", "task": "t-1"}},
		{tool: "todo_complete_task", kind: w, reconcile: connectors.ReconcileStableID, scopes: []string{"Tasks.ReadWrite"}, required: []string{"list_id", "task_id"},
			args: map[string]any{"list_id": "l-1", "task_id": "t-1"}, identity: map[string]string{"list": "l-1", "task": "t-1"}},
		{tool: "contacts_search", kind: r, scopes: []string{"Contacts.Read"}, args: map[string]any{"q": "secret"}, identity: map[string]string{}},
		{tool: "people_search", kind: r, scopes: []string{"People.Read"}, args: map[string]any{"q": "secret"}, identity: map[string]string{}},
		{tool: "users_search", kind: r, scopes: []string{"User.ReadBasic.All"}, required: []string{"q"}, args: map[string]any{"q": "secret"}, identity: map[string]string{}},
	})
}

func TestTodoReads(t *testing.T) {
	_, res := mustRun(t, map[string]route{"GET /v1.0/me/todo/lists": {status: 200, body: `{"value":[{"id":"l-1","displayName":"Tasks","isOwner":true,"wellknownListName":"defaultList"}]}`}},
		"todo_list_lists", nil, false)
	var lists struct {
		Items []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"items"`
	}
	decode(t, res, &lists)
	if len(lists.Items) != 1 || lists.Items[0].DisplayName != "Tasks" {
		t.Errorf("lists = %+v", lists)
	}
	srv, res := mustRun(t, map[string]route{"GET /v1.0/me/todo/lists/l-1/tasks": {status: 200, body: `{"value":[{"id":"t-1","title":"Ship","status":"notStarted","importance":"high",
		"dueDateTime":{"dateTime":"2026-10-20T00:00:00.0000000","timeZone":"UTC"},"body":{"contentType":"text","content":"notes"}}]}`}},
		"todo_list_tasks", map[string]any{"list_id": "l-1", "status": "notStarted"}, false)
	var tasks struct {
		Items []struct {
			ID, Title, Status, Importance, Due, Body string
		} `json:"items"`
	}
	decode(t, res, &tasks)
	if len(tasks.Items) != 1 || tasks.Items[0].Due != "2026-10-20T00:00:00.0000000" || tasks.Items[0].Body != "notes" {
		t.Errorf("tasks = %+v", tasks)
	}
	if f := query(t, srv, "/v1.0/me/todo/lists/l-1/tasks").Get("$filter"); f != "status eq 'notStarted'" {
		t.Errorf("$filter = %q", f)
	}
	wantInvalid(t, "todo_list_tasks", map[string]any{"list_id": "l-1", "status": "done'"}, false)
}

func TestTodoWrites(t *testing.T) {
	create := "POST /v1.0/me/todo/lists/l-1/tasks"
	srv, res := mustRun(t, map[string]route{create: {status: 201, body: `{"id":"t-new","title":"Ship"}`}},
		"todo_create_task", map[string]any{"list_id": "l-1", "title": "Ship", "due": "2026-10-20", "importance": "high", "body": "notes"}, true)
	b := jsonBody(t, srv.Last(t, create))
	due, _ := b["dueDateTime"].(map[string]any)
	if b["title"] != "Ship" || b["importance"] != "high" || due["dateTime"] != "2026-10-20T00:00:00" || due["timeZone"] != "UTC" {
		t.Errorf("create body = %v", b)
	}
	if ids := toolNamed(t, mustConnector(t), "todo_create_task").ResultIDs(res); ids["id"] != "t-new" {
		t.Errorf("ResultIDs = %v", ids)
	}
	wantInvalid(t, "todo_create_task", map[string]any{"list_id": "l-1", "title": "x", "importance": "urgent"}, true)
	wantInvalid(t, "todo_create_task", map[string]any{"list_id": "l-1", "title": "x", "due": "tomorrow"}, true)

	task := "PATCH /v1.0/me/todo/lists/l-1/tasks/t-1"
	srv, _ = mustRun(t, map[string]route{task: {status: 200, body: `{"id":"t-1"}`}}, "todo_update_task", map[string]any{"list_id": "l-1", "task_id": "t-1", "status": "inProgress"}, true)
	if b := jsonBody(t, srv.Last(t, task)); b["status"] != "inProgress" || len(b) != 1 {
		t.Errorf("update body = %v", b)
	}
	wantInvalid(t, "todo_update_task", map[string]any{"list_id": "l-1", "task_id": "t-1"}, true)

	srv, _ = mustRun(t, map[string]route{task: {status: 200, body: `{"id":"t-1","status":"completed"}`}}, "todo_complete_task", map[string]any{"list_id": "l-1", "task_id": "t-1"}, true)
	if b := jsonBody(t, srv.Last(t, task)); b["status"] != "completed" {
		t.Errorf("complete body = %v", b)
	}
	get := "GET /v1.0/me/todo/lists/l-1/tasks/t-1"
	got, err := check(t, map[string]route{get: {status: 200, body: `{"id":"t-1","status":"completed"}`}}, "todo_complete_task", map[string]string{"list": "l-1", "task": "t-1"})
	wantFound(t, got, err, "t-1")
	got, err = check(t, map[string]route{get: {status: 200, body: `{"id":"t-1","status":"notStarted"}`}}, "todo_complete_task", map[string]string{"list": "l-1", "task": "t-1"})
	wantNotFound(t, got, err)
	if _, err := check(t, nil, "todo_complete_task", map[string]string{"task": "t-1"}); err == nil {
		t.Error("check without the list must fail")
	}
	runWriteErrorCases(t, task, route{status: 200, body: `{"id":"t-1"}`}, "todo_complete_task", map[string]any{"list_id": "l-1", "task_id": "t-1"})
}

func TestContactsPeopleUsers(t *testing.T) {
	srv, res := mustRun(t, map[string]route{"GET /v1.0/me/contacts": {status: 200, body: `{"value":[{"id":"c-1","displayName":"Bob Example",
		"emailAddresses":[{"name":"Bob","address":"bob@example.test"}],"companyName":"Example","mobilePhone":"+1 555"}]}`}},
		"contacts_search", map[string]any{"q": "Bo'b"}, false)
	var contacts struct {
		Items []struct {
			DisplayName string   `json:"display_name"`
			Emails      []string `json:"emails"`
		} `json:"items"`
	}
	decode(t, res, &contacts)
	if len(contacts.Items) != 1 || contacts.Items[0].Emails[0] != "bob@example.test" {
		t.Errorf("contacts = %+v", contacts)
	}
	if f := query(t, srv, "/v1.0/me/contacts").Get("$filter"); !strings.Contains(f, "startswith(displayName,'Bo''b')") {
		t.Errorf("$filter = %q", f)
	}
	srv, _ = mustRun(t, map[string]route{"GET /v1.0/me/contacts": {status: 200, body: `{"value":[]}`}}, "contacts_search", map[string]any{"q": "bob@example.test"}, false)
	if f := query(t, srv, "/v1.0/me/contacts").Get("$filter"); f != "emailAddresses/any(a:a/address eq 'bob@example.test')" {
		t.Errorf("email $filter = %q", f)
	}

	srv, res = mustRun(t, map[string]route{"GET /v1.0/me/people": {status: 200, body: `{"value":[{"id":"p-1","displayName":"Carol","jobTitle":"PM",
		"scoredEmailAddresses":[{"address":"carol@example.test"}]}]}`}}, "people_search", map[string]any{"q": "carol"}, false)
	var people struct {
		Items []struct {
			DisplayName string   `json:"display_name"`
			Emails      []string `json:"emails"`
		} `json:"items"`
	}
	decode(t, res, &people)
	if len(people.Items) != 1 || people.Items[0].Emails[0] != "carol@example.test" {
		t.Errorf("people = %+v", people)
	}
	if s := query(t, srv, "/v1.0/me/people").Get("$search"); s != `"carol"` {
		t.Errorf("$search = %q", s)
	}

	srv, res = mustRun(t, map[string]route{"GET /v1.0/users": {status: 200, body: `{"value":[{"id":"u-1","displayName":"Dave","mail":"dave@example.test","userPrincipalName":"dave@example.test"}]}`}},
		"users_search", map[string]any{"q": `Da"ve`}, false)
	r := srv.Last(t, "GET /v1.0/users")
	if r.Header.Get("ConsistencyLevel") != "eventual" || r.URL.Query().Get("$search") != `"displayName:Dave" OR "mail:Dave"` {
		t.Errorf("users request: ConsistencyLevel %q $search %q", r.Header.Get("ConsistencyLevel"), r.URL.Query().Get("$search"))
	}
	var users struct {
		Items []struct{ ID, Mail string } `json:"items"`
	}
	decode(t, res, &users)
	if len(users.Items) != 1 || users.Items[0].Mail != "dave@example.test" {
		t.Errorf("users = %+v", users)
	}
	wantInvalid(t, "users_search", map[string]any{"q": " "}, false)

	c, _ := newConnectorWithScopes(t, newAPIServer(t, nil), connectors.Bounds{}, []string{"User.Read", "People.Read"})
	_, err := c.Call(t.Context(), call("users_search", map[string]any{"q": "x"}))
	wantClass(t, err, microsoft.ClassScopeRequired, 0)
}
