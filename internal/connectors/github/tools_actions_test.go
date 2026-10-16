package github_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

func TestActionsToolsMetadata(t *testing.T) {
	read, write := connectors.KindRead, connectors.KindWrite
	aRead, aWrite := []string{"actions:read"}, []string{"actions:write"}
	run := withArgs(map[string]any{"run_id": 101})
	runIdent := identityWith(map[string]string{"run_id": "101"})
	checkTools(t, []toolMeta{
		{name: "list_workflow_runs", kind: read, scopes: aRead, required: []string{"owner", "repo"}, paged: true,
			props: []string{"owner", "repo", "workflow", "branch", "event", "status", "actor", "head_sha", "page", "per_page"},
			args:  withArgs(map[string]any{"workflow": "ci.yml"}), identity: identityWith(map[string]string{"workflow": "ci.yml"})},
		{name: "get_workflow_run", kind: read, scopes: aRead, required: []string{"owner", "repo", "run_id"}, props: []string{"owner", "repo", "run_id"}, args: run, identity: runIdent},
		{name: "list_workflow_jobs", kind: read, scopes: aRead, required: []string{"owner", "repo", "run_id"}, paged: true,
			props: []string{"owner", "repo", "run_id", "filter", "page", "per_page"}, args: run, identity: runIdent},
		{name: "get_job_logs", kind: read, scopes: aRead, required: []string{"owner", "repo", "job_id"}, props: []string{"owner", "repo", "job_id", "tail_lines"},
			args: withArgs(map[string]any{"job_id": 9}), identity: identityWith(map[string]string{"job_id": "9"})},
		{name: "run_workflow", kind: write, scopes: aWrite, required: []string{"owner", "repo", "workflow", "ref"}, reconcile: connectors.ReconcileNone,
			props:    []string{"owner", "repo", "workflow", "ref", "inputs"},
			args:     withArgs(map[string]any{"workflow": "deploy.yml", "ref": "main", "inputs": map[string]any{"x": "secret"}}),
			identity: identityWith(map[string]string{"workflow": "deploy.yml", "ref": "main"})},
		{name: "rerun_workflow_run", kind: write, scopes: aWrite, required: []string{"owner", "repo", "run_id"}, reconcile: connectors.ReconcileNone,
			props: []string{"owner", "repo", "run_id", "failed_only"}, args: run, identity: runIdent},
		{name: "cancel_workflow_run", kind: write, scopes: aWrite, required: []string{"owner", "repo", "run_id"}, reconcile: connectors.ReconcileStableID,
			props: []string{"owner", "repo", "run_id"}, args: run, identity: runIdent},
	})
}

const runJSON = `{"id":101,"name":"CI","display_title":"Fix uploader","status":"completed","conclusion":"failure","event":"push",
	"head_branch":"main","head_sha":"abc","run_number":12,"run_attempt":2,"html_url":"https://github.example.test/run/101","actor":{"login":"octocat"}}`

func TestListWorkflowRuns(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /repos/example-org/widgets/actions/runs":                  {status: 200, body: `{"total_count":1,"workflow_runs":[` + runJSON + `]}`},
		"GET /repos/example-org/widgets/actions/workflows/ci.yml/runs": {status: 200, body: `{"total_count":0,"workflow_runs":[]}`},
		"GET /repos/example-org/widgets/actions/workflows/77/runs":     {status: 200, body: `{"total_count":0,"workflow_runs":[]}`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_workflow_runs", withArgs(map[string]any{"branch": "main", "status": "failure", "event": "push"})))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			ID         int64  `json:"id"`
			Conclusion string `json:"conclusion"`
			Branch     string `json:"branch"`
			Attempt    int    `json:"run_attempt"`
			Actor      string `json:"actor"`
		} `json:"items"`
	}
	decode(t, res, &p)
	if p.TotalCount != 1 || len(p.Items) != 1 || p.Items[0].ID != 101 || p.Items[0].Conclusion != "failure" || p.Items[0].Branch != "main" || p.Items[0].Attempt != 2 || p.Items[0].Actor != "octocat" {
		t.Errorf("runs = %+v", p)
	}
	if q := query(t, srv, "/repos/example-org/widgets/actions/runs"); q.Get("branch") != "main" || q.Get("status") != "failure" || q.Get("event") != "push" {
		t.Errorf("query = %v", q)
	}
	for _, wf := range []any{"ci.yml", "77", 77} {
		if res, err := c.Call(context.Background(), call("list_workflow_runs", withArgs(map[string]any{"workflow": wf}))); err != nil || !res.Empty {
			t.Errorf("workflow %v: res %+v err %v", wf, res, err)
		}
	}
}

func TestGetWorkflowRunAndJobs(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /repos/example-org/widgets/actions/runs/101": {status: 200, body: runJSON},
		"GET /repos/example-org/widgets/actions/runs/101/jobs": {status: 200, body: `{"total_count":1,"jobs":[{"id":9,"name":"test","status":"completed","conclusion":"failure",
			"html_url":"https://github.example.test/job/9","steps":[{"number":1,"name":"checkout","status":"completed","conclusion":"success"},{"number":2,"name":"go test","status":"completed","conclusion":"failure"}]}]}`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_workflow_run", withArgs(map[string]any{"run_id": 101})))
	if err != nil {
		t.Fatal(err)
	}
	var run struct {
		ID     int64  `json:"id"`
		Status string `json:"status"`
		Title  string `json:"display_title"`
	}
	decode(t, res, &run)
	if run.ID != 101 || run.Status != "completed" || run.Title != "Fix uploader" {
		t.Errorf("run = %+v", run)
	}
	res, err = c.Call(context.Background(), call("list_workflow_jobs", withArgs(map[string]any{"run_id": "101", "filter": "all"})))
	if err != nil {
		t.Fatal(err)
	}
	var jobs struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			ID    int64 `json:"id"`
			Steps []struct {
				Name       string `json:"name"`
				Conclusion string `json:"conclusion"`
			} `json:"steps"`
		} `json:"items"`
	}
	decode(t, res, &jobs)
	if jobs.TotalCount != 1 || len(jobs.Items) != 1 || jobs.Items[0].ID != 9 || len(jobs.Items[0].Steps) != 2 || jobs.Items[0].Steps[1].Conclusion != "failure" {
		t.Errorf("jobs = %+v", jobs)
	}
	if q := query(t, srv, "/repos/example-org/widgets/actions/runs/101/jobs"); q.Get("filter") != "all" {
		t.Errorf("query = %v", q)
	}
	if _, err := c.Call(context.Background(), call("get_workflow_run", withArgs(map[string]any{"run_id": -1}))); err == nil {
		t.Error("negative run_id accepted")
	}
}

// logServer answers the logs endpoint with a redirect to a signed blob
// URL on the same test host; the blob must be fetched without the token.
func logServer(t *testing.T, log string) (*apiServer, *string) {
	t.Helper()
	srv := newAPIServer(t, nil)
	blobAuth := new(string)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/example-org/widgets/actions/jobs/9/logs":
			if r.Header.Get("Authorization") != "Bearer "+testToken {
				http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "http://"+r.Host+"/blob/log.txt?sig=abc", http.StatusFound)
		case "/blob/log.txt":
			*blobAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(log))
		default:
			http.NotFound(w, r)
		}
	})
	return srv, blobAuth
}

func TestGetJobLogsTail(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 1000; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	srv, blobAuth := logServer(t, b.String())
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_job_logs", withArgs(map[string]any{"job_id": 9, "tail_lines": 3})))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Logs       string `json:"logs"`
		Lines      int    `json:"lines"`
		TotalLines int    `json:"total_lines"`
		Truncated  bool   `json:"truncated"`
	}
	decode(t, res, &out)
	if out.Logs != "line 998\nline 999\nline 1000\n" || out.TotalLines != 1000 || out.Lines != 3 || !out.Truncated {
		t.Errorf("logs = %+v", out)
	}
	if *blobAuth != "" {
		t.Errorf("the signed log URL was sent the token: %q", *blobAuth)
	}
}

func TestGetJobLogsBoundedFromTheEnd(t *testing.T) {
	log := strings.Repeat("noise\n", 5000) + "the error\n"
	srv, _ := logServer(t, log)
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 2048})
	res, err := c.Call(context.Background(), call("get_job_logs", withArgs(map[string]any{"job_id": 9, "tail_lines": 5000})))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Logs      string `json:"logs"`
		Truncated bool   `json:"truncated"`
	}
	decode(t, res, &out)
	if !strings.HasSuffix(out.Logs, "the error\n") || len(out.Logs) > 2048 || !out.Truncated || !res.Partial {
		t.Errorf("logs %d bytes truncated %v, want the end within the bound", len(out.Logs), out.Truncated)
	}
}

// --- writes --------------------------------------------------------------------------

func TestRunWorkflow(t *testing.T) {
	path := "POST /repos/example-org/widgets/actions/workflows/deploy.yml/dispatches"
	srv := newAPIServer(t, map[string]route{path: {status: 200, body: `{"workflow_run_id":555,"html_url":"https://github.example.test/run/555"}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("run_workflow", withArgs(map[string]any{"workflow": "deploy.yml", "ref": "main", "inputs": map[string]any{"env": "staging"}})))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, path))
	inputs, _ := body["inputs"].(map[string]any)
	if body["ref"] != "main" || inputs["env"] != "staging" || body["return_run_details"] != true {
		t.Errorf("request = %v", body)
	}
	if ids := toolNamed(t, c, "run_workflow").ResultIDs(res); ids["run_id"] != "555" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := c.Call(context.Background(), write("run_workflow", withArgs(map[string]any{"workflow": "deploy.yml", "ref": "main", "inputs": "x"}))); err == nil {
		t.Error("non-object inputs accepted")
	}
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{path: tc.rt})
			res, err := shortTimeout(t, srv).Call(context.Background(), write("run_workflow", withArgs(map[string]any{"workflow": "deploy.yml", "ref": "main"})))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestRerunWorkflowRun(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"POST /repos/example-org/widgets/actions/runs/101/rerun":             {status: 201, body: `{}`},
		"POST /repos/example-org/widgets/actions/runs/101/rerun-failed-jobs": {status: 201, body: `{}`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	for _, failed := range []bool{false, true} {
		res, err := c.Call(context.Background(), write("rerun_workflow_run", withArgs(map[string]any{"run_id": 101, "failed_only": failed})))
		if err != nil {
			t.Fatal(err)
		}
		if ids := toolNamed(t, c, "rerun_workflow_run").ResultIDs(res); ids["run_id"] != "101" {
			t.Errorf("ResultIDs = %v", ids)
		}
	}
	if srv.Count("POST /repos/example-org/widgets/actions/runs/101/rerun") != 1 || srv.Count("POST /repos/example-org/widgets/actions/runs/101/rerun-failed-jobs") != 1 {
		t.Errorf("requests = %v", srv.Requests())
	}
}

const cancelPath = "POST /repos/example-org/widgets/actions/runs/101/cancel"

func TestCancelWorkflowRun(t *testing.T) {
	srv := newAPIServer(t, map[string]route{cancelPath: {status: 202, body: `{}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("cancel_workflow_run", withArgs(map[string]any{"run_id": 101})))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolNamed(t, c, "cancel_workflow_run").ResultIDs(res); ids["run_id"] != "101" {
		t.Errorf("ResultIDs = %v", ids)
	}
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{cancelPath: tc.rt})
			res, err := shortTimeout(t, srv).Call(context.Background(), write("cancel_workflow_run", withArgs(map[string]any{"run_id": 101})))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestCheckCancelled(t *testing.T) {
	ident := identityWith(map[string]string{"run_id": "101"})
	for name, tc := range map[string]struct {
		body           string
		found, missing bool
	}{
		"cancelled":     {body: `{"id":101,"status":"completed","conclusion":"cancelled"}`, found: true},
		"finished else": {body: `{"id":101,"status":"completed","conclusion":"success"}`, missing: true},
		"still running": {body: `{"id":101,"status":"in_progress"}`},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/actions/runs/101": {status: 200, body: tc.body}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := toolNamed(t, c, "cancel_workflow_run").Reconcile.Check(context.Background(), reconcile("cancel_workflow_run", ident))
			switch {
			case tc.found:
				wantFound(t, res, err, "101")
			case tc.missing:
				wantNotFound(t, res, err)
			default:
				if err == nil {
					t.Errorf("Check = %+v, want cannot tell yet", res)
				}
			}
		})
	}
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	if _, err := toolNamed(t, c, "cancel_workflow_run").Reconcile.Check(context.Background(), reconcile("cancel_workflow_run", repoIdentity)); err == nil {
		t.Error("Check without run_id succeeded")
	}
	_ = github.ToolCancelWorkflowRun
}
