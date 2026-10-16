package github_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

const headSHA = "0123456789abcdef0123456789abcdef01234567"

func TestPullToolsMetadata(t *testing.T) {
	read, write := connectors.KindRead, connectors.KindWrite
	or := []string{"owner", "repo"}
	orn := []string{"owner", "repo", "number"}
	n43 := withArgs(map[string]any{"number": 43})
	ident43 := identityWith(map[string]string{"number": "43"})
	prRead := []string{"pull_requests:read"}
	prWrite := []string{"pull_requests:write"}
	checkTools(t, []toolMeta{
		{name: "list_pull_requests", kind: read, scopes: prRead, required: or, paged: true,
			props: []string{"owner", "repo", "state", "head", "base", "sort", "direction", "page", "per_page"}, args: ownerRepo, identity: repoIdentity},
		{name: "get_pull_request_diff", kind: read, scopes: prRead, required: orn, props: orn, args: n43, identity: ident43},
		{name: "get_pull_request_status", kind: read, scopes: []string{"pull_requests:read", "statuses:read", "checks:read"}, required: orn, props: orn, args: n43, identity: ident43},
		{name: "list_pull_request_reviews", kind: read, scopes: prRead, required: orn, paged: true, props: append(append([]string{}, orn...), "page", "per_page"), args: n43, identity: ident43},
		{name: "list_pull_request_review_comments", kind: read, scopes: prRead, required: orn, paged: true, props: append(append([]string{}, orn...), "page", "per_page"), args: n43, identity: ident43},
		{name: "update_pull_request", kind: write, scopes: prWrite, required: orn, reconcile: connectors.ReconcileNone,
			props: []string{"owner", "repo", "number", "title", "body", "state", "base", "maintainer_can_modify"},
			args:  withArgs(map[string]any{"number": 43, "title": "secret"}), identity: ident43},
		{name: "create_pull_request_review", kind: write, scopes: prWrite, required: []string{"owner", "repo", "number", "event"}, reconcile: connectors.ReconcileMarker,
			props: []string{"owner", "repo", "number", "event", "body", "commit_id", "comments"},
			args:  withArgs(map[string]any{"number": 43, "event": "APPROVE", "body": "secret"}), identity: ident43},
		{name: "request_reviewers", kind: write, scopes: prWrite, required: orn, reconcile: connectors.ReconcileStableID,
			props:    []string{"owner", "repo", "number", "reviewers", "team_reviewers"},
			args:     withArgs(map[string]any{"number": 43, "reviewers": []any{"Hubot", "octocat"}, "team_reviewers": []any{"core"}}),
			identity: identityWith(map[string]string{"number": "43", "reviewers": "hubot,octocat", "team_reviewers": "core"})},
		{name: "merge_pull_request", kind: write, scopes: []string{"contents:write"}, required: orn, reconcile: connectors.ReconcileStableID,
			props: []string{"owner", "repo", "number", "merge_method", "commit_title", "commit_message", "sha"},
			args:  withArgs(map[string]any{"number": 43, "commit_message": "secret"}), identity: ident43},
	})
}

func TestListPullRequests(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/pulls": {status: 200, body: "pulls_by_head.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_pull_requests", withArgs(map[string]any{"state": "closed", "base": "main", "head": "octocat:feature"})))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Items []struct {
			Number int    `json:"number"`
			Head   string `json:"head"`
			Base   string `json:"base"`
			URL    string `json:"url"`
		} `json:"items"`
	}
	decode(t, res, &p)
	if len(p.Items) == 0 || p.Items[0].Number == 0 || p.Items[0].URL == "" {
		t.Errorf("pulls = %+v", p)
	}
	if q := query(t, srv, "/repos/example-org/widgets/pulls"); q.Get("state") != "closed" || q.Get("base") != "main" || q.Get("head") != "octocat:feature" {
		t.Errorf("query = %v", q)
	}
}

func TestGetPullRequestDiffBounded(t *testing.T) {
	diff := "diff --git a/x b/x\n" + strings.Repeat("+line\n", 5000)
	var accept string
	srv := newAPIServer(t, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		if r.URL.Path != "/repos/example-org/widgets/pulls/43" || r.Header.Get("Authorization") != "Bearer "+testToken {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(diff))
	})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 4096})
	res, err := c.Call(context.Background(), call("get_pull_request_diff", withArgs(map[string]any{"number": 43})))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Diff      string `json:"diff"`
		Truncated bool   `json:"truncated"`
	}
	decode(t, res, &out)
	if !strings.Contains(accept, "diff") || !out.Truncated || !res.Partial || !strings.HasPrefix(diff, out.Diff) || len(out.Diff) == 0 || len(out.Diff) > 4096 {
		t.Errorf("accept %q diff %d bytes truncated %v", accept, len(out.Diff), out.Truncated)
	}
}

func TestGetPullRequestStatus(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /repos/example-org/widgets/pulls/43": {status: 200, body: "pull.json"},
		"GET /repos/example-org/widgets/commits/" + headSHA + "/status": {status: 200, body: `{"state":"failure","total_count":1,
			"statuses":[{"context":"ci/lint","state":"failure","description":"2 issues","target_url":"https://ci.example.test/1"}]}`},
		"GET /repos/example-org/widgets/commits/" + headSHA + "/check-runs": {status: 200, body: `{"total_count":1,
			"check_runs":[{"name":"test","status":"completed","conclusion":"success","html_url":"https://github.example.test/run/1"}]}`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_pull_request_status", withArgs(map[string]any{"number": 43})))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		SHA       string                            `json:"sha"`
		State     string                            `json:"state"`
		Statuses  []struct{ Context, State string } `json:"statuses"`
		CheckRuns []struct {
			Name       string `json:"name"`
			Conclusion string `json:"conclusion"`
		} `json:"check_runs"`
	}
	decode(t, res, &out)
	if out.SHA != headSHA || out.State != "failure" || len(out.Statuses) != 1 || out.Statuses[0].Context != "ci/lint" || len(out.CheckRuns) != 1 || out.CheckRuns[0].Conclusion != "success" {
		t.Errorf("status = %+v", out)
	}
}

func TestListReviewsAndReviewComments(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /repos/example-org/widgets/pulls/43/reviews":  {status: 200, body: `[{"id":5,"state":"APPROVED","body":"lgtm","user":{"login":"hubot"},"commit_id":"abc"}]`},
		"GET /repos/example-org/widgets/pulls/43/comments": {status: 200, body: `[{"id":9,"path":"a.go","line":3,"side":"RIGHT","body":"nit","user":{"login":"hubot"},"pull_request_review_id":5}]`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_pull_request_reviews", withArgs(map[string]any{"number": 43})))
	if err != nil {
		t.Fatal(err)
	}
	var reviews struct {
		Items []struct {
			ID    int64  `json:"id"`
			State string `json:"state"`
			User  string `json:"user"`
		} `json:"items"`
	}
	decode(t, res, &reviews)
	if len(reviews.Items) != 1 || reviews.Items[0].State != "APPROVED" || reviews.Items[0].User != "hubot" {
		t.Errorf("reviews = %+v", reviews)
	}
	res, err = c.Call(context.Background(), call("list_pull_request_review_comments", withArgs(map[string]any{"number": 43})))
	if err != nil {
		t.Fatal(err)
	}
	var comments struct {
		Items []struct {
			ID       int64  `json:"id"`
			Path     string `json:"path"`
			Line     int    `json:"line"`
			ReviewID int64  `json:"review_id"`
		} `json:"items"`
	}
	decode(t, res, &comments)
	if len(comments.Items) != 1 || comments.Items[0].Path != "a.go" || comments.Items[0].Line != 3 || comments.Items[0].ReviewID != 5 {
		t.Errorf("comments = %+v", comments)
	}
}

// --- writes ------------------------------------------------------------------------

const patchPullPath = "PATCH /repos/example-org/widgets/pulls/43"

func TestUpdatePullRequest(t *testing.T) {
	srv := newAPIServer(t, map[string]route{patchPullPath: {status: 200, body: "pull.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("update_pull_request", withArgs(map[string]any{"number": 43, "state": "open", "base": "develop"})))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, patchPullPath))
	if body["state"] != "open" || body["base"] != "develop" {
		t.Errorf("request = %v", body)
	}
	if ids := toolNamed(t, c, "update_pull_request").ResultIDs(res); ids["number"] != "43" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := c.Call(context.Background(), write("update_pull_request", withArgs(map[string]any{"number": 43}))); err == nil {
		t.Error("update without fields accepted")
	}
	_, err = c.Call(context.Background(), write("update_pull_request", withArgs(map[string]any{"number": 43, "state": "closed", "base": "develop"})))
	wantClass(t, err, github.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{patchPullPath: tc.rt})
			res, err := shortTimeout(t, srv).Call(context.Background(), write("update_pull_request", withArgs(map[string]any{"number": 43, "title": "t"})))
			checkWriteError(t, tc, res, err)
		})
	}
}

const reviewsPath = "POST /repos/example-org/widgets/pulls/43/reviews"

func TestCreatePullRequestReview(t *testing.T) {
	srv := newAPIServer(t, map[string]route{reviewsPath: {status: 200, body: `{"id":77,"state":"CHANGES_REQUESTED","html_url":"https://github.example.test/r/77"}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("create_pull_request_review", withArgs(map[string]any{
		"number": 43, "event": "REQUEST_CHANGES", "body": "Please add a test.",
		"comments": []any{map[string]any{"path": "a.go", "line": 3, "body": "here"}},
	})))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, reviewsPath))
	comments, _ := body["comments"].([]any)
	if body["event"] != "REQUEST_CHANGES" || !strings.HasSuffix(body["body"].(string), marker) || len(comments) != 1 {
		t.Errorf("request = %v", body)
	}
	if ids := toolNamed(t, c, "create_pull_request_review").ResultIDs(res); ids["id"] != "77" {
		t.Errorf("ResultIDs = %v", ids)
	}
	for _, args := range []map[string]any{
		withArgs(map[string]any{"number": 43, "event": "MAYBE"}),
		withArgs(map[string]any{"number": 43, "event": "COMMENT"}),
		withArgs(map[string]any{"number": 43, "event": "APPROVE", "comments": []any{"bad"}}),
	} {
		if _, err := c.Call(context.Background(), write("create_pull_request_review", args)); err == nil {
			t.Errorf("args %v accepted", args)
		}
	}
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{reviewsPath: tc.rt})
			res, err := shortTimeout(t, srv).Call(context.Background(), write("create_pull_request_review", withArgs(map[string]any{"number": 43, "event": "APPROVE"})))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestCheckReview(t *testing.T) {
	ident := identityWith(map[string]string{"number": "43"})
	listPath := "GET /repos/example-org/widgets/pulls/43/reviews"
	cases := map[string]struct {
		rt      route
		found   string
		missing bool
	}{
		"found":   {rt: route{status: 200, body: `[{"id":1,"body":"x"},{"id":77,"body":"ok\n\n` + strings.ReplaceAll(marker, `"`, `\"`) + `"}]`}, found: "77"},
		"missing": {rt: route{status: 200, body: `[{"id":1,"body":"x"}]`}, missing: true},
		"error":   {rt: route{status: 500, body: "error_server.json"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := toolNamed(t, c, "create_pull_request_review").Reconcile.Check(context.Background(), reconcile("create_pull_request_review", ident))
			switch {
			case tc.found != "":
				wantFound(t, res, err, tc.found)
			case tc.missing:
				wantNotFound(t, res, err)
			default:
				if err == nil {
					t.Errorf("Check = %+v, want cannot tell", res)
				}
			}
		})
	}
}

const reviewersPath = "POST /repos/example-org/widgets/pulls/43/requested_reviewers"

func TestRequestReviewers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{reviewersPath: {status: 201, body: "pull.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("request_reviewers", withArgs(map[string]any{"number": 43, "reviewers": []any{"hubot"}, "team_reviewers": []any{"core"}})))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, reviewersPath))
	if r, _ := body["reviewers"].([]any); len(r) != 1 || r[0] != "hubot" {
		t.Errorf("request = %v", body)
	}
	if ids := toolNamed(t, c, "request_reviewers").ResultIDs(res); ids["number"] != "43" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := c.Call(context.Background(), write("request_reviewers", withArgs(map[string]any{"number": 43}))); err == nil {
		t.Error("no reviewers accepted")
	}
}

func TestCheckReviewers(t *testing.T) {
	ident := identityWith(map[string]string{"number": "43", "reviewers": "hubot", "team_reviewers": "core"})
	path := "GET /repos/example-org/widgets/pulls/43/requested_reviewers"
	srv := newAPIServer(t, map[string]route{path: {status: 200, body: `{"users":[{"login":"Hubot"}],"teams":[{"slug":"core"}]}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := toolNamed(t, c, "request_reviewers").Reconcile.Check(context.Background(), reconcile("request_reviewers", ident))
	wantFound(t, res, err, "43")
	srv = newAPIServer(t, map[string]route{path: {status: 200, body: `{"users":[],"teams":[]}`}})
	c, _ = newConnector(t, srv, connectors.Bounds{})
	if res, err := toolNamed(t, c, "request_reviewers").Reconcile.Check(context.Background(), reconcile("request_reviewers", ident)); err == nil {
		t.Errorf("missing reviewers: Check = %+v, want cannot tell (they may have reviewed already)", res)
	}
	if _, err := toolNamed(t, c, "request_reviewers").Reconcile.Check(context.Background(), reconcile("request_reviewers", repoIdentity)); !errors.Is(err, github.ErrNotReconcilable) {
		t.Errorf("no number: err = %v", err)
	}
}

const mergePath = "PUT /repos/example-org/widgets/pulls/43/merge"

func TestMergePullRequest(t *testing.T) {
	srv := newAPIServer(t, map[string]route{mergePath: {status: 200, body: `{"sha":"m1","merged":true,"message":"Pull Request successfully merged"}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("merge_pull_request", withArgs(map[string]any{"number": 43, "merge_method": "squash", "sha": headSHA, "commit_title": "T"})))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, mergePath))
	if body["merge_method"] != "squash" || body["sha"] != headSHA || body["commit_title"] != "T" {
		t.Errorf("request = %v", body)
	}
	if ids := toolNamed(t, c, "merge_pull_request").ResultIDs(res); ids["sha"] != "m1" || ids["number"] != "43" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := c.Call(context.Background(), write("merge_pull_request", withArgs(map[string]any{"number": 43, "merge_method": "octopus"}))); err == nil {
		t.Error("bad merge_method accepted")
	}
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{mergePath: tc.rt})
			res, err := shortTimeout(t, srv).Call(context.Background(), write("merge_pull_request", withArgs(map[string]any{"number": 43})))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestCheckMerged(t *testing.T) {
	ident := identityWith(map[string]string{"number": "43"})
	for name, tc := range map[string]struct {
		status       int
		found, error bool
	}{"merged": {status: 204, found: true}, "not merged": {status: 404}, "unavailable": {status: 500, error: true}} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/pulls/43/merge": {status: tc.status}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := toolNamed(t, c, "merge_pull_request").Reconcile.Check(context.Background(), reconcile("merge_pull_request", ident))
			switch {
			case tc.error:
				if err == nil {
					t.Errorf("Check = %+v, want cannot tell", res)
				}
			case tc.found:
				wantFound(t, res, err, "43")
			default:
				wantNotFound(t, res, err)
			}
		})
	}
}
