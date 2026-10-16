package github_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

// toolMeta is what every new tool's declaration is checked against.
type toolMeta struct {
	name      string
	kind      connectors.Kind
	scopes    []string
	required  []string
	props     []string
	reconcile connectors.ReconcileKind
	paged     bool
	args      map[string]any
	identity  map[string]string
}

// checkTools asserts each declaration: kind, scopes, closed schema with
// exactly the properties (each described), required list, page bounds,
// reconciliation and resource identity.
func checkTools(t *testing.T, metas []toolMeta) {
	t.Helper()
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, m := range metas {
		t.Run(m.name, func(t *testing.T) {
			tool := toolNamed(t, c, m.name)
			if tool.Kind != m.kind {
				t.Errorf("Kind = %q, want %q", tool.Kind, m.kind)
			}
			if strings.Join(tool.RequiredScopes, ",") != strings.Join(m.scopes, ",") {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, m.scopes)
			}
			var s struct {
				Type       string                    `json:"type"`
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
				Additional *bool                     `json:"additionalProperties"`
			}
			if err := json.Unmarshal(tool.InputSchema, &s); err != nil {
				t.Fatal(err)
			}
			if s.Type != "object" || s.Additional == nil || *s.Additional {
				t.Errorf("schema must be a closed object: %s", tool.InputSchema)
			}
			if strings.Join(s.Required, ",") != strings.Join(m.required, ",") {
				t.Errorf("required = %v, want %v", s.Required, m.required)
			}
			var props []string
			for p, v := range s.Properties {
				props = append(props, p)
				if d, _ := v["description"].(string); strings.TrimSpace(d) == "" {
					t.Errorf("property %q has no description", p)
				}
			}
			slices.Sort(props)
			want := slices.Clone(m.props)
			slices.Sort(want)
			if !slices.Equal(props, want) {
				t.Errorf("properties = %v, want %v", props, want)
			}
			if m.paged != (tool.Bounds.MaxPageSize > 0) {
				t.Errorf("MaxPageSize = %d, paged = %v", tool.Bounds.MaxPageSize, m.paged)
			}
			if tool.Reconcile.Kind != m.reconcile {
				t.Errorf("Reconcile = %q, want %q", tool.Reconcile.Kind, m.reconcile)
			}
			if m.kind == connectors.KindWrite && tool.ResultIDs == nil {
				t.Error("write without ResultIDs")
			}
			if m.identity != nil {
				got := tool.ResourceIdentity(m.args)
				if len(got) != len(m.identity) {
					t.Errorf("ResourceIdentity = %v, want %v", got, m.identity)
				}
				for k, v := range m.identity {
					if got[k] != v {
						t.Errorf("ResourceIdentity[%s] = %q, want %q", k, got[k], v)
					}
				}
				for _, v := range got {
					if strings.Contains(v, "secret") {
						t.Errorf("ResourceIdentity leaks argument content: %v", got)
					}
				}
			}
		})
	}
}

var ownerRepo = map[string]any{"owner": "Example-Org", "repo": "Widgets"}

func withArgs(extra map[string]any) map[string]any {
	out := map[string]any{"owner": "example-org", "repo": "widgets"}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

var repoIdentity = map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org"}

func identityWith(extra map[string]string) map[string]string {
	out := map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org"}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// shortTimeout builds a connector whose calls give up after 500ms, so
// the writeErrorCases timeout row becomes an unknown outcome quickly.
func shortTimeout(t *testing.T, srv *apiServer) *github.Connector {
	t.Helper()
	c, err := github.New(github.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRepoToolsMetadata(t *testing.T) {
	read, write := connectors.KindRead, connectors.KindWrite
	or := []string{"owner", "repo"}
	paged := func(p ...string) []string { return append(append(slices.Clone(or), p...), "page", "per_page") }
	checkTools(t, []toolMeta{
		{name: "get_file_contents", kind: read, scopes: []string{"contents:read"}, required: or, props: append(slices.Clone(or), "path", "ref"),
			args: map[string]any{"owner": "Example-Org", "repo": "Widgets", "path": "Docs/README.md", "ref": "main"}, identity: identityWith(map[string]string{"path": "Docs/README.md", "ref": "main"})},
		{name: "list_branches", kind: read, scopes: []string{"contents:read"}, required: or, props: paged("protected"), paged: true, args: ownerRepo, identity: repoIdentity},
		{name: "list_commits", kind: read, scopes: []string{"contents:read"}, required: or, props: paged("sha", "path", "author", "since", "until"), paged: true, args: ownerRepo, identity: repoIdentity},
		{name: "get_commit", kind: read, scopes: []string{"contents:read"}, required: []string{"owner", "repo", "sha"}, props: append(slices.Clone(or), "sha"),
			args: withArgs(map[string]any{"sha": "abc"}), identity: identityWith(map[string]string{"sha": "abc"})},
		{name: "list_tags", kind: read, required: or, props: paged(), paged: true, args: ownerRepo, identity: repoIdentity},
		{name: "list_releases", kind: read, scopes: []string{"contents:read"}, required: or, props: paged(), paged: true, args: ownerRepo, identity: repoIdentity},
		{name: "get_release", kind: read, scopes: []string{"contents:read"}, required: or, props: append(slices.Clone(or), "tag"), args: ownerRepo, identity: repoIdentity},
		{name: "search_code", kind: read, required: []string{"q"}, props: []string{"q", "owner", "repo", "page", "per_page"}, paged: true, args: ownerRepo, identity: repoIdentity},
		{name: "search_repositories", kind: read, required: []string{"q"}, props: []string{"q", "sort", "order", "page", "per_page"}, paged: true, args: map[string]any{"q": "x"}, identity: map[string]string{}},
		{name: "search_users", kind: read, required: []string{"q"}, props: []string{"q", "sort", "order", "page", "per_page"}, paged: true, args: map[string]any{"q": "x"}, identity: map[string]string{}},
		{name: "create_or_update_file", kind: write, scopes: []string{"contents:write"}, required: []string{"owner", "repo", "path", "content", "message"},
			props: append(slices.Clone(or), "path", "content", "message", "branch", "sha"), reconcile: connectors.ReconcileMarker,
			args:     withArgs(map[string]any{"path": "src/App.go", "content": "secret", "message": "secret", "branch": "Feature/X"}),
			identity: identityWith(map[string]string{"path": "src/App.go", "branch": "Feature/X"})},
	})
}

// --- get_file_contents -------------------------------------------------------------

const contentsPath = "GET /repos/example-org/widgets/contents/docs/readme.md"

func fileJSON(content []byte, encoding string) string {
	enc := base64.StdEncoding.EncodeToString(content)
	if encoding == "none" {
		enc = ""
	}
	b, _ := json.Marshal(map[string]any{
		"type": "file", "name": "readme.md", "path": "docs/readme.md", "sha": "blob1", "size": len(content),
		"encoding": encoding, "content": enc, "html_url": "https://github.example.test/example-org/widgets/blob/main/docs/readme.md",
	})
	return string(b)
}

type fileResult struct {
	Type      string `json:"type"`
	Path      string `json:"path"`
	SHA       string `json:"sha"`
	Size      int    `json:"size"`
	Encoding  string `json:"encoding"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
	Entries   []struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"entries"`
}

func TestGetFileContentsText(t *testing.T) {
	srv := newAPIServer(t, map[string]route{contentsPath: {status: 200, body: fileJSON([]byte("# Widgets\nhello\n"), "base64")}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_file_contents", withArgs(map[string]any{"path": "docs/readme.md", "ref": "main"})))
	if err != nil {
		t.Fatal(err)
	}
	var f fileResult
	decode(t, res, &f)
	if f.Type != "file" || f.Encoding != "text" || f.Content != "# Widgets\nhello\n" || f.SHA != "blob1" || f.Truncated || res.Partial {
		t.Errorf("file = %+v", f)
	}
	if q := query(t, srv, "/repos/example-org/widgets/contents/docs/readme.md"); q.Get("ref") != "main" {
		t.Errorf("ref = %q", q.Get("ref"))
	}
}

func TestGetFileContentsBinaryIsBase64(t *testing.T) {
	bin := []byte{0x89, 'P', 'N', 'G', 0, 1, 2, 0xff}
	srv := newAPIServer(t, map[string]route{contentsPath: {status: 200, body: fileJSON(bin, "base64")}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_file_contents", withArgs(map[string]any{"path": "docs/readme.md"})))
	if err != nil {
		t.Fatal(err)
	}
	var f fileResult
	decode(t, res, &f)
	if f.Encoding != "base64" || f.Content != base64.StdEncoding.EncodeToString(bin) {
		t.Errorf("file = %+v", f)
	}
}

func TestGetFileContentsTruncatedToBounds(t *testing.T) {
	big := []byte(strings.Repeat("line of text\n", 2000))
	srv := newAPIServer(t, map[string]route{contentsPath: {status: 200, body: fileJSON(big, "base64")}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 4096})
	res, err := c.Call(context.Background(), call("get_file_contents", withArgs(map[string]any{"path": "docs/readme.md"})))
	if err != nil {
		t.Fatal(err)
	}
	var f fileResult
	decode(t, res, &f)
	raw, _ := json.Marshal(res.Content)
	if !f.Truncated || !res.Partial || len(raw) > 4096 || !strings.HasPrefix(string(big), f.Content) || f.Content == "" {
		t.Errorf("truncated = %v partial = %v size = %d content %d bytes", f.Truncated, res.Partial, len(raw), len(f.Content))
	}
}

// Files over 1 MB come back with encoding "none": the raw media type is
// fetched from the same endpoint, read only up to the bound.
func TestGetFileContentsLargeFileFetchedRawAndBounded(t *testing.T) {
	big := strings.Repeat("x", 300<<10)
	var rawAccept string
	srv := newAPIServer(t, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("missing token")
		}
		if strings.Contains(r.Header.Get("Accept"), "raw") {
			rawAccept = r.Header.Get("Accept")
			_, _ = w.Write([]byte(big))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fileJSON([]byte(big), "none")))
	})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 8192})
	res, err := c.Call(context.Background(), call("get_file_contents", withArgs(map[string]any{"path": "docs/readme.md"})))
	if err != nil {
		t.Fatal(err)
	}
	var f fileResult
	decode(t, res, &f)
	if rawAccept == "" || f.Encoding != "text" || !f.Truncated || len(f.Content) == 0 || len(f.Content) > 8192 || f.Size != len(big) {
		t.Errorf("accept %q file encoding %q truncated %v content %d size %d", rawAccept, f.Encoding, f.Truncated, len(f.Content), f.Size)
	}
}

func TestGetFileContentsDirectory(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/contents/docs": {status: 200, body: `[
		{"type":"file","name":"readme.md","path":"docs/readme.md","sha":"a","size":3},
		{"type":"dir","name":"img","path":"docs/img","sha":"b","size":0}]`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("get_file_contents", withArgs(map[string]any{"path": "docs/"})))
	if err != nil {
		t.Fatal(err)
	}
	var f fileResult
	decode(t, res, &f)
	if f.Type != "dir" || len(f.Entries) != 2 || f.Entries[1].Type != "dir" || f.Entries[0].Path != "docs/readme.md" {
		t.Errorf("dir = %+v", f)
	}
}

func TestGetFileContentsRejectsTraversal(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	_, err := c.Call(context.Background(), call("get_file_contents", withArgs(map[string]any{"path": "docs/../../etc"})))
	wantClass(t, err, github.ClassInvalidArgument, 0)
}

func TestGetFileContentsNotFound(t *testing.T) {
	srv := newAPIServer(t, map[string]route{contentsPath: {status: 404, body: "error_not_found.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	_, err := c.Call(context.Background(), call("get_file_contents", withArgs(map[string]any{"path": "docs/readme.md"})))
	wantClass(t, err, github.ClassNotFound, 404)
}

// --- lists ---------------------------------------------------------------------------

func nextLink(path string) map[string]string {
	return map[string]string{"Link": `<https://api.github.example.test` + path + `?page=2>; rel="next"`}
}

func TestListBranches(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/branches": {status: 200, headers: nextLink("/repos/example-org/widgets/branches"),
		body: `[{"name":"main","commit":{"sha":"s1"},"protected":true},{"name":"dev","commit":{"sha":"s2"}}]`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_branches", withArgs(map[string]any{"protected": true, "per_page": 2})))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		HasMore bool `json:"has_more"`
		Items   []struct {
			Name      string `json:"name"`
			SHA       string `json:"sha"`
			Protected bool   `json:"protected"`
		} `json:"items"`
	}
	decode(t, res, &p)
	if !p.HasMore || len(p.Items) != 2 || p.Items[0].Name != "main" || p.Items[0].SHA != "s1" || !p.Items[0].Protected {
		t.Errorf("branches = %+v", p)
	}
	if q := query(t, srv, "/repos/example-org/widgets/branches"); q.Get("protected") != "true" || q.Get("per_page") != "2" {
		t.Errorf("query = %v", q)
	}
}

func TestListCommits(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/commits": {status: 200, body: `[
		{"sha":"c1","html_url":"https://github.example.test/c1","commit":{"message":"Fix the uploader\n\nlong body","author":{"name":"Octo Cat","date":"2026-01-02T03:04:05Z"}},"author":{"login":"octocat"}}]`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_commits", withArgs(map[string]any{"sha": "main", "path": "src", "author": "octocat", "since": "2026-01-01T00:00:00Z"})))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Items []struct {
			SHA     string `json:"sha"`
			Message string `json:"message"`
			Author  string `json:"author"`
			Login   string `json:"author_login"`
			Date    string `json:"date"`
		} `json:"items"`
	}
	decode(t, res, &p)
	if len(p.Items) != 1 || p.Items[0].SHA != "c1" || p.Items[0].Message != "Fix the uploader\n\nlong body" || p.Items[0].Login != "octocat" || p.Items[0].Date != "2026-01-02T03:04:05Z" {
		t.Errorf("commits = %+v", p)
	}
	q := query(t, srv, "/repos/example-org/widgets/commits")
	if q.Get("sha") != "main" || q.Get("path") != "src" || q.Get("author") != "octocat" || q.Get("since") == "" {
		t.Errorf("query = %v", q)
	}
	_, err = c.Call(context.Background(), call("list_commits", withArgs(map[string]any{"since": "yesterday"})))
	wantClass(t, err, github.ClassInvalidArgument, 0)
}

func TestGetCommitDropsPatchesToFit(t *testing.T) {
	patch := strings.Repeat("+added line\n", 400)
	body, _ := json.Marshal(map[string]any{
		"sha": "c1", "html_url": "https://github.example.test/c1",
		"commit": map[string]any{"message": "msg", "author": map[string]any{"name": "Octo", "date": "2026-01-02T03:04:05Z"}},
		"stats":  map[string]any{"additions": 800, "deletions": 0, "total": 800},
		"files":  []any{map[string]any{"filename": "a.go", "status": "modified", "patch": patch}, map[string]any{"filename": "b.go", "status": "added", "patch": patch}},
	})
	srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/commits/c1": {status: 200, body: string(body)}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 6000})
	res, err := c.Call(context.Background(), call("get_commit", withArgs(map[string]any{"sha": "c1"})))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		SHA       string `json:"sha"`
		Additions int    `json:"additions"`
		Files     []struct {
			Filename       string `json:"filename"`
			Patch          string `json:"patch"`
			PatchTruncated bool   `json:"patch_truncated"`
		} `json:"files"`
	}
	decode(t, res, &out)
	raw, _ := json.Marshal(res.Content)
	if out.SHA != "c1" || out.Additions != 800 || len(out.Files) != 2 || !res.Partial || len(raw) > 6000 {
		t.Errorf("commit = %+v (size %d, partial %v)", out, len(raw), res.Partial)
	}
	if !out.Files[0].PatchTruncated && !out.Files[1].PatchTruncated {
		t.Error("no patch dropped")
	}
}

func TestListTagsAndReleases(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /repos/example-org/widgets/tags":     {status: 200, body: `[{"name":"v1.0.0","commit":{"sha":"t1"}}]`},
		"GET /repos/example-org/widgets/releases": {status: 200, body: `[{"id":7,"tag_name":"v1.0.0","name":"One","draft":false,"prerelease":true,"body":"notes","html_url":"https://github.example.test/r/7","author":{"login":"octocat"}}]`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("list_tags", withArgs(nil)))
	if err != nil {
		t.Fatal(err)
	}
	var tags struct {
		Items []struct {
			Name string `json:"name"`
			SHA  string `json:"sha"`
		} `json:"items"`
	}
	decode(t, res, &tags)
	if len(tags.Items) != 1 || tags.Items[0].Name != "v1.0.0" || tags.Items[0].SHA != "t1" {
		t.Errorf("tags = %+v", tags)
	}
	res, err = c.Call(context.Background(), call("list_releases", withArgs(nil)))
	if err != nil {
		t.Fatal(err)
	}
	var rel struct {
		Items []struct {
			ID         int64  `json:"id"`
			Tag        string `json:"tag_name"`
			Prerelease bool   `json:"prerelease"`
			Author     string `json:"author"`
			Body       string `json:"body"`
		} `json:"items"`
	}
	decode(t, res, &rel)
	if len(rel.Items) != 1 || rel.Items[0].ID != 7 || rel.Items[0].Tag != "v1.0.0" || !rel.Items[0].Prerelease || rel.Items[0].Author != "octocat" || rel.Items[0].Body != "" {
		t.Errorf("releases = %+v (lists carry no body)", rel)
	}
}

func TestGetRelease(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /repos/example-org/widgets/releases/latest":      {status: 200, body: `{"id":8,"tag_name":"v2","body":"latest notes"}`},
		"GET /repos/example-org/widgets/releases/tags/v1.0.0": {status: 200, body: `{"id":7,"tag_name":"v1.0.0","body":"old notes"}`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	for tag, want := range map[string]string{"": "latest notes", "v1.0.0": "old notes"} {
		args := withArgs(nil)
		if tag != "" {
			args["tag"] = tag
		}
		res, err := c.Call(context.Background(), call("get_release", args))
		if err != nil {
			t.Fatal(err)
		}
		var r struct {
			Body string `json:"body"`
		}
		decode(t, res, &r)
		if r.Body != want {
			t.Errorf("tag %q body = %q", tag, r.Body)
		}
	}
}

// --- search ------------------------------------------------------------------------------

func TestSearchCode(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /search/code": {status: 200, body: `{"total_count":1,"incomplete_results":true,"items":[
		{"name":"up.go","path":"src/up.go","sha":"b1","html_url":"https://github.example.test/x","repository":{"full_name":"example-org/widgets"}}]}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("search_code", map[string]any{"q": "retry language:go", "owner": "example-org", "repo": "widgets"}))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Total int `json:"total_count"`
		Items []struct {
			Path string `json:"path"`
			Repo string `json:"repo"`
		} `json:"items"`
	}
	decode(t, res, &p)
	if p.Total != 1 || len(p.Items) != 1 || p.Items[0].Path != "src/up.go" || p.Items[0].Repo != "example-org/widgets" || !res.Partial {
		t.Errorf("search_code = %+v partial %v", p, res.Partial)
	}
	if got := query(t, srv, "/search/code").Get("q"); got != "repo:example-org/widgets retry language:go" {
		t.Errorf("q = %q", got)
	}
}

func TestSearchRepositoriesAndUsers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /search/repositories": {status: 200, body: `{"total_count":1,"items":[{"full_name":"example-org/widgets","description":"d","stargazers_count":5,"html_url":"https://github.example.test/w","private":true,"default_branch":"main"}]}`},
		"GET /search/users":        {status: 200, body: `{"total_count":0,"items":[]}`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call("search_repositories", map[string]any{"q": "widgets", "sort": "stars"}))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Items []struct {
			FullName string `json:"full_name"`
			Stars    int    `json:"stars"`
			Private  bool   `json:"private"`
		} `json:"items"`
	}
	decode(t, res, &p)
	if len(p.Items) != 1 || p.Items[0].FullName != "example-org/widgets" || p.Items[0].Stars != 5 || !p.Items[0].Private {
		t.Errorf("repos = %+v", p)
	}
	res, err = c.Call(context.Background(), call("search_users", map[string]any{"q": "octo"}))
	if err != nil || !res.Empty {
		t.Errorf("users: res %+v err %v, want empty", res, err)
	}
	if _, err := c.Call(context.Background(), call("search_users", map[string]any{"q": " "})); err == nil {
		t.Error("blank q accepted")
	}
}

// --- create_or_update_file ---------------------------------------------------------------

const putContentsPath = "PUT /repos/example-org/widgets/contents/src/app.go"

const createdFileJSON = `{"content":{"path":"src/app.go","sha":"blob2","html_url":"https://github.example.test/blob"},
	"commit":{"sha":"commit2","html_url":"https://github.example.test/commit2"}}`

func TestCreateOrUpdateFile(t *testing.T) {
	srv := newAPIServer(t, map[string]route{putContentsPath: {status: 200, body: createdFileJSON}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write("create_or_update_file", withArgs(map[string]any{
		"path": "src/app.go", "content": "package main\n", "message": "Add app", "branch": "feature/x", "sha": "blob1",
	})))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, putContentsPath))
	content, _ := base64.StdEncoding.DecodeString(body["content"].(string))
	msg, _ := body["message"].(string)
	if string(content) != "package main\n" || body["branch"] != "feature/x" || body["sha"] != "blob1" {
		t.Errorf("request = %v", body)
	}
	if !strings.HasPrefix(msg, "Add app\n\n") || !strings.Contains(msg, github.CommitTrailer(opID)) {
		t.Errorf("message %q lacks the operation trailer", msg)
	}
	ids := toolNamed(t, c, "create_or_update_file").ResultIDs(res)
	if ids["commit_sha"] != "commit2" || ids["sha"] != "blob2" {
		t.Errorf("ResultIDs = %v", ids)
	}
}

func TestCreateOrUpdateFileValidationAndErrors(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{
		withArgs(map[string]any{"path": "a/../b", "content": "x", "message": "m"}),
		withArgs(map[string]any{"path": "a", "content": "x", "message": " "}),
		withArgs(map[string]any{"path": "a", "content": strings.Repeat("x", github.MaxFileWriteBytes+1), "message": "m"}),
	} {
		if _, err := c.Call(context.Background(), write("create_or_update_file", args)); err == nil {
			t.Errorf("args %v accepted", args["path"])
		}
	}
	for _, tc := range writeErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{putContentsPath: tc.rt})
			res, err := shortTimeout(t, srv).Call(context.Background(), write("create_or_update_file", withArgs(map[string]any{"path": "src/app.go", "content": "x", "message": "m"})))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestCheckFileCommit(t *testing.T) {
	ident := identityWith(map[string]string{"path": "src/app.go", "branch": "feature/x"})
	withTrailer := `[{"sha":"other","commit":{"message":"unrelated"}},{"sha":"commit2","commit":{"message":"Add app\n\n` + github.CommitTrailer(opID) + `"}}]`
	cases := map[string]struct {
		rt      route
		found   string
		missing bool
	}{
		"found":       {rt: route{status: 200, body: withTrailer}, found: "commit2"},
		"not found":   {rt: route{status: 200, body: `[{"sha":"other","commit":{"message":"unrelated"}}]`}, missing: true},
		"empty":       {rt: route{status: 200, body: `[]`}, missing: true},
		"unavailable": {rt: route{status: 500, body: "error_server.json"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET /repos/example-org/widgets/commits": tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := toolNamed(t, c, "create_or_update_file").Reconcile.Check(context.Background(), reconcile("create_or_update_file", ident))
			switch {
			case tc.found != "":
				wantFound(t, res, err, tc.found)
				q := query(t, srv, "/repos/example-org/widgets/commits")
				if q.Get("sha") != "feature/x" || q.Get("path") != "src/app.go" {
					t.Errorf("query = %v", q)
				}
			case tc.missing:
				wantNotFound(t, res, err)
			default:
				if err == nil {
					t.Errorf("Check = %+v, want cannot tell", res)
				}
			}
		})
	}
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	if _, err := toolNamed(t, c, "create_or_update_file").Reconcile.Check(context.Background(), reconcile("create_or_update_file", repoIdentity)); !errors.Is(err, github.ErrNotReconcilable) {
		t.Errorf("Check without a path = %v, want ErrNotReconcilable", err)
	}
}
