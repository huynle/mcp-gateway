package atlassian_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// The Confluence tools added after the v1 set.

const v2 = wikiBase + "/api/v2"

func TestConfluenceMoreToolsMetadata(t *testing.T) {
	page := map[string]any{"id": "123456"}
	pageID := map[string]string{"page": "123456"}
	reads := []metadataCase{
		{
			app: atlassian.ConfluenceApp, tool: "list_spaces", props: []string{"keys", "type", "limit", "cursor"},
			args: map[string]any{"keys": []any{"DOCS"}}, identity: map[string]string{}, scopes: []string{"read:space:confluence"}, page: true,
		},
		{
			app: atlassian.ConfluenceApp, tool: "get_page_children", required: []string{"id"}, props: []string{"id", "limit", "cursor"},
			args: page, identity: pageID, scopes: []string{"read:page:confluence"}, page: true,
		},
		{
			app: atlassian.ConfluenceApp, tool: "get_page_by_title", required: []string{"space_key", "title"}, props: []string{"space_key", "title"},
			args: map[string]any{"space_key": "DOCS", "title": "secret"}, identity: map[string]string{"space": "DOCS"},
			scopes: []string{"read:page:confluence", "read:space:confluence"},
		},
		{
			app: atlassian.ConfluenceApp, tool: "get_page_comments", required: []string{"id"}, props: []string{"id", "kind", "limit", "cursor"},
			args: page, identity: pageID, scopes: []string{"read:comment:confluence"}, page: true,
		},
		{
			app: atlassian.ConfluenceApp, tool: "list_page_attachments", required: []string{"id"}, props: []string{"id", "limit", "cursor"},
			args: page, identity: pageID, scopes: []string{"read:attachment:confluence"}, page: true,
		},
		{
			app: atlassian.ConfluenceApp, tool: "get_page_labels", required: []string{"id"}, props: []string{"id", "limit", "cursor"},
			args: page, identity: pageID, scopes: []string{"read:page:confluence"}, page: true,
		},
		{
			app: atlassian.ConfluenceApp, tool: "get_page_history", required: []string{"id"}, props: []string{"id", "limit", "cursor"},
			args: page, identity: pageID, scopes: []string{"read:page:confluence"}, page: true,
		},
	}
	for _, tc := range reads {
		t.Run(tc.tool, func(t *testing.T) { checkMetadata(t, tc) })
	}
	writes := []struct {
		metadataCase
		kind connectors.ReconcileKind
	}{
		{metadataCase{
			app: atlassian.ConfluenceApp, tool: "update_page", required: []string{"id", "body"}, props: []string{"id", "title", "body", "version_message"},
			args: map[string]any{"id": "123456", "body": "secret"}, identity: pageID, scopes: []string{"write:page:confluence", "read:page:confluence"},
		}, connectors.ReconcileMarker},
		{metadataCase{
			app: atlassian.ConfluenceApp, tool: "add_page_comment", required: []string{"id", "body"}, props: []string{"id", "body", "parent_comment_id"},
			args:     map[string]any{"id": "123456", "body": "secret", "parent_comment_id": "777"},
			identity: map[string]string{"page": "123456", "parent_comment": "777"}, scopes: []string{"write:comment:confluence", "read:comment:confluence"},
		}, connectors.ReconcileMarker},
		{metadataCase{
			app: atlassian.ConfluenceApp, tool: "add_page_labels", required: []string{"id", "labels"}, props: []string{"id", "labels"},
			args:     map[string]any{"id": "123456", "labels": []any{"Release-Notes", "q4"}},
			identity: map[string]string{"page": "123456", "labels": "release-notes,q4"},
			scopes:   []string{"write:label:confluence", "read:label:confluence", "read:page:confluence"},
		}, connectors.ReconcileStableID},
	}
	for _, tc := range writes {
		t.Run(tc.tool, func(t *testing.T) {
			checkMetadata(t, tc.metadataCase)
			c, _ := newConfluence(t, newAPIServer(t, nil), connectors.Bounds{})
			tool := toolNamed(t, c, tc.tool)
			if tool.Kind != connectors.KindWrite || tool.Reconcile.Kind != tc.kind || tool.Reconcile.Check == nil || tool.ResultIDs == nil {
				t.Errorf("kind %q reconcile %q", tool.Kind, tool.Reconcile.Kind)
			}
		})
	}
}

func TestConfluenceToolNames(t *testing.T) {
	c, _ := newConfluence(t, newAPIServer(t, nil), connectors.Bounds{})
	var reads, writes []string
	for _, tool := range c.Tools() {
		if tool.Kind == connectors.KindRead {
			reads = append(reads, tool.Name)
		} else {
			writes = append(writes, tool.Name)
		}
	}
	wantEqual(t, "reads", reads, []string{"search", "get_page", "list_spaces", "get_page_children", "get_page_by_title", "get_page_comments",
		"list_page_attachments", "get_page_labels", "get_page_history"})
	wantEqual(t, "writes", writes, []string{"create_page", "update_page", "add_page_comment", "add_page_labels"})
}

func TestListSpaces(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + v2 + "/spaces": {status: 200, body: `{"results":[
		{"id":"98304","key":"DOCS","name":"Documentation","type":"global","status":"current","homepageId":"65537","_links":{"webui":"/spaces/DOCS"}}],
		"_links":{"next":"/wiki/api/v2/spaces?cursor=abc123&limit=1"}}`}})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "list_spaces", map[string]any{"keys": []any{"DOCS"}, "type": "global", "limit": 1}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Spaces []struct {
			ID         string `json:"id"`
			Key        string `json:"key"`
			Name       string `json:"name"`
			Type       string `json:"type"`
			HomepageID string `json:"homepage_id"`
			URL        string `json:"url"`
		} `json:"spaces"`
		HasMore    bool   `json:"has_more"`
		NextCursor string `json:"next_cursor"`
	}
	decode(t, res, &got)
	if len(got.Spaces) != 1 || got.Spaces[0].Key != "DOCS" || got.Spaces[0].HomepageID != "65537" || got.Spaces[0].URL != siteURL+"/wiki/spaces/DOCS" {
		t.Errorf("spaces = %+v", got.Spaces)
	}
	if !got.HasMore || got.NextCursor != "abc123" {
		t.Errorf("paging = %+v", got)
	}
	q := query(t, srv, v2+"/spaces")
	if q.Get("keys") != "DOCS" || q.Get("type") != "global" || q.Get("limit") != "1" {
		t.Errorf("query = %v", q)
	}
	if _, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "list_spaces", map[string]any{"cursor": "abc123"})); err != nil {
		t.Fatal(err)
	}
	if q := query(t, srv, v2+"/spaces"); q.Get("cursor") != "abc123" {
		t.Errorf("cursor not passed: %v", q)
	}
}

func TestGetPageChildren(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + v2 + "/pages/123456/children": {status: 200, body: `{"results":[
		{"id":"123457","title":"Child one","status":"current","spaceId":"98304","childPosition":0}],"_links":{}}`}})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_children", map[string]any{"id": "123456"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Parent   string `json:"parent_id"`
		Children []struct {
			ID, Title, Status string
		} `json:"children"`
		HasMore bool `json:"has_more"`
	}
	decode(t, res, &got)
	if got.Parent != "123456" || len(got.Children) != 1 || got.Children[0].Title != "Child one" || got.HasMore {
		t.Errorf("children = %+v", got)
	}
}

func TestGetPageByTitle(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + v2 + "/spaces": {status: 200, body: "spaces_docs.json"},
		"GET " + v2 + "/pages": {status: 200, body: `{"results":[{"id":"123456","title":"Release notes","status":"current","spaceId":"98304",
			"version":{"number":4},"body":{"storage":{"representation":"storage","value":"<p>Hello</p>"}},"_links":{"webui":"/spaces/DOCS/pages/123456"}}]}`},
	})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_by_title", map[string]any{"space_key": "DOCS", "title": "Release notes"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ID, Title, Body string
		Version         int
	}
	decode(t, res, &got)
	if got.ID != "123456" || got.Body != "<p>Hello</p>" || got.Version != 4 {
		t.Errorf("page = %+v", got)
	}
	q := query(t, srv, v2+"/pages")
	if q.Get("title") != "Release notes" || q.Get("space-id") == "" || q.Get("body-format") != "storage" {
		t.Errorf("query = %v", q)
	}
	srv = newAPIServer(t, map[string]route{"GET " + v2 + "/spaces": {status: 200, body: "spaces_docs.json"}, "GET " + v2 + "/pages": {status: 200, body: `{"results":[]}`}})
	c, _ = newConfluence(t, srv, connectors.Bounds{})
	_, err = c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_by_title", map[string]any{"space_key": "DOCS", "title": "Nope"}))
	wantClass(t, err, atlassian.ClassNotFound, 0)
}

func TestGetPageComments(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + v2 + "/pages/123456/footer-comments": {status: 200, body: `{"results":[{"id":"777","status":"current","version":{"authorId":"a1","createdAt":"2026-10-01T10:00:00.000Z"},
			"body":{"storage":{"value":"<p>Looks good</p>"}},"_links":{"webui":"/spaces/DOCS/pages/123456?focusedCommentId=777"}}],"_links":{}}`},
		"GET " + v2 + "/pages/123456/inline-comments": {status: 200, body: `{"results":[{"id":"778","resolutionStatus":"open","properties":{"inlineOriginalSelection":"typo here"},
			"version":{"authorId":"b2"},"body":{"storage":{"value":"<p>Fix</p>"}}}],"_links":{}}`},
	})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_comments", map[string]any{"id": "123456"}))
	if err != nil {
		t.Fatal(err)
	}
	type comments struct {
		Kind     string `json:"kind"`
		Comments []struct {
			ID         string `json:"id"`
			AuthorID   string `json:"author_id"`
			CreatedAt  string `json:"created_at"`
			Body       string `json:"body"`
			Resolution string `json:"resolution_status"`
			Selection  string `json:"inline_selection"`
			URL        string `json:"url"`
		} `json:"comments"`
	}
	var got comments
	decode(t, res, &got)
	if got.Kind != "footer" || len(got.Comments) != 1 || got.Comments[0].Body != "<p>Looks good</p>" || got.Comments[0].AuthorID != "a1" || got.Comments[0].CreatedAt != "2026-10-01T10:00:00Z" || got.Comments[0].URL == "" {
		t.Errorf("footer = %+v", got)
	}
	if q := query(t, srv, v2+"/pages/123456/footer-comments"); q.Get("body-format") != "storage" {
		t.Errorf("query = %v", q)
	}
	res, err = c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_comments", map[string]any{"id": "123456", "kind": "inline"}))
	if err != nil {
		t.Fatal(err)
	}
	got = comments{}
	decode(t, res, &got)
	if got.Kind != "inline" || len(got.Comments) != 1 || got.Comments[0].Resolution != "open" || got.Comments[0].Selection != "typo here" {
		t.Errorf("inline = %+v", got)
	}
	if _, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_comments", map[string]any{"id": "123456", "kind": "page"})); err == nil {
		t.Error("bad kind accepted")
	}
}

func TestListPageAttachmentsLabelsHistory(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + v2 + "/pages/123456/attachments": {status: 200, body: `{"results":[{"id":"att1","title":"diagram.png","mediaType":"image/png","fileSize":2048,
			"comment":"v2","createdAt":"2026-10-01T10:00:00.000Z","downloadLink":"/download/attachments/123456/diagram.png","webuiLink":"/pages/viewpageattachments.action?pageId=123456"}],"_links":{}}`},
		"GET " + v2 + "/pages/123456/labels":   {status: 200, body: `{"results":[{"id":"9","name":"release-notes","prefix":"global"}],"_links":{}}`},
		"GET " + v2 + "/pages/123456/versions": {status: 200, body: `{"results":[{"number":4,"authorId":"a1","message":"typo","createdAt":"2026-10-02T10:00:00.000Z","minorEdit":true}],"_links":{}}`},
	})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "list_page_attachments", map[string]any{"id": "123456"}))
	if err != nil {
		t.Fatal(err)
	}
	var att struct {
		Attachments []struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			MediaType   string `json:"media_type"`
			FileSize    int    `json:"file_size"`
			DownloadURL string `json:"download_url"`
		} `json:"attachments"`
	}
	decode(t, res, &att)
	if len(att.Attachments) != 1 || att.Attachments[0].FileSize != 2048 || att.Attachments[0].MediaType != "image/png" || att.Attachments[0].DownloadURL != siteURL+"/wiki/download/attachments/123456/diagram.png" {
		t.Errorf("attachments = %+v", att)
	}
	res, err = c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_labels", map[string]any{"id": "123456"}))
	if err != nil {
		t.Fatal(err)
	}
	var labels struct {
		Labels []struct{ ID, Name, Prefix string } `json:"labels"`
	}
	decode(t, res, &labels)
	if len(labels.Labels) != 1 || labels.Labels[0].Name != "release-notes" {
		t.Errorf("labels = %+v", labels)
	}
	res, err = c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_history", map[string]any{"id": "123456"}))
	if err != nil {
		t.Fatal(err)
	}
	var hist struct {
		Versions []struct {
			Number    int    `json:"number"`
			AuthorID  string `json:"author_id"`
			Message   string `json:"message"`
			CreatedAt string `json:"created_at"`
			MinorEdit bool   `json:"minor_edit"`
		} `json:"versions"`
	}
	decode(t, res, &hist)
	if len(hist.Versions) != 1 || hist.Versions[0].Number != 4 || !hist.Versions[0].MinorEdit || hist.Versions[0].Message != "typo" {
		t.Errorf("history = %+v", hist)
	}
	for _, tool := range []string{"get_page_children", "get_page_comments", "list_page_attachments", "get_page_labels", "get_page_history"} {
		if _, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, tool, map[string]any{"id": "x/../1"})); err == nil {
			t.Errorf("%s: bad id accepted", tool)
		}
	}
}

func TestConfluenceMoreReadsUnavailable(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET " + v2 + "/pages/123456/labels": {status: 502}})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), call(atlassian.ConfluenceApp, "get_page_labels", map[string]any{"id": "123456"}))
	if err != nil || !res.Unavailable {
		t.Errorf("res = %+v err = %v, want Unavailable", res, err)
	}
}

// --- writes -----------------------------------------------------------------------------------

const pageV2Path = v2 + "/pages/123456"

func TestUpdatePageAndCheck(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET " + pageV2Path: {status: 200, body: `{"id":"123456","title":"Old title","status":"current","spaceId":"98304","version":{"number":4},
			"body":{"storage":{"value":"<p>new</p>\n<p>` + marker + `</p>"}}}`},
		"PUT " + pageV2Path: {status: 200, body: `{"id":"123456","version":{"number":5},"_links":{"webui":"/spaces/DOCS/pages/123456"}}`},
	})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "update_page", map[string]any{"id": "123456", "body": "new", "version_message": "via gateway"}))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, "PUT "+pageV2Path))
	ver, _ := body["version"].(map[string]any)
	b, _ := body["body"].(map[string]any)
	if body["id"] != "123456" || body["title"] != "Old title" || body["status"] != "current" || ver["number"] != float64(5) || ver["message"] != "via gateway" {
		t.Errorf("body = %v", body)
	}
	if b["representation"] != "storage" || b["value"] != "<p>new</p>\n<p>"+marker+"</p>" {
		t.Errorf("page body = %v", b)
	}
	if ids := toolNamed(t, c, "update_page").ResultIDs(res); ids["id"] != "123456" || ids["version"] != "5" || ids["url"] != siteURL+"/wiki/spaces/DOCS/pages/123456" {
		t.Errorf("ResultIDs = %v", ids)
	}
	check := toolNamed(t, c, "update_page").Reconcile.Check
	r, err := check(context.Background(), reconcile(atlassian.ConfluenceApp, "update_page", map[string]string{"page": "123456"}))
	wantFound(t, r, err, "123456")
	if _, err := check(context.Background(), reconcile(atlassian.ConfluenceApp, "update_page", map[string]string{})); !errors.Is(err, atlassian.ErrNotReconcilable) {
		t.Errorf("err = %v", err)
	}
}

func TestUpdatePageErrors(t *testing.T) {
	get := route{status: 200, body: `{"id":"123456","title":"T","status":"current","version":{"number":1}}`}
	for _, tc := range writeErrorCases(route{status: 200, body: `{"id":"123456","version":{"number":2}}`}) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + pageV2Path: get, "PUT " + pageV2Path: tc.rt})
			c := newWriter(t, atlassian.ConfluenceApp, srv)
			res, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "update_page", map[string]any{"id": "123456", "body": "b"}))
			checkWriteError(t, "confluence", tc, res, err)
		})
	}
	t.Run("lookup failure is known", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET " + pageV2Path: {status: 404, body: "error_confluence_not_found.json"}})
		c, _ := newConfluence(t, srv, connectors.Bounds{})
		_, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "update_page", map[string]any{"id": "123456", "body": "b"}))
		wantClass(t, err, atlassian.ClassNotFound, 404)
		if srv.Count("PUT "+pageV2Path) != 0 {
			t.Error("PUT sent after a failed lookup")
		}
	})
}

func TestAddPageCommentAndCheck(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"POST " + v2 + "/footer-comments": {status: 200, body: `{"id":"779","_links":{"webui":"/spaces/DOCS/pages/123456?focusedCommentId=779"}}`},
		"GET " + v2 + "/pages/123456/footer-comments": {pageParam: "cursor", pages: map[string]route{
			"":   {status: 200, body: `{"results":[{"id":"777","body":{"storage":{"value":"<p>old</p>"}}}],"_links":{"next":"/wiki/api/v2/pages/123456/footer-comments?cursor=c2"}}`},
			"c2": {status: 200, body: `{"results":[{"id":"779","body":{"storage":{"value":"<p>` + marker + `</p>"}}}],"_links":{}}`},
		}},
		"GET " + v2 + "/footer-comments/777/children": {status: 200, body: `{"results":[],"_links":{}}`},
	})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "add_page_comment", map[string]any{"id": "123456", "body": "Nice <work>"}))
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, srv.Last(t, "POST "+v2+"/footer-comments"))
	b, _ := body["body"].(map[string]any)
	if body["pageId"] != "123456" || b["representation"] != "storage" || b["value"] != "<p>Nice &lt;work&gt;</p>\n<p>"+marker+"</p>" {
		t.Errorf("body = %v", body)
	}
	if ids := toolNamed(t, c, "add_page_comment").ResultIDs(res); ids["id"] != "779" || ids["page"] != "123456" {
		t.Errorf("ResultIDs = %v", ids)
	}
	check := toolNamed(t, c, "add_page_comment").Reconcile.Check
	r, err := check(context.Background(), reconcile(atlassian.ConfluenceApp, "add_page_comment", map[string]string{"page": "123456"}))
	wantFound(t, r, err, "779")
	r, err = check(context.Background(), reconcile(atlassian.ConfluenceApp, "add_page_comment", map[string]string{"page": "123456", "parent_comment": "777"}))
	wantNotFound(t, r, err)

	if _, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "add_page_comment", map[string]any{"id": "123456", "body": "reply", "parent_comment_id": "777"})); err != nil {
		t.Fatal(err)
	}
	reply := jsonBody(t, srv.Last(t, "POST "+v2+"/footer-comments"))
	if reply["parentCommentId"] != "777" || reply["pageId"] != nil {
		t.Errorf("reply body = %v", reply)
	}
}

func TestAddPageLabelsAndCheck(t *testing.T) {
	labelPath := "POST " + wikiBase + "/rest/api/content/123456/label"
	srv := newAPIServer(t, map[string]route{
		labelPath:                            {status: 200, body: `{"results":[{"name":"release-notes"},{"name":"q4"}]}`},
		"GET " + v2 + "/pages/123456/labels": {status: 200, body: `{"results":[{"name":"release-notes"},{"name":"q4"}],"_links":{}}`},
	})
	c, _ := newConfluence(t, srv, connectors.Bounds{})
	res, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "add_page_labels", map[string]any{"id": "123456", "labels": []any{"Release-Notes", "q4"}}))
	if err != nil {
		t.Fatal(err)
	}
	if b := strings.TrimSpace(srv.Last(t, labelPath).Body); b != `[{"prefix":"global","name":"release-notes"},{"prefix":"global","name":"q4"}]` {
		t.Errorf("body = %s", b)
	}
	if ids := toolNamed(t, c, "add_page_labels").ResultIDs(res); ids["page"] != "123456" || ids["labels"] != "release-notes,q4" {
		t.Errorf("ResultIDs = %v", ids)
	}
	check := toolNamed(t, c, "add_page_labels").Reconcile.Check
	r, err := check(context.Background(), reconcile(atlassian.ConfluenceApp, "add_page_labels", map[string]string{"page": "123456", "labels": "release-notes,q4"}))
	wantFound(t, r, err, "123456")
	r, err = check(context.Background(), reconcile(atlassian.ConfluenceApp, "add_page_labels", map[string]string{"page": "123456", "labels": "missing"}))
	wantNotFound(t, r, err)
	for _, bad := range []map[string]any{{"id": "123456"}, {"id": "123456", "labels": []any{"two words"}}} {
		if _, err := c.Call(context.Background(), write(atlassian.ConfluenceApp, "add_page_labels", bad)); err == nil {
			t.Errorf("args %v accepted", bad)
		}
	}
}
