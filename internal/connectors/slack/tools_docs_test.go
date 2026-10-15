package slack_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// jsonBody decodes the JSON body of a recorded request.
func jsonBody(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("%s body %q: %v", r.Method, r.Body, err)
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Errorf("%s Content-Type = %q", r.Method, r.Header.Get("Content-Type"))
	}
	return m
}

func TestDocToolsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	r, w, none := connectors.KindRead, connectors.KindWrite, connectors.ReconcileNone
	canvas := map[string]string{"canvas": "F0CANVAS01"}
	list := map[string]string{"list": "F0LIST0001"}
	checkToolCases(t, c, []toolCase{
		{tool: "read_canvas", kind: r, scopes: []string{"canvases:read"}, required: []string{"canvas"},
			props: []string{"canvas"}, args: map[string]any{"canvas": "F0CANVAS01"}, identity: canvas},
		{tool: "create_canvas", kind: w, rec: none, scopes: []string{"canvases:write"}, required: nil,
			props: []string{"title", "markdown", "channel"}, args: map[string]any{"title": "secret", "markdown": "secret", "channel": "C0ENGGEN01"},
			identity: map[string]string{"channel": "C0ENGGEN01", "channel_id": "C0ENGGEN01"}},
		{tool: "update_canvas", kind: w, rec: none, scopes: []string{"canvases:write"}, required: []string{"canvas", "operation"},
			props:    []string{"canvas", "operation", "markdown", "section_id", "section_text"},
			args:     map[string]any{"canvas": "F0CANVAS01", "operation": "insert_at_end", "markdown": "secret"},
			identity: map[string]string{"canvas": "F0CANVAS01", "operation": "insert_at_end"}},
		{tool: "read_list", kind: r, scopes: []string{"lists:read"}, required: []string{"list"},
			props: []string{"list", "limit", "cursor", "archived"}, args: map[string]any{"list": "F0LIST0001"}, identity: list},
		{tool: "create_list", kind: w, rec: none, scopes: []string{"lists:write"}, required: []string{"name"},
			props: []string{"name", "description", "columns", "todo_mode"}, args: map[string]any{"name": "secret"}, identity: map[string]string{}},
		{tool: "update_list", kind: w, rec: none, scopes: []string{"lists:write"}, required: []string{"list"},
			props: []string{"list", "name", "description", "todo_mode"}, args: map[string]any{"list": "F0LIST0001", "name": "secret"}, identity: list},
		{tool: "add_list_item", kind: w, rec: none, scopes: []string{"lists:read", "lists:write"}, required: []string{"list", "fields"},
			props: []string{"list", "fields", "parent_item"}, args: map[string]any{"list": "F0LIST0001", "fields": map[string]any{"Title": "secret"}}, identity: list},
		{tool: "update_list_item", kind: w, rec: none, scopes: []string{"lists:read", "lists:write"}, required: []string{"list", "item", "fields"},
			props: []string{"list", "item", "fields"}, args: map[string]any{"list": "F0LIST0001", "item": "Rec0ITEM001", "fields": map[string]any{"Title": "secret"}},
			identity: map[string]string{"list": "F0LIST0001", "item": "Rec0ITEM001"}},
	})
	if got := toolNamed(t, c, "update_canvas").OptionalScopes; strings.Join(got, ",") != "canvases:read" {
		t.Errorf("update_canvas optional scopes = %v (section_text looks a section up)", got)
	}
}

func TestReadCanvas(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"canvases.getContent": {body: `{"ok":true,"content":"# Plan\n\n- [ ] spec\n"}`}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("read_canvas", map[string]any{"canvas": "f0canvas01"}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Canvas, Markdown string
		Truncated        bool
	}
	decode(t, res, &got)
	if got.Canvas != "F0CANVAS01" || got.Markdown != "# Plan\n\n- [ ] spec\n" || got.Truncated {
		t.Errorf("content = %+v", got)
	}
	req := srv.Last(t, "canvases.getContent")
	if b := jsonBody(t, req); b["canvas_id"] != "F0CANVAS01" || b["content_type"] != "markdown" {
		t.Errorf("body = %v", b)
	}
	if req.Header.Get("Authorization") != "Bearer "+testToken {
		t.Error("the token travels as a bearer header")
	}

	big := strings.Repeat("x", 300<<10)
	srv2 := newAPIServer(t, map[string]route{"canvases.getContent": {body: `{"ok":true,"content":"` + big + `"}`}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	res, _ = c2.Call(context.Background(), call("read_canvas", map[string]any{"canvas": "F0CANVAS01"}))
	decode(t, res, &got)
	if !got.Truncated || !res.Partial || len(got.Markdown) >= len(big) {
		t.Errorf("big canvas: truncated %v partial %v len %d", got.Truncated, res.Partial, len(got.Markdown))
	}

	srv3 := newAPIServer(t, map[string]route{"canvases.getContent": {body: `{"ok":false,"error":"canvas_not_found"}`}})
	c3, _ := newConnector(t, srv3, slack.Options{})
	_, err = c3.Call(context.Background(), call("read_canvas", map[string]any{"canvas": "F0CANVAS01"}))
	wantClass(t, err, slack.ClassNotFound)

	srv4 := newAPIServer(t, map[string]route{"canvases.getContent": {status: 429, headers: map[string]string{"Retry-After": "7"}}})
	c4, _ := newConnector(t, srv4, slack.Options{})
	_, err = c4.Call(context.Background(), call("read_canvas", map[string]any{"canvas": "F0CANVAS01"}))
	var rl *connectors.RateLimited
	if !errors.As(err, &rl) || rl.RetryAfter.Seconds() != 7 {
		t.Errorf("429: %v", err)
	}

	srv5 := newAPIServer(t, map[string]route{"canvases.getContent": {status: 503}})
	c5, _ := newConnector(t, srv5, slack.Options{})
	res, err = c5.Call(context.Background(), call("read_canvas", map[string]any{"canvas": "F0CANVAS01"}))
	if err != nil || !res.Unavailable {
		t.Errorf("503: err %v unavailable %v", err, res.Unavailable)
	}
}

func TestCreateCanvas(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"canvases.create": {body: `{"ok":true,"canvas_id":"F0CANVAS01"}`}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("create_canvas", map[string]any{"title": "Plan", "markdown": "# Plan", "channel": "C0ENGGEN01"}))
	if err != nil {
		t.Fatal(err)
	}
	b := jsonBody(t, srv.Last(t, "canvases.create"))
	doc, _ := b["document_content"].(map[string]any)
	if b["title"] != "Plan" || b["channel_id"] != "C0ENGGEN01" || doc["type"] != "markdown" || doc["markdown"] != "# Plan" {
		t.Errorf("body = %v", b)
	}
	if ids := toolNamed(t, c, "create_canvas").ResultIDs(res); ids["canvas"] != "F0CANVAS01" {
		t.Errorf("ResultIDs = %v", ids)
	}

	srv2 := newAPIServer(t, map[string]route{"canvases.create": {body: `{"ok":true,"canvas_id":"F0CANVAS02"}`}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	if _, err := c2.Call(context.Background(), write("create_canvas", map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if b := jsonBody(t, srv2.Last(t, "canvases.create")); len(b) != 0 {
		t.Errorf("empty canvas body = %v", b)
	}

	srv3 := newAPIServer(t, map[string]route{"canvases.create": {status: 502}})
	c3, _ := newConnector(t, srv3, slack.Options{})
	if _, err := c3.Call(context.Background(), write("create_canvas", map[string]any{"title": "x"})); !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("502: %v, want outcome unknown", err)
	}
	srv4 := newAPIServer(t, map[string]route{"canvases.create": {body: `{"ok":false,"error":"canvas_creation_failed"}`}})
	c4, _ := newConnector(t, srv4, slack.Options{})
	_, err = c4.Call(context.Background(), write("create_canvas", map[string]any{"title": "x"}))
	wantClass(t, err, slack.ClassInvalidArgument)

	c5, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	_, err = c5.Call(context.Background(), write("create_canvas", map[string]any{"markdown": strings.Repeat("x", slack.MaxCanvasMarkdown+1)}))
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestUpdateCanvas(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"canvases.edit": {body: "ok.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("update_canvas", map[string]any{"canvas": "F0CANVAS01", "operation": "insert_at_end", "markdown": "- more"}))
	if err != nil {
		t.Fatal(err)
	}
	b := jsonBody(t, srv.Last(t, "canvases.edit"))
	changes, _ := b["changes"].([]any)
	ch, _ := changes[0].(map[string]any)
	doc, _ := ch["document_content"].(map[string]any)
	if b["canvas_id"] != "F0CANVAS01" || len(changes) != 1 || ch["operation"] != "insert_at_end" || doc["markdown"] != "- more" || ch["section_id"] != nil {
		t.Errorf("body = %v", b)
	}
	if ids := toolNamed(t, c, "update_canvas").ResultIDs(res); ids["canvas"] != "F0CANVAS01" {
		t.Errorf("ResultIDs = %v", ids)
	}

	// rename uses title_content.
	srv2 := newAPIServer(t, map[string]route{"canvases.edit": {body: "ok.json"}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	if _, err := c2.Call(context.Background(), write("update_canvas", map[string]any{"canvas": "F0CANVAS01", "operation": "rename", "markdown": "New title"})); err != nil {
		t.Fatal(err)
	}
	ch = jsonBody(t, srv2.Last(t, "canvases.edit"))["changes"].([]any)[0].(map[string]any)
	if title, _ := ch["title_content"].(map[string]any); title["markdown"] != "New title" || ch["document_content"] != nil {
		t.Errorf("rename change = %v", ch)
	}

	// section_text looks the section up first; exactly one must match.
	srv3 := newAPIServer(t, map[string]route{
		"canvases.sections.lookup": {body: `{"ok":true,"sections":[{"id":"temp:C:abc"}]}`},
		"canvases.edit":            {body: "ok.json"},
	})
	c3, _ := newConnector(t, srv3, slack.Options{})
	if _, err := c3.Call(context.Background(), write("update_canvas", map[string]any{"canvas": "F0CANVAS01", "operation": "delete", "section_text": "Old notes"})); err != nil {
		t.Fatal(err)
	}
	crit := jsonBody(t, srv3.Last(t, "canvases.sections.lookup"))["criteria"].(map[string]any)
	if crit["contains_text"] != "Old notes" {
		t.Errorf("lookup criteria = %v", crit)
	}
	ch = jsonBody(t, srv3.Last(t, "canvases.edit"))["changes"].([]any)[0].(map[string]any)
	if ch["section_id"] != "temp:C:abc" || ch["operation"] != "delete" || ch["document_content"] != nil {
		t.Errorf("delete change = %v", ch)
	}

	srv4 := newAPIServer(t, map[string]route{"canvases.sections.lookup": {body: `{"ok":true,"sections":[{"id":"a"},{"id":"b"}]}`}})
	c4, _ := newConnector(t, srv4, slack.Options{})
	_, err = c4.Call(context.Background(), write("update_canvas", map[string]any{"canvas": "F0CANVAS01", "operation": "replace", "markdown": "x", "section_text": "dup"}))
	wantClass(t, err, slack.ClassInvalidArgument)
	if srv4.Count("canvases.edit") != 0 {
		t.Error("an ambiguous section must not be edited")
	}

	for name, args := range map[string]map[string]any{
		"bad op":              {"canvas": "F0CANVAS01", "operation": "append", "markdown": "x"},
		"insert no markdown":  {"canvas": "F0CANVAS01", "operation": "insert_at_start"},
		"after no section":    {"canvas": "F0CANVAS01", "operation": "insert_after", "markdown": "x"},
		"delete no section":   {"canvas": "F0CANVAS01", "operation": "delete"},
		"delete and markdown": {"canvas": "F0CANVAS01", "operation": "delete", "section_id": "temp:C:abc", "markdown": "x"},
		"bad canvas":          {"canvas": "C0ENGGEN01", "operation": "insert_at_end", "markdown": "x"},
		"both section args":   {"canvas": "F0CANVAS01", "operation": "replace", "markdown": "x", "section_id": "temp:C:abc", "section_text": "y"},
	} {
		srv := newAPIServer(t, nil)
		c, _ := newConnector(t, srv, slack.Options{})
		_, err := c.Call(context.Background(), write("update_canvas", args))
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		wantClass(t, err, slack.ClassInvalidArgument)
	}

	srv5 := newAPIServer(t, map[string]route{"canvases.edit": {status: 500}})
	c5, _ := newConnector(t, srv5, slack.Options{})
	if _, err := c5.Call(context.Background(), write("update_canvas", map[string]any{"canvas": "F0CANVAS01", "operation": "insert_at_end", "markdown": "x"})); !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Errorf("500: %v", err)
	}
}

// listItems is a slackLists.items.list answer with the list's schema.
const listItems = `{"ok":true,
	"list":{"id":"F0LIST0001","title":"Sprint Board","list_metadata":{"schema":[
		{"id":"Col0TITLE1","key":"title","name":"Title","type":"text","is_primary_column":true},
		{"id":"Col0STATUS","key":"status","name":"Status","type":"select","options":{"choices":[{"value":"todo","label":"To do"},{"value":"done","label":"Done"}]}},
		{"id":"Col0OWNER1","key":"owner","name":"Owner","type":"user"},
		{"id":"Col0DUE001","key":"due","name":"Due","type":"date"},
		{"id":"Col0EST001","key":"estimate","name":"Estimate","type":"number"},
		{"id":"Col0DONE01","key":"ready","name":"Ready?","type":"checkbox"},
		{"id":"Col0VOTE01","key":"vote","name":"Vote","type":"vote"}]}},
	"items":[{"id":"Rec0ITEM001","list_id":"F0LIST0001","date_created":1700000000,"created_by":"U0ALICE001","updated_by":"U0BOB00002",
		"fields":[{"key":"title","column_id":"Col0TITLE1","text":"Ship it","value":"[]"},{"key":"status","column_id":"Col0STATUS","value":"done","select":["done"]}]}],
	"response_metadata":{"next_cursor":"bmV4dA=="}}`

func TestReadList(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"slackLists.items.list": {body: listItems}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), call("read_list", map[string]any{"list": "F0LIST0001", "limit": 10, "archived": true}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		List struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Columns []struct {
				ID, Key, Name, Type string
				Choices             []string `json:"choices"`
			} `json:"columns"`
		} `json:"list"`
		Items []struct {
			ID        string `json:"id"`
			CreatedBy string `json:"created_by"`
			Created   string `json:"created"`
			Fields    []struct {
				Column string `json:"column"`
				Key    string `json:"key"`
				Text   string `json:"text"`
				Value  any    `json:"value"`
			} `json:"fields"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
		HasMore    bool   `json:"has_more"`
	}
	decode(t, res, &got)
	if got.List.ID != "F0LIST0001" || got.List.Title != "Sprint Board" || len(got.List.Columns) != 7 || got.List.Columns[1].Name != "Status" ||
		strings.Join(got.List.Columns[1].Choices, ",") != "todo=To do,done=Done" {
		t.Errorf("list = %+v", got.List)
	}
	if len(got.Items) != 1 || got.Items[0].ID != "Rec0ITEM001" || got.Items[0].CreatedBy != "U0ALICE001" || got.Items[0].Created != "2023-11-14T22:13:20Z" ||
		len(got.Items[0].Fields) != 2 || got.Items[0].Fields[0].Column != "Col0TITLE1" || got.Items[0].Fields[0].Text != "Ship it" || got.Items[0].Fields[1].Value != "done" {
		t.Errorf("items = %+v", got.Items)
	}
	if got.NextCursor != "bmV4dA==" || !got.HasMore {
		t.Errorf("paging = %+v", got)
	}
	if b := jsonBody(t, srv.Last(t, "slackLists.items.list")); b["list_id"] != "F0LIST0001" || b["limit"] != 10.0 || b["include_list"] != true || b["archived"] != true {
		t.Errorf("body = %v", b)
	}

	srv2 := newAPIServer(t, map[string]route{"slackLists.items.list": {body: `{"ok":false,"error":"list_not_found"}`}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	_, err = c2.Call(context.Background(), call("read_list", map[string]any{"list": "F0LIST0001"}))
	wantClass(t, err, slack.ClassNotFound)
}

func TestCreateList(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"slackLists.create": {body: `{"ok":true,"list_id":"F0LIST0001"}`}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("create_list", map[string]any{
		"name": "Sprint", "description": "Work for the sprint", "todo_mode": true,
		"columns": []any{
			map[string]any{"name": "Task", "type": "text"},
			map[string]any{"name": "Status", "type": "select", "choices": []any{"To do", "Done"}},
			map[string]any{"name": "Labels", "type": "multi_select", "choices": []any{"P0"}},
			map[string]any{"name": "Owner", "type": "user"},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	b := jsonBody(t, srv.Last(t, "slackLists.create"))
	schema, _ := b["schema"].([]any)
	if b["name"] != "Sprint" || b["todo_mode"] != true || len(schema) != 4 {
		t.Fatalf("body = %v", b)
	}
	first, status, labels := schema[0].(map[string]any), schema[1].(map[string]any), schema[2].(map[string]any)
	if first["is_primary_column"] != true || first["key"] != "task" || first["type"] != "text" {
		t.Errorf("primary column = %v", first)
	}
	opts, _ := status["options"].(map[string]any)
	choices, _ := opts["choices"].([]any)
	if status["type"] != "select" || opts["format"] != "single_select" || len(choices) != 2 || choices[1].(map[string]any)["label"] != "Done" || choices[1].(map[string]any)["value"] != "done" {
		t.Errorf("select column = %v", status)
	}
	if lo, _ := labels["options"].(map[string]any); labels["type"] != "select" || lo["format"] != "multi_select" {
		t.Errorf("multi_select column = %v", labels)
	}
	if !strings.Contains(string(srv.Last(t, "slackLists.create").Body), "Work for the sprint") {
		t.Error("description not sent as rich text")
	}
	if ids := toolNamed(t, c, "create_list").ResultIDs(res); ids["list"] != "F0LIST0001" {
		t.Errorf("ResultIDs = %v", ids)
	}

	for name, args := range map[string]map[string]any{
		"no name":           {"name": " "},
		"bad type":          {"name": "x", "columns": []any{map[string]any{"name": "A", "type": "hologram"}}},
		"no col name":       {"name": "x", "columns": []any{map[string]any{"type": "text"}}},
		"first not text":    {"name": "x", "columns": []any{map[string]any{"name": "Owner", "type": "user"}}},
		"columns not array": {"name": "x", "columns": "Title"},
	} {
		c, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
		_, err := c.Call(context.Background(), write("create_list", args))
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		wantClass(t, err, slack.ClassInvalidArgument)
	}
}

func TestUpdateList(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"slackLists.update": {body: "ok.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("update_list", map[string]any{"list": "F0LIST0001", "name": "Renamed", "todo_mode": false}))
	if err != nil {
		t.Fatal(err)
	}
	if b := jsonBody(t, srv.Last(t, "slackLists.update")); b["id"] != "F0LIST0001" || b["name"] != "Renamed" || b["todo_mode"] != false || b["description_blocks"] != nil {
		t.Errorf("body = %v", b)
	}
	if ids := toolNamed(t, c, "update_list").ResultIDs(res); ids["list"] != "F0LIST0001" {
		t.Errorf("ResultIDs = %v", ids)
	}
	c2, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	_, err = c2.Call(context.Background(), write("update_list", map[string]any{"list": "F0LIST0001"}))
	wantClass(t, err, slack.ClassInvalidArgument)
}

func TestAddListItem(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"slackLists.items.list":   {body: listItems},
		"slackLists.items.create": {body: `{"ok":true,"item":{"id":"Rec0ITEM009","list_id":"F0LIST0001"}}`},
	})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("add_list_item", map[string]any{"list": "F0LIST0001", "parent_item": "Rec0ITEM001", "fields": map[string]any{
		"Title": "Write docs", "status": "Done", "Col0OWNER1": "<@U0ALICE001>", "due": "2030-01-02", "Estimate": 3.5, "ready?": true,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	if b := jsonBody(t, srv.Last(t, "slackLists.items.list")); b["limit"] != 1.0 || b["include_list"] != true {
		t.Errorf("schema lookup body = %v", b)
	}
	b := jsonBody(t, srv.Last(t, "slackLists.items.create"))
	if b["list_id"] != "F0LIST0001" || b["parent_item_id"] != "Rec0ITEM001" {
		t.Errorf("body = %v", b)
	}
	fields := map[string]map[string]any{}
	for _, f := range b["initial_fields"].([]any) {
		m := f.(map[string]any)
		fields[m["column_id"].(string)] = m
	}
	raw, _ := json.Marshal(fields["Col0TITLE1"]["rich_text"])
	if !strings.Contains(string(raw), `"text":"Write docs"`) || !strings.Contains(string(raw), `"rich_text_section"`) {
		t.Errorf("text field = %s", raw)
	}
	if v, _ := fields["Col0STATUS"]["select"].([]any); len(v) != 1 || v[0] != "done" {
		t.Errorf("select (label resolved to value) = %v", fields["Col0STATUS"])
	}
	if v, _ := fields["Col0OWNER1"]["user"].([]any); len(v) != 1 || v[0] != "U0ALICE001" {
		t.Errorf("user = %v", fields["Col0OWNER1"])
	}
	if v, _ := fields["Col0DUE001"]["date"].([]any); len(v) != 1 || v[0] != "2030-01-02" {
		t.Errorf("date = %v", fields["Col0DUE001"])
	}
	if v, _ := fields["Col0EST001"]["number"].([]any); len(v) != 1 || v[0] != 3.5 {
		t.Errorf("number = %v", fields["Col0EST001"])
	}
	if fields["Col0DONE01"]["checkbox"] != true {
		t.Errorf("checkbox = %v", fields["Col0DONE01"])
	}
	if ids := toolNamed(t, c, "add_list_item").ResultIDs(res); ids["list"] != "F0LIST0001" || ids["item"] != "Rec0ITEM009" {
		t.Errorf("ResultIDs = %v", ids)
	}

	for name, fields := range map[string]map[string]any{
		"unknown column":     {"Nope": "x"},
		"unknown choice":     {"Status": "Blocked"},
		"bad date":           {"Due": "tomorrow"},
		"bad user":           {"Owner": "alice"},
		"bad number":         {"Estimate": "lots"},
		"unsupported column": {"Vote": 1},
		"empty":              {},
	} {
		srv := newAPIServer(t, map[string]route{"slackLists.items.list": {body: listItems}})
		c, _ := newConnector(t, srv, slack.Options{})
		_, err := c.Call(context.Background(), write("add_list_item", map[string]any{"list": "F0LIST0001", "fields": fields}))
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		wantClass(t, err, slack.ClassInvalidArgument)
		if srv.Count("slackLists.items.create") != 0 {
			t.Errorf("%s: item created", name)
		}
	}
}

func TestUpdateListItem(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"slackLists.items.list": {body: listItems}, "slackLists.items.update": {body: "ok.json"}})
	c, _ := newConnector(t, srv, slack.Options{})
	res, err := c.Call(context.Background(), write("update_list_item", map[string]any{"list": "F0LIST0001", "item": "Rec0ITEM001",
		"fields": map[string]any{"Status": "todo", "Owner": []any{"U0ALICE001", "U0BOB00002"}}}))
	if err != nil {
		t.Fatal(err)
	}
	b := jsonBody(t, srv.Last(t, "slackLists.items.update"))
	cells, _ := b["cells"].([]any)
	if b["list_id"] != "F0LIST0001" || len(cells) != 2 {
		t.Fatalf("body = %v", b)
	}
	for _, cell := range cells {
		m := cell.(map[string]any)
		if m["row_id"] != "Rec0ITEM001" {
			t.Errorf("cell = %v", m)
		}
		if m["column_id"] == "Col0OWNER1" {
			if v, _ := m["user"].([]any); len(v) != 2 {
				t.Errorf("owner cell = %v", m)
			}
		}
	}
	if ids := toolNamed(t, c, "update_list_item").ResultIDs(res); ids["item"] != "Rec0ITEM001" {
		t.Errorf("ResultIDs = %v", ids)
	}

	srv2 := newAPIServer(t, map[string]route{"slackLists.items.list": {body: listItems}, "slackLists.items.update": {body: `{"ok":false,"error":"row_not_found"}`}})
	c2, _ := newConnector(t, srv2, slack.Options{})
	_, err = c2.Call(context.Background(), write("update_list_item", map[string]any{"list": "F0LIST0001", "item": "Rec0ITEM001", "fields": map[string]any{"Title": "x"}}))
	wantClass(t, err, slack.ClassNotFound)

	c3, _ := newConnector(t, newAPIServer(t, nil), slack.Options{})
	_, err = c3.Call(context.Background(), write("update_list_item", map[string]any{"list": "F0LIST0001", "item": "row1", "fields": map[string]any{"Title": "x"}}))
	wantClass(t, err, slack.ClassInvalidArgument)
}
