package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: label management (create_label, update_label,
// delete_label) and filters (get_filter, create_filter, delete_filter).

const (
	labelsPath       = gm + "labels"
	createLabelPath  = "POST " + labelsPath
	labelPath        = labelsPath + "/Label_42"
	getLabelPath     = "GET " + labelPath
	patchLabelPath   = "PATCH " + labelPath
	deleteLabelPath  = "DELETE " + labelPath
	filtersBase      = gm + "settings/filters"
	createFilterPath = "POST " + filtersBase
	filterPath       = filtersBase + "/ANe1BmjExample2"
	getFilterPath    = "GET " + filterPath
	deleteFilterPath = "DELETE " + filterPath
)

func TestGmailOrganizeDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	cl := declared(t, c, "gmail.create_label", w, []string{google.ScopeGmailLabels}, connectors.ReconcileNone)
	ul := declared(t, c, "gmail.update_label", w, []string{google.ScopeGmailLabels}, connectors.ReconcileStableID)
	declared(t, c, "gmail.delete_label", w, []string{google.ScopeGmailLabels}, connectors.ReconcileStableID)
	declared(t, c, "gmail.get_filter", r, []string{google.ScopeGmailReadonly}, "")
	cf := declared(t, c, "gmail.create_filter", w, []string{google.ScopeGmailSettingsBasic}, connectors.ReconcileNone)
	declared(t, c, "gmail.delete_filter", w, []string{google.ScopeGmailSettingsBasic}, connectors.ReconcileStableID)

	if id := cl.ResourceIdentity(map[string]any{"name": "Secret project", "label_list_visibility": "labelHide"}); len(id) != 1 || id["label_list_visibility"] != "labelHide" {
		t.Errorf("create_label identity = %v (never the name)", id)
	}
	id := ul.ResourceIdentity(map[string]any{"label_id": "Label_42", "name": "Secret", "message_list_visibility": "hide", "background_color": "#16A765", "text_color": "#FFFFFF"})
	want := map[string]string{"label_id": "Label_42", "name": "true", "message_list_visibility": "hide", "background_color": "#16a765", "text_color": "#ffffff"}
	if len(id) != len(want) {
		t.Errorf("update_label identity = %v, want %v", id, want)
	}
	for k, v := range want {
		if id[k] != v {
			t.Errorf("update_label identity[%s] = %q, want %q", k, id[k], v)
		}
	}
	id = cf.ResourceIdentity(map[string]any{
		"criteria": map[string]any{"from": "boss@secret.test", "query": "secret"},
		"action":   map[string]any{"forward": "Me <me@Home.test>", "add_label_ids": []any{"STARRED", "Label_1"}, "remove_label_ids": []any{"INBOX"}},
	})
	if id["forward_domain"] != "home.test" || id["add_labels"] != "Label_1,STARRED" || id["remove_labels"] != "INBOX" || len(id) != 3 {
		t.Errorf("create_filter identity = %v", id)
	}
	for _, v := range id {
		if strings.Contains(v, "secret") || strings.Contains(v, "me@") {
			t.Errorf("create_filter identity carries content: %v", id)
		}
	}
	for _, full := range []string{"gmail.create_filter"} {
		schema := string(toolOf(t, c, full).InputSchema)
		for _, want := range []string{`"criteria"`, `"action"`, `"size_comparison"`, `"forward"`} {
			if !strings.Contains(schema, want) {
				t.Errorf("%s schema lacks %s: %s", full, want, schema)
			}
		}
	}
}

func TestCreateLabel(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createLabelPath: {status: 200, body: "gmail_label.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.create_label", map[string]any{
		"name": "Receipts", "label_list_visibility": "labelShow", "message_list_visibility": "show", "background_color": "#16a765", "text_color": "#ffffff",
	}))
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, srv.Last(t, createLabelPath))
	color, _ := body["color"].(map[string]any)
	if body["name"] != "Receipts" || body["labelListVisibility"] != "labelShow" || body["messageListVisibility"] != "show" || color["backgroundColor"] != "#16a765" || color["textColor"] != "#ffffff" {
		t.Errorf("body = %v", body)
	}
	var out struct {
		ID, Name, Type        string
		LabelListVisibility   string `json:"label_list_visibility"`
		MessageListVisibility string `json:"message_list_visibility"`
		BackgroundColor       string `json:"background_color"`
	}
	decode(t, res, &out)
	if out.ID != "Label_42" || out.Name != "Receipts" || out.Type != "user" || out.LabelListVisibility != "labelShow" || out.BackgroundColor != "#16a765" {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "gmail.create_label").ResultIDs(res); ids["label_id"] != "Label_42" {
		t.Errorf("ResultIDs = %v", ids)
	}
	// Name only: no visibility or color sent.
	if _, err := run(t, c, write("gmail.create_label", map[string]any{"name": "Plain"})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, createLabelPath)); body["color"] != nil || body["labelListVisibility"] != nil {
		t.Errorf("name only body = %v", body)
	}
	tk.calls = nil
	for name, args := range map[string]map[string]any{
		"no name":         {},
		"long name":       {"name": strings.Repeat("x", 226)},
		"line break":      {"name": "a\nb"},
		"bad visibility":  {"name": "a", "label_list_visibility": "sometimes"},
		"bad message vis": {"name": "a", "message_list_visibility": "maybe"},
		"one color":       {"name": "a", "background_color": "#16a765"},
		"bad color":       {"name": "a", "background_color": "green", "text_color": "#ffffff"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.create_label", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("gmail_label.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createLabelPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.create_label", map[string]any{"name": "Receipts"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestUpdateLabel(t *testing.T) {
	srv := newAPIServer(t, map[string]route{patchLabelPath: {status: 200, body: "gmail_label_hidden.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.update_label", map[string]any{"label_id": "Label_42", "label_list_visibility": "labelHide", "message_list_visibility": "hide"}))
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, srv.Last(t, patchLabelPath))
	if body["labelListVisibility"] != "labelHide" || body["messageListVisibility"] != "hide" || body["name"] != nil || body["color"] != nil {
		t.Errorf("patch body = %v, want only the given fields", body)
	}
	if ids := toolOf(t, c, "gmail.update_label").ResultIDs(res); ids["label_id"] != "Label_42" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := run(t, c, write("gmail.update_label", map[string]any{"label_id": "Label_42", "name": "Renamed", "background_color": "#16a765", "text_color": "#ffffff"})); err != nil {
		t.Fatal(err)
	}
	body = bodyOf(t, srv.Last(t, patchLabelPath))
	if color, _ := body["color"].(map[string]any); body["name"] != "Renamed" || color["backgroundColor"] != "#16a765" {
		t.Errorf("patch body = %v", body)
	}
	tk.calls = nil
	for name, args := range map[string]map[string]any{
		"no id":          {"name": "x"},
		"nothing":        {"label_id": "Label_42"},
		"bad visibility": {"label_id": "Label_42", "label_list_visibility": "x"},
		"blank name":     {"label_id": "Label_42", "name": " "},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.update_label", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("gmail_label.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{patchLabelPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.update_label", map[string]any{"label_id": "Label_42", "message_list_visibility": "hide"}))
			checkWriteError(t, tc, res, err)
		})
	}
	hide := map[string]any{"label_id": "Label_42", "label_list_visibility": "labelHide", "message_list_visibility": "hide"}
	for name, tc := range map[string]struct {
		args map[string]any
		rt   route
		want string
	}{
		"applied":            {hide, route{status: 200, body: "gmail_label_hidden.json"}, "found"},
		"not applied":        {hide, route{status: 200, body: "gmail_label.json"}, "not_found"},
		"color applied":      {map[string]any{"label_id": "Label_42", "background_color": "#16A765", "text_color": "#ffffff"}, route{status: 200, body: "gmail_label.json"}, "found"},
		"color not applied":  {map[string]any{"label_id": "Label_42", "background_color": "#000000", "text_color": "#ffffff"}, route{status: 200, body: "gmail_label.json"}, "not_found"},
		"renamed unprovable": {map[string]any{"label_id": "Label_42", "name": "x", "label_list_visibility": "labelHide"}, route{status: 200, body: "gmail_label_hidden.json"}, "cannot"},
		"gone":               {hide, route{status: 404, body: "error_not_found.json"}, "cannot"},
		"500":                {hide, route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getLabelPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.update_label", tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "Label_42")
		})
	}
}

func TestDeleteLabel(t *testing.T) {
	srv := newAPIServer(t, map[string]route{deleteLabelPath: {status: 204}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.delete_label", map[string]any{"label_id": "Label_42"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "gmail.delete_label").ResultIDs(res); ids["label_id"] != "Label_42" {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err = run(t, c, write("gmail.delete_label", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{deleteLabelPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.delete_label", map[string]any{"label_id": "Label_42"}))
			checkWriteError(t, tc, res, err)
		})
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"gone":        {route{status: 404, body: "error_not_found.json"}, "found"},
		"still there": {route{status: 200, body: "gmail_label.json"}, "not_found"},
		"500":         {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getLabelPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.delete_label", map[string]any{"label_id": "Label_42"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "Label_42")
		})
	}
}

func TestGetFilter(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getFilterPath: {status: 200, body: "gmail_filter.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.get_filter", map[string]any{"filter_id": "ANe1BmjExample2"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID       string `json:"id"`
		Criteria struct {
			Query          string `json:"query"`
			SizeComparison string `json:"size_comparison"`
		} `json:"criteria"`
		Action struct {
			Forward string `json:"forward"`
		} `json:"action"`
	}
	decode(t, res, &out)
	if out.ID != "ANe1BmjExample2" || out.Criteria.Query != "list:dev.example.test" || out.Criteria.SizeComparison != "larger" || out.Action.Forward != "archive@example.test" {
		t.Errorf("out = %+v", out)
	}
	if id := toolOf(t, c, "gmail.get_filter").ResourceIdentity(map[string]any{"filter_id": "ANe1BmjExample2"}); id["filter_id"] != "ANe1BmjExample2" {
		t.Errorf("identity = %v", id)
	}
	_, err = run(t, c, call("gmail.get_filter", nil))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFilterPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.get_filter", map[string]any{"filter_id": "ANe1BmjExample2"}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestCreateFilter(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFilterPath: {status: 200, body: "gmail_filter.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.create_filter", map[string]any{
		"criteria": map[string]any{"query": "list:dev.example.test", "negated_query": "urgent", "size": 1048576, "size_comparison": "larger", "exclude_chats": true},
		"action":   map[string]any{"forward": "archive@example.test", "remove_label_ids": []any{"INBOX"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, srv.Last(t, createFilterPath))
	cr, _ := body["criteria"].(map[string]any)
	ac, _ := body["action"].(map[string]any)
	if cr["query"] != "list:dev.example.test" || cr["negatedQuery"] != "urgent" || cr["size"] != float64(1048576) || cr["sizeComparison"] != "larger" || cr["excludeChats"] != true {
		t.Errorf("criteria = %v", cr)
	}
	if rm, _ := ac["removeLabelIds"].([]any); ac["forward"] != "archive@example.test" || len(rm) != 1 {
		t.Errorf("action = %v", ac)
	}
	var out struct {
		ID string `json:"id"`
	}
	decode(t, res, &out)
	if out.ID != "ANe1BmjExample2" {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "gmail.create_filter").ResultIDs(res); ids["filter_id"] != "ANe1BmjExample2" {
		t.Errorf("ResultIDs = %v", ids)
	}
	tk.calls = nil
	label := map[string]any{"add_label_ids": []any{"STARRED"}}
	for name, args := range map[string]map[string]any{
		"no criteria":         {"action": label},
		"empty criteria":      {"criteria": map[string]any{}, "action": label},
		"no action":           {"criteria": map[string]any{"from": "a@b.test"}},
		"empty action":        {"criteria": map[string]any{"from": "a@b.test"}, "action": map[string]any{}},
		"criteria not object": {"criteria": "from:a", "action": label},
		"unknown criterion":   {"criteria": map[string]any{"sender": "a"}, "action": label},
		"unknown action":      {"criteria": map[string]any{"from": "a"}, "action": map[string]any{"delete": true}},
		"size alone":          {"criteria": map[string]any{"size": 10}, "action": label},
		"bad comparison":      {"criteria": map[string]any{"size": 10, "size_comparison": "equal"}, "action": label},
		"bad size":            {"criteria": map[string]any{"size": -1, "size_comparison": "larger"}, "action": label},
		"bad forward":         {"criteria": map[string]any{"from": "a"}, "action": map[string]any{"forward": "nobody"}},
		"bad label":           {"criteria": map[string]any{"from": "a"}, "action": map[string]any{"add_label_ids": []any{"a/b"}}},
		"bad bool":            {"criteria": map[string]any{"has_attachment": "yes"}, "action": label},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.create_filter", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("gmail_filter.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createFilterPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.create_filter", map[string]any{"criteria": map[string]any{"from": "a@b.test"}, "action": label}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestDeleteFilter(t *testing.T) {
	srv := newAPIServer(t, map[string]route{deleteFilterPath: {status: 204}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.delete_filter", map[string]any{"filter_id": "ANe1BmjExample2"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "gmail.delete_filter").ResultIDs(res); ids["filter_id"] != "ANe1BmjExample2" {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err = run(t, c, write("gmail.delete_filter", map[string]any{"filter_id": "a/b"}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{deleteFilterPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.delete_filter", map[string]any{"filter_id": "ANe1BmjExample2"}))
			checkWriteError(t, tc, res, err)
		})
	}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"gone":        {route{status: 404, body: "error_not_found.json"}, "found"},
		"still there": {route{status: 200, body: "gmail_filter.json"}, "not_found"},
		"500":         {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFilterPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.delete_filter", map[string]any{"filter_id": "ANe1BmjExample2"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "ANe1BmjExample2")
		})
	}
}
