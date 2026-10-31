package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: Forms writes (create, set_publish_settings) and
// get_response.

const (
	newFormID         = "1NewForm00000000000000000000000000"
	newFormBatchPath  = "POST /v1/forms/" + newFormID + ":batchUpdate"
	publishPath       = "POST /v1/forms/" + formID + ":setPublishSettings"
	getResponsePath   = "GET /v1/forms/" + formID + "/responses/ACYDBNexample1"
	createdFormBody   = `{"id":"` + newFormID + `","mimeType":"application/vnd.google-apps.form","webViewLink":"https://docs.google.com/forms/d/` + newFormID + `/edit","parents":["` + folderID + `"]}`
	publishedFormBody = `{"formId":"` + formID + `","publishSettings":{"publishState":{"isPublished":true,"isAcceptingResponses":true}}}`
	closedFormBody    = `{"formId":"` + formID + `","publishSettings":{"publishState":{"isPublished":true}}}`
	responseBody      = `{"formId":"` + formID + `","responseId":"ACYDBNexample1","createTime":"2026-10-20T10:00:00Z","answers":{"b":{"questionId":"b","textAnswers":{"answers":[{"value":"Riley"}]}},"a":{"questionId":"a","textAnswers":{"answers":[{"value":"` + "March 3" + `"}]}}}}`
)

func TestFormsWriteDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	w := connectors.KindWrite
	declared(t, c, "forms.create", w, []string{google.ScopeDriveFile}, connectors.ReconcileMarker)
	declared(t, c, "forms.set_publish_settings", w, []string{google.ScopeFormsBody}, connectors.ReconcileStableID)
	declared(t, c, "forms.get_response", connectors.KindRead, []string{google.ScopeFormsResponsesReadonly}, "")
	id := toolOf(t, c, "forms.create").ResourceIdentity(map[string]any{"title": "secret", "description": "secret", "parent_id": folderID})
	if id["drive"] != "my" || id["folder_id"] != folderID || len(id) != 2 {
		t.Errorf("create identity = %v", id)
	}
	id = toolOf(t, c, "forms.set_publish_settings").ResourceIdentity(map[string]any{"form_id": formID, "published": true})
	if id["form_id"] != formID || id["published"] != "true" || id["accepting_responses"] != "true" || len(id) != 3 {
		t.Errorf("set_publish_settings identity = %v", id)
	}
	id = toolOf(t, c, "forms.set_publish_settings").ResourceIdentity(map[string]any{"form_id": formID, "published": true, "accepting_responses": false})
	if id["accepting_responses"] != "false" {
		t.Errorf("set_publish_settings identity = %v", id)
	}
	id = toolOf(t, c, "forms.get_response").ResourceIdentity(map[string]any{"form_id": formID, "response_id": "ACYDBNexample1"})
	if id["form_id"] != formID || id["response_id"] != "ACYDBNexample1" || len(id) != 2 {
		t.Errorf("get_response identity = %v", id)
	}
}

func TestFormsCreate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		createFilePath:   {status: 200, body: createdFormBody},
		newFormBatchPath: {status: 200, body: `{"replies":[{}],"writeControl":{"requiredRevisionId":"r1"}}`},
	})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("forms.create", map[string]any{"title": "Team survey", "description": "Tell us", "parent_id": folderID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID         string `json:"id"`
		URL        string `json:"url"`
		InfoStatus string `json:"info_status"`
	}
	decode(t, res, &out)
	if out.ID != newFormID || out.InfoStatus != "applied" || !strings.Contains(out.URL, newFormID) {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "forms.create").ResultIDs(res); ids["id"] != newFormID || ids["url"] == "" {
		t.Errorf("ResultIDs = %v", ids)
	}
	created := bodyOf(t, srv.Last(t, createFilePath))
	props, _ := created["appProperties"].(map[string]any)
	if created["mimeType"] != "application/vnd.google-apps.form" || created["name"] != "Team survey" || props["mcp-gateway-op"] != opID {
		t.Errorf("files.create body = %v", created)
	}
	info := srv.Last(t, newFormBatchPath).Body
	if !strings.Contains(info, `"updateFormInfo"`) || !strings.Contains(info, `"title":"Team survey"`) || !strings.Contains(info, `"description":"Tell us"`) ||
		!strings.Contains(info, `"updateMask":"title,description"`) {
		t.Errorf("updateFormInfo = %s", info)
	}

	// Once the form exists the write succeeded whatever the info update does.
	for _, tc := range []struct {
		rt   route
		want string
	}{
		{route{status: 400, body: "error_bad_request.json"}, "failed"},
		{route{status: 500, body: "error_server.json"}, "unknown"},
	} {
		srv := newAPIServer(t, map[string]route{createFilePath: {status: 200, body: createdFormBody}, newFormBatchPath: tc.rt})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := run(t, c, write("forms.create", map[string]any{"title": "x"}))
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			InfoStatus string `json:"info_status"`
			InfoError  string `json:"info_error"`
		}
		decode(t, res, &out)
		if out.InfoStatus != tc.want || out.InfoError == "" {
			t.Errorf("info = %+v, want %s", out, tc.want)
		}
		if body := srv.Last(t, newFormBatchPath).Body; strings.Contains(body, "description") {
			t.Errorf("no description given, yet %s", body)
		}
	}

	_, err = run(t, newAPIServerConnector(t), write("forms.create", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases(createdFormBody) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createFilePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("forms.create", map[string]any{"title": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
	for _, tc := range []struct {
		name string
		rt   route
		want string
	}{
		{"hit", route{status: 200, body: "files_list_marker_hit.json"}, "found"},
		{"miss", route{status: 200, body: "files_list_empty.json"}, "not_found"},
		{"500", route{status: 500, body: "error_server.json"}, "cannot_tell"},
	} {
		t.Run("check "+tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listFilesPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "forms.create", map[string]any{"title": "x"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			if tc.want == "found" {
				if err != nil || out.Outcome != connectors.ReconcileFound {
					t.Errorf("check = %+v, %v", out, err)
				}
				return
			}
			wantOutcome(t, out, err, tc.want, "")
		})
	}
}

// newAPIServerConnector is a connector against a server expecting no
// request.
func newAPIServerConnector(t *testing.T) *google.Connector {
	t.Helper()
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	return c
}

func TestFormsSetPublishSettings(t *testing.T) {
	srv := newAPIServer(t, map[string]route{publishPath: {status: 200, body: publishedFormBody}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("forms.set_publish_settings", map[string]any{"form_id": formID, "published": true}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		FormID             string `json:"form_id"`
		Published          bool   `json:"published"`
		AcceptingResponses bool   `json:"accepting_responses"`
	}
	decode(t, res, &out)
	if out.FormID != formID || !out.Published || !out.AcceptingResponses {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "forms.set_publish_settings").ResultIDs(res); ids["form_id"] != formID {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := srv.Last(t, publishPath).Body
	if !strings.Contains(body, `"isPublished":true`) || !strings.Contains(body, `"isAcceptingResponses":true`) || !strings.Contains(body, `"updateMask":"publish_state"`) {
		t.Errorf("body = %s", body)
	}
	if _, err := run(t, c, write("forms.set_publish_settings", map[string]any{"form_id": formID, "published": false})); err != nil {
		t.Fatal(err)
	}
	if body := srv.Last(t, publishPath).Body; !strings.Contains(body, `"isPublished":false`) || !strings.Contains(body, `"isAcceptingResponses":false`) {
		t.Errorf("unpublish body = %s", body)
	}
	cl, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{
		{"form_id": formID},
		{"published": true},
		{"form_id": formID, "published": "yes"},
		{"form_id": formID, "published": false, "accepting_responses": true},
	} {
		_, err := run(t, cl, write("forms.set_publish_settings", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases(publishedFormBody) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{publishPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("forms.set_publish_settings", map[string]any{"form_id": formID, "published": true}))
			checkWriteError(t, tc, res, err)
		})
	}
	// Check: the form's publish state compared with the identity.
	for _, tc := range []struct {
		name string
		args map[string]any
		rt   route
		want string
	}{
		{"match", map[string]any{"form_id": formID, "published": true}, route{status: 200, body: publishedFormBody}, "found"},
		{"accepting differs", map[string]any{"form_id": formID, "published": true}, route{status: 200, body: closedFormBody}, "not_found"},
		{"closed matches", map[string]any{"form_id": formID, "published": true, "accepting_responses": false}, route{status: 200, body: closedFormBody}, "found"},
		{"legacy form", map[string]any{"form_id": formID, "published": true}, route{status: 200, body: `{"formId":"` + formID + `"}`}, "cannot_tell"},
		{"404", map[string]any{"form_id": formID, "published": true}, route{status: 404, body: "error_not_found.json"}, "cannot_tell"},
		{"500", map[string]any{"form_id": formID, "published": true}, route{status: 500, body: "error_server.json"}, "cannot_tell"},
	} {
		t.Run("check "+tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFormPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "forms.set_publish_settings", tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, formID)
		})
	}
}

func TestFormsGetResponse(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getResponsePath: {status: 200, body: responseBody}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("forms.get_response", map[string]any{"form_id": formID, "response_id": "ACYDBNexample1"}))
	if err != nil {
		t.Fatal(err)
	}
	var out formResponse
	decode(t, res, &out)
	if out.ResponseID != "ACYDBNexample1" || len(out.Answers) != 2 || out.Answers[0].QuestionID != "a" || out.Answers[1].Values[0] != "Riley" {
		t.Errorf("out = %+v", out)
	}
	_, err = run(t, c, call("forms.get_response", map[string]any{"form_id": formID}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %d, want 1", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getResponsePath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("forms.get_response", map[string]any{"form_id": formID, "response_id": "ACYDBNexample1"}))
			checkReadError(t, tc, res, err)
		})
	}
	// A long answer is cut to the bounds.
	long := `{"responseId":"R","answers":{"a":{"questionId":"a","textAnswers":{"answers":[{"value":"` + strings.Repeat("x", 4000) + `"}]}}}}`
	srv = newAPIServer(t, map[string]route{getResponsePath: {status: 200, body: strings.Replace(long, `"R"`, `"ACYDBNexample1"`, 1)}})
	c, _ = newConnector(t, srv, connectors.Bounds{MaxResultBytes: 1000})
	res, err = run(t, c, call("forms.get_response", map[string]any{"form_id": formID, "response_id": "ACYDBNexample1"}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &out)
	if !out.Truncated || !res.Partial || encodedSizeOf(t, res) > 1000 {
		t.Errorf("truncated %v partial %v size %d", out.Truncated, res.Partial, encodedSizeOf(t, res))
	}
}
