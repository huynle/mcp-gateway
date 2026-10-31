package google_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 4: the forms app (Google Forms API, read only).

const (
	formID        = "1FormExample0000000000000000000000"
	getFormPath   = "GET /v1/forms/" + formID
	responsesPath = "GET /v1/forms/" + formID + "/responses"
)

type formItem struct {
	ItemID     string   `json:"item_id"`
	Title      string   `json:"title"`
	Type       string   `json:"type"`
	QuestionID string   `json:"question_id"`
	Required   bool     `json:"required"`
	ChoiceType string   `json:"choice_type"`
	Options    []string `json:"options"`
	Rows       []struct {
		QuestionID string `json:"question_id"`
		Title      string `json:"title"`
	} `json:"rows"`
}

type formOut struct {
	FormID       string     `json:"form_id"`
	Title        string     `json:"title"`
	Description  string     `json:"description"`
	ResponderURI string     `json:"responder_uri"`
	Items        []formItem `json:"items"`
	Truncated    bool       `json:"truncated"`
}

type formResponse struct {
	ResponseID        string `json:"response_id"`
	CreateTime        string `json:"create_time"`
	LastSubmittedTime string `json:"last_submitted_time"`
	RespondentEmail   string `json:"respondent_email"`
	Answers           []struct {
		QuestionID string   `json:"question_id"`
		Values     []string `json:"values"`
		FileIDs    []string `json:"file_ids"`
	} `json:"answers"`
	Truncated bool `json:"truncated"`
}

type responsesOut struct {
	FormID        string         `json:"form_id"`
	MaxResults    int            `json:"max_results"`
	NextPageToken string         `json:"next_page_token"`
	HasMore       bool           `json:"has_more"`
	Truncated     bool           `json:"truncated"`
	Items         []formResponse `json:"items"`
}

func TestFormsDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	declared(t, c, "forms.get", connectors.KindRead, []string{google.ScopeFormsBodyReadonly}, "")
	declared(t, c, "forms.list_responses", connectors.KindRead, []string{google.ScopeFormsResponsesReadonly}, "")
	for _, tool := range appOf(t, c, google.AppForms).Tools() {
		if tool.Kind != connectors.KindRead {
			continue // increment 5 writes: tested in tools_forms_write_test.go and batch_test.go
		}
		id := tool.ResourceIdentity(map[string]any{"form_id": formID, "page_token": "secret"})
		if len(id) != 1 || id["form_id"] != formID {
			t.Errorf("forms.%s identity = %v, want only form_id", tool.Name, id)
		}
	}
}

func TestFormsGet(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getFormPath: {status: 200, body: "form.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("forms.get", map[string]any{"form_id": formID}))
	if err != nil {
		t.Fatal(err)
	}
	var out formOut
	decode(t, res, &out)
	if out.FormID != formID || out.Title != "Team offsite survey" || out.Description != "Tell us what works for the offsite." ||
		out.ResponderURI != "https://docs.google.com/forms/d/e/1FAIpQLSexample/viewform" || len(out.Items) != 7 {
		t.Fatalf("out = %+v", out)
	}
	it := out.Items
	if it[0].ItemID != "1a2b3c4d" || it[0].Type != "text" || it[0].QuestionID != "0a1b2c3d" || !it[0].Required {
		t.Errorf("item 0 = %+v", it[0])
	}
	if it[1].Type != "choice" || it[1].ChoiceType != "RADIO" || strings.Join(it[1].Options, "|") != "March 3|March 10|(other)" || it[1].Required {
		t.Errorf("item 1 = %+v", it[1])
	}
	if it[2].Type != "paragraph" {
		t.Errorf("item 2 = %+v", it[2])
	}
	if it[3].Type != "grid" || it[3].ChoiceType != "RADIO" || strings.Join(it[3].Options, "|") != "Good|Bad" || len(it[3].Rows) != 2 ||
		it[3].Rows[1].QuestionID != "4e5f6071" || it[3].Rows[1].Title != "Afternoon" || it[3].QuestionID != "" {
		t.Errorf("item 3 = %+v", it[3])
	}
	if it[4].Type != "page_break" || it[5].Type != "file_upload" || it[5].QuestionID != "5f607182" || it[6].Type != "image" {
		t.Errorf("items 4-6 = %+v", it[4:])
	}
	if res.Empty || res.Partial || len(tk.calls) != 1 {
		t.Errorf("res = %+v", res)
	}

	// Bounds: the description is cut first, then trailing items dropped.
	c2, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 400})
	res, err = run(t, c2, call("forms.get", map[string]any{"form_id": formID}))
	if err != nil {
		t.Fatal(err)
	}
	out = formOut{}
	decode(t, res, &out)
	if !out.Truncated || !res.Partial || encodedSizeOf(t, res) > 400 || len(out.Items) == 0 || len(out.Items) == 7 || out.Description != "" {
		t.Errorf("bounded: out = %+v (%d bytes)", out, encodedSizeOf(t, res))
	}

	srvEmpty := newAPIServer(t, map[string]route{getFormPath: {status: 200, body: "form_empty.json"}})
	cEmpty, _ := newConnector(t, srvEmpty, connectors.Bounds{})
	res, err = run(t, cEmpty, call("forms.get", map[string]any{"form_id": formID}))
	out = formOut{}
	decode(t, res, &out)
	if err != nil || !res.Empty || out.Items == nil {
		t.Errorf("no items: res = %+v, %v; want empty with items []", res, err)
	}

	cl, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{{}, {"form_id": "a b"}} {
		_, err := run(t, cl, call("forms.get", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getFormPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("forms.get", map[string]any{"form_id": formID}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestFormsListResponses(t *testing.T) {
	srv := newAPIServer(t, map[string]route{responsesPath: {status: 200, body: "form_responses.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("forms.list_responses", map[string]any{"form_id": formID, "max_results": 2, "page_token": "page-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if q := query(t, srv, "/v1/forms/"+formID+"/responses"); q.Get("pageSize") != "2" || q.Get("pageToken") != "page-1" {
		t.Errorf("query = %v", q)
	}
	var out responsesOut
	decode(t, res, &out)
	if out.FormID != formID || out.MaxResults != 2 || out.NextPageToken != "page-2" || !out.HasMore || len(out.Items) != 2 || res.Empty || res.Partial {
		t.Fatalf("out = %+v, res = %+v", out, res)
	}
	r1 := out.Items[0]
	if r1.ResponseID != "ACYDBNexample1" || r1.CreateTime != "2026-10-20T10:00:00.123Z" || r1.LastSubmittedTime != "2026-10-20T10:05:00.456Z" ||
		r1.RespondentEmail != "riley@example.test" || len(r1.Answers) != 3 {
		t.Fatalf("response 1 = %+v", r1)
	}
	// Answers sorted by question id; file uploads give names and ids.
	if r1.Answers[0].QuestionID != "0a1b2c3d" || r1.Answers[0].Values[0] != "Riley" || r1.Answers[1].QuestionID != "1b2c3d4e" ||
		r1.Answers[2].QuestionID != "5f607182" || r1.Answers[2].Values[0] != "deck.pdf" || r1.Answers[2].FileIDs[0] != "1UploadedFile000" {
		t.Errorf("answers = %+v", r1.Answers)
	}
	if out.Items[1].RespondentEmail != "" {
		t.Errorf("response 2 = %+v", out.Items[1])
	}

	// Default page and clamping.
	if _, err := run(t, c, call("forms.list_responses", map[string]any{"form_id": formID})); err != nil {
		t.Fatal(err)
	}
	if q := query(t, srv, "/v1/forms/"+formID+"/responses"); q.Get("pageSize") != "25" || q.Has("pageToken") {
		t.Errorf("default query = %v", q)
	}
	cc, _ := newConnector(t, srv, connectors.Bounds{MaxPageSize: 10})
	res, err = run(t, cc, call("forms.list_responses", map[string]any{"form_id": formID, "max_results": 50}))
	if err != nil || !res.Partial {
		t.Errorf("clamped: res = %+v, %v; want partial", res, err)
	}

	// Bounds: trailing responses dropped (never below one), then the last
	// one's values cut.
	c2, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 600})
	res, err = run(t, c2, call("forms.list_responses", map[string]any{"form_id": formID}))
	if err != nil {
		t.Fatal(err)
	}
	out = responsesOut{}
	decode(t, res, &out)
	if !out.Truncated || !res.Partial || len(out.Items) != 1 || out.Items[0].Truncated || encodedSizeOf(t, res) > 600 {
		t.Errorf("bounded: out = %+v (%d bytes)", out, encodedSizeOf(t, res))
	}
	long := `{"responses": [{"responseId": "ACYDBNexample3", "answers": {"2c3d4e5f": {"questionId": "2c3d4e5f", "textAnswers": {"answers": [{"value": "` +
		strings.Repeat("long answer ", 40) + `"}]}}}}]}`
	srvLong := newAPIServer(t, map[string]route{responsesPath: {status: 200, body: long}})
	c3, _ := newConnector(t, srvLong, connectors.Bounds{MaxResultBytes: 300})
	res, err = run(t, c3, call("forms.list_responses", map[string]any{"form_id": formID}))
	if err != nil {
		t.Fatal(err)
	}
	out = responsesOut{}
	decode(t, res, &out)
	if !out.Truncated || !res.Partial || len(out.Items) != 1 || !out.Items[0].Truncated || encodedSizeOf(t, res) > 300 ||
		!strings.HasPrefix(out.Items[0].Answers[0].Values[0], "long answer") {
		t.Errorf("bounded values: out = %+v (%d bytes)", out, encodedSizeOf(t, res))
	}

	srvEmpty := newAPIServer(t, map[string]route{responsesPath: {status: 200, body: "form_responses_empty.json"}})
	cEmpty, _ := newConnector(t, srvEmpty, connectors.Bounds{})
	res, err = run(t, cEmpty, call("forms.list_responses", map[string]any{"form_id": formID}))
	out = responsesOut{}
	decode(t, res, &out)
	if err != nil || !res.Empty || out.Items == nil || out.HasMore {
		t.Errorf("empty: out = %+v res = %+v, %v", out, res, err)
	}

	cl, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{{}, {"form_id": formID, "max_results": 0}, {"form_id": formID, "page_token": 3}} {
		_, err := run(t, cl, call("forms.list_responses", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{responsesPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("forms.list_responses", map[string]any{"form_id": formID}))
			checkReadError(t, tc, res, err)
		})
	}
}

// forms.get accepts forms.body(.readonly), drive, drive.readonly and
// drive.file; responses.list forms.responses.readonly, drive and
// drive.file (not drive.readonly).
func TestFormsScopeGate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		getFormPath:   {status: 200, body: "form.json"},
		responsesPath: {status: 200, body: "form_responses.json"},
	})
	cases := []struct {
		id              string
		scopes          []string
		form, responses bool
	}{
		{"a4000000-0000-4000-8000-000000000001", []string{google.ScopeFormsBodyReadonly}, true, false},
		{"a4000000-0000-4000-8000-000000000002", []string{google.ScopeFormsBody}, true, false},
		{"a4000000-0000-4000-8000-000000000003", []string{google.ScopeFormsResponsesReadonly}, false, true},
		{"a4000000-0000-4000-8000-000000000004", []string{google.ScopeDriveReadonly}, true, false},
		{"a4000000-0000-4000-8000-000000000005", []string{google.ScopeDrive}, true, true},
		{"a4000000-0000-4000-8000-000000000006", []string{google.ScopeDriveFile}, true, true},
	}
	accounts := connectors.NewStaticAccountSource()
	for _, tc := range cases {
		accounts.Add(alice, connectors.Account{ID: tc.id, App: google.AppForms, Label: connectors.LabelPersonal, Scopes: tc.scopes})
	}
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		for full, want := range map[string]bool{"forms.get": tc.form, "forms.list_responses": tc.responses} {
			cl := call(full, map[string]any{"form_id": formID})
			cl.Account = tc.id
			_, err := run(t, c, cl)
			if want && err != nil {
				t.Errorf("%s with %v: %v", full, tc.scopes, err)
			} else if !want {
				wantClass(t, err, google.ClassScopeRequired, 0)
			}
		}
	}
}
