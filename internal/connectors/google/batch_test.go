package google_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: the raw batch_update tools of Docs, Sheets, Slides and
// Forms. The requests go to Google exactly as given (Google validates
// them); the result carries Google's replies, trimmed to the bounds.

const (
	sheetsBatchPath = "POST /v4/spreadsheets/" + sheetID + ":batchUpdate"
	formsBatchPath  = "POST /v1/forms/" + formID + ":batchUpdate"
)

// batchCase is one app's raw batch_update tool.
type batchCase struct {
	tool, idArg, id, path, scope, reply string
	writeControl                        bool
}

func batchCases() []batchCase {
	return []batchCase{
		{"docs.batch_update", "document_id", docID, batchUpdatePath, google.ScopeDocuments,
			`{"documentId":"` + docID + `","replies":[{},{"createNamedRange":{"namedRangeId":"kix.nr1"}}],"writeControl":{"requiredRevisionId":"rev-2"}}`, true},
		{"sheets.batch_update", "spreadsheet_id", sheetID, sheetsBatchPath, google.ScopeSpreadsheets,
			`{"spreadsheetId":"` + sheetID + `","replies":[{},{"addSheet":{"properties":{"sheetId":42,"title":"New"}}}]}`, false},
		{"slides.batch_update", "presentation_id", presID, presBatchPath, google.ScopePresentations,
			`{"presentationId":"` + presID + `","replies":[{},{"createSlide":{"objectId":"s1"}}],"writeControl":{"requiredRevisionId":"rev-2"}}`, true},
		{"forms.batch_update", "form_id", formID, formsBatchPath, google.ScopeFormsBody,
			`{"replies":[{},{"createItem":{"itemId":"i1","questionId":["q1"]}}],"writeControl":{"requiredRevisionId":"rev-2"}}`, true},
	}
}

// twoRequests are a deleteX and a createX request with a nested field
// the connector does not know: it must reach Google untouched.
func twoRequests() []any {
	return []any{
		map[string]any{"zetaRequest": map[string]any{"objectId": "a"}},
		map[string]any{"alphaRequest": map[string]any{"nested": map[string]any{"futureField": 7}}},
	}
}

func TestBatchUpdateDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, bc := range batchCases() {
		tool := declared(t, c, bc.tool, connectors.KindWrite, []string{bc.scope}, connectors.ReconcileNone)
		id := tool.ResourceIdentity(map[string]any{bc.idArg: bc.id, "requests": append(twoRequests(), map[string]any{"zetaRequest": map[string]any{"text": "secret"}})})
		if id[bc.idArg] != bc.id || id["request_kinds"] != "alphaRequest,zetaRequest" || len(id) != 2 {
			t.Errorf("%s identity = %v", bc.tool, id)
		}
		var schema struct {
			Properties map[string]struct {
				Type  string         `json:"type"`
				Items map[string]any `json:"items"`
			} `json:"properties"`
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Fatal(err)
		}
		if p := schema.Properties["requests"]; p.Type != "array" || p.Items["type"] != "object" {
			t.Errorf("%s requests schema = %+v", bc.tool, p)
		}
		_, hasRev := schema.Properties["required_revision_id"]
		if hasRev != bc.writeControl {
			t.Errorf("%s required_revision_id in schema = %v, want %v", bc.tool, hasRev, bc.writeControl)
		}
	}
}

func TestBatchUpdateSendsRequestsAsGiven(t *testing.T) {
	for _, bc := range batchCases() {
		t.Run(bc.tool, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{bc.path: {status: 200, body: bc.reply}})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			args := map[string]any{bc.idArg: bc.id, "requests": twoRequests()}
			if bc.writeControl {
				args["required_revision_id"] = "rev-1"
			}
			res, err := run(t, c, write(bc.tool, args))
			if err != nil {
				t.Fatal(err)
			}
			body := bodyOf(t, srv.Last(t, bc.path))
			reqs, _ := body["requests"].([]any)
			if len(reqs) != 2 || !strings.Contains(srv.Last(t, bc.path).Body, `"futureField":7`) {
				t.Errorf("body = %s", srv.Last(t, bc.path).Body)
			}
			wc, _ := body["writeControl"].(map[string]any)
			if bc.writeControl && wc["requiredRevisionId"] != "rev-1" {
				t.Errorf("writeControl = %v", body["writeControl"])
			}
			if bc.tool == "forms.batch_update" && body["includeFormInResponse"] == true {
				t.Error("forms.batch_update must not ask for the form in the response")
			}
			var out struct {
				RequestCount int               `json:"request_count"`
				RequestKinds []string          `json:"request_kinds"`
				Replies      []json.RawMessage `json:"replies"`
				RevisionID   string            `json:"revision_id"`
				Truncated    bool              `json:"truncated"`
			}
			decode(t, res, &out)
			if out.RequestCount != 2 || len(out.Replies) != 2 || out.Truncated || strings.Join(out.RequestKinds, ",") != "alphaRequest,zetaRequest" {
				t.Errorf("out = %+v", out)
			}
			if bc.writeControl && out.RevisionID != "rev-2" {
				t.Errorf("revision_id = %q", out.RevisionID)
			}
			if ids := toolOf(t, c, bc.tool).ResultIDs(res); ids[bc.idArg] != bc.id {
				t.Errorf("ResultIDs = %v", ids)
			}
			var raw map[string]any
			decode(t, res, &raw)
			if raw[bc.idArg] != bc.id {
				t.Errorf("result %s = %v", bc.idArg, raw[bc.idArg])
			}
		})
	}
}

func TestBatchUpdateValidatesBeforeTheToken(t *testing.T) {
	many := make([]any, google.MaxBatchRequests+1)
	for i := range many {
		many[i] = map[string]any{"insertText": map[string]any{"text": "x"}}
	}
	huge := []any{map[string]any{"insertText": map[string]any{"text": strings.Repeat("x", google.MaxBatchBytes)}}}
	for _, bc := range batchCases() {
		c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
		for name, args := range map[string]map[string]any{
			"no id":         {"requests": twoRequests()},
			"bad id":        {bc.idArg: "a/b", "requests": twoRequests()},
			"no requests":   {bc.idArg: bc.id},
			"empty":         {bc.idArg: bc.id, "requests": []any{}},
			"not an array":  {bc.idArg: bc.id, "requests": "insertText"},
			"not an object": {bc.idArg: bc.id, "requests": []any{"insertText"}},
			"two kinds":     {bc.idArg: bc.id, "requests": []any{map[string]any{"a": map[string]any{}, "b": map[string]any{}}}},
			"no kind":       {bc.idArg: bc.id, "requests": []any{map[string]any{}}},
			"kind not obj":  {bc.idArg: bc.id, "requests": []any{map[string]any{"insertText": "x"}}},
			"too many":      {bc.idArg: bc.id, "requests": many},
			"too large":     {bc.idArg: bc.id, "requests": huge},
		} {
			_, err := run(t, c, write(bc.tool, args))
			if err == nil {
				t.Errorf("%s %s: no error", bc.tool, name)
				continue
			}
			wantClass(t, err, google.ClassInvalidArgument, 0)
		}
		if len(tk.calls) != 0 {
			t.Errorf("%s: token calls for invalid arguments = %d", bc.tool, len(tk.calls))
		}
	}
}

func TestBatchUpdateRepliesFitTheBounds(t *testing.T) {
	var replies []string
	for range 50 {
		replies = append(replies, `{"replaceAllText":{"occurrencesChanged":1,"note":"`+strings.Repeat("r", 100)+`"}}`)
	}
	srv := newAPIServer(t, map[string]route{batchUpdatePath: {status: 200, body: `{"documentId":"` + docID + `","replies":[` + strings.Join(replies, ",") + `]}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 1500})
	res, err := run(t, c, write("docs.batch_update", map[string]any{"document_id": docID, "requests": twoRequests()}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Replies   []json.RawMessage `json:"replies"`
		Truncated bool              `json:"truncated"`
	}
	decode(t, res, &out)
	if !out.Truncated || len(out.Replies) == 0 || len(out.Replies) >= 50 || encodedSizeOf(t, res) > 1500 {
		t.Errorf("replies %d truncated %v size %d", len(out.Replies), out.Truncated, encodedSizeOf(t, res))
	}
}

func TestBatchUpdateWriteErrors(t *testing.T) {
	for _, bc := range batchCases() {
		for _, tc := range writeErrorCases(bc.reply) {
			t.Run(bc.tool+" "+tc.name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{bc.path: tc.rt})
				res, err := run(t, shortTimeout(t, srv), write(bc.tool, map[string]any{bc.idArg: bc.id, "requests": twoRequests()}))
				checkWriteError(t, tc, res, err)
			})
		}
	}
}

// The batch tools keep the per-file admission: drive.file admits them;
// the read-only scopes do not.
func TestBatchUpdateScopeGate(t *testing.T) {
	cases := []struct {
		id     string
		scopes []string
		ok     bool
	}{
		{"b5000000-0000-4000-8000-000000000001", []string{google.ScopeDriveFile}, true},
		{"b5000000-0000-4000-8000-000000000002", []string{google.ScopeDrive}, true},
		{"b5000000-0000-4000-8000-000000000003", []string{google.ScopeDriveReadonly}, false},
		{"b5000000-0000-4000-8000-000000000004", []string{google.ScopeFormsBodyReadonly, google.ScopeDocumentsReadonly, google.ScopeSpreadsheetsReadonly, google.ScopePresentationsReadonly}, false},
	}
	for _, bc := range batchCases() {
		srv := newAPIServer(t, map[string]route{bc.path: {status: 200, body: bc.reply}})
		accounts := connectors.NewStaticAccountSource()
		app, _, _ := strings.Cut(bc.tool, ".")
		for _, tc := range cases {
			accounts.Add(alice, connectors.Account{ID: tc.id, App: app, Label: connectors.LabelPersonal, Scopes: tc.scopes})
		}
		c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range cases {
			cl := write(bc.tool, map[string]any{bc.idArg: bc.id, "requests": twoRequests()})
			cl.Account = tc.id
			_, err := run(t, c, cl)
			if tc.ok && err != nil {
				t.Errorf("%s with %v: %v", bc.tool, tc.scopes, err)
			} else if !tc.ok {
				wantClass(t, err, google.ClassScopeRequired, 0)
			}
		}
	}
}
