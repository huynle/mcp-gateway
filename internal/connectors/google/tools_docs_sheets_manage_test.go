package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// docs.replace_text; sheets.get_metadata, update_range, create.

const (
	sheetMetaPath    = "GET /v4/spreadsheets/" + sheetID
	updateValuesPath = "PUT /v4/spreadsheets/" + sheetID + "/values/Budget!A1:C2"
)

func TestDocsSheetsManageDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "docs.replace_text", w, []string{google.ScopeDocuments}, connectors.ReconcileNone)
	declared(t, c, "sheets.get_metadata", r, []string{google.ScopeSpreadsheetsReadonly}, "")
	declared(t, c, "sheets.update_range", w, []string{google.ScopeSpreadsheets}, connectors.ReconcileNone)
	declared(t, c, "sheets.create", w, []string{google.ScopeDriveFile}, connectors.ReconcileMarker)
	if id := toolOf(t, c, "docs.replace_text").ResourceIdentity(map[string]any{"document_id": docID, "find": "secret"}); len(id) != 1 || id["document_id"] != docID {
		t.Errorf("replace_text identity = %v", id)
	}
}

func TestDocsReplaceText(t *testing.T) {
	srv := newAPIServer(t, map[string]route{batchUpdatePath: {status: 200, body: "replace_all_reply.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("docs.replace_text", map[string]any{"document_id": docID, "find": "{{name}}", "replace": "Alice"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		DocumentID         string `json:"document_id"`
		OccurrencesChanged int64  `json:"occurrences_changed"`
	}
	decode(t, res, &out)
	if out.DocumentID != docID || out.OccurrencesChanged != 3 {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "docs.replace_text").ResultIDs(res); ids["document_id"] != docID {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := srv.Last(t, batchUpdatePath).Body
	if !strings.Contains(body, `"replaceAllText"`) || !strings.Contains(body, `"text":"{{name}}"`) || !strings.Contains(body, `"matchCase":true`) || !strings.Contains(body, `"replaceText":"Alice"`) {
		t.Errorf("body = %s", body)
	}
	// An empty replacement deletes the matches; it must be sent.
	if _, err := run(t, c, write("docs.replace_text", map[string]any{"document_id": docID, "find": "x", "replace": "", "match_case": false})); err != nil {
		t.Fatal(err)
	}
	if body := srv.Last(t, batchUpdatePath).Body; !strings.Contains(body, `"replaceText":""`) || strings.Contains(body, `"matchCase":true`) {
		t.Errorf("body = %s", body)
	}
	for _, args := range []map[string]any{{"document_id": docID, "replace": "x"}, {"document_id": docID, "find": "x"}, {"find": "x", "replace": "y"}} {
		_, err := run(t, c, write("docs.replace_text", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases("replace_all_reply.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{batchUpdatePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("docs.replace_text", map[string]any{"document_id": docID, "find": "a", "replace": "b"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestSheetsGetMetadata(t *testing.T) {
	srv := newAPIServer(t, map[string]route{sheetMetaPath: {status: 200, body: "spreadsheet_meta.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("sheets.get_metadata", map[string]any{"spreadsheet_id": sheetID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Title  string `json:"title"`
		URL    string `json:"url"`
		Sheets []struct {
			SheetID int64 `json:"sheet_id"`
			Title   string
			Rows    int64 `json:"rows"`
			Columns int64 `json:"columns"`
			Hidden  bool
		} `json:"sheets"`
	}
	decode(t, res, &out)
	if out.Title != "Budget 2026" || len(out.Sheets) != 2 || out.Sheets[1].SheetID != 77 || out.Sheets[0].Rows != 1000 || !out.Sheets[1].Hidden {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/v4/spreadsheets/"+sheetID); q.Get("fields") == "" || q.Get("includeGridData") == "true" {
		t.Errorf("query = %v (fields, never grid data)", q)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{sheetMetaPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("sheets.get_metadata", map[string]any{"spreadsheet_id": sheetID}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestSheetsUpdateRange(t *testing.T) {
	srv := newAPIServer(t, map[string]route{updateValuesPath: {status: 200, body: "values_update.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("sheets.update_range", map[string]any{"spreadsheet_id": sheetID, "range": "Budget!A1:C2", "rows": []any{[]any{"a", "b", "=1+1"}, []any{1.5, true, nil}}}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		UpdatedRange string `json:"updated_range"`
		UpdatedCells int64  `json:"updated_cells"`
	}
	decode(t, res, &out)
	if out.UpdatedRange != "Budget!A1:C2" || out.UpdatedCells != 6 {
		t.Errorf("out = %+v", out)
	}
	req := srv.Last(t, updateValuesPath)
	if req.URL.Query().Get("valueInputOption") != "RAW" || !strings.Contains(req.Body, `"=1+1"`) {
		t.Errorf("update = %v %s", req.URL.Query(), req.Body)
	}
	if ids := toolOf(t, c, "sheets.update_range").ResultIDs(res); ids["spreadsheet_id"] != sheetID || ids["updated_range"] != "Budget!A1:C2" {
		t.Errorf("ResultIDs = %v", ids)
	}
	for _, args := range []map[string]any{
		{"spreadsheet_id": sheetID, "range": "A1"},
		{"spreadsheet_id": sheetID, "range": "A1", "rows": []any{[]any{"x"}}, "value_input_option": "FORMULA"},
	} {
		_, err := run(t, c, write("sheets.update_range", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
}

func TestSheetsCreate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFilePath: {status: 200, body: "created_spreadsheet.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("sheets.create", map[string]any{"title": "Budget 2027", "parent_id": folderID}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "sheets.create").ResultIDs(res); ids["id"] != "1NewSheet000000000000000000000000000" || ids["url"] == "" {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := bodyOf(t, srv.Last(t, createFilePath))
	props, _ := body["appProperties"].(map[string]any)
	if body["mimeType"] != "application/vnd.google-apps.spreadsheet" || body["name"] != "Budget 2027" || props["mcp-gateway-op"] != opID {
		t.Errorf("body = %v", body)
	}
	_, err = run(t, c, write("sheets.create", map[string]any{}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	srv2 := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list_marker_hit.json"}})
	c2, _ := newConnector(t, srv2, connectors.Bounds{})
	tool, in := reconcileInput(t, c2, "sheets.create", map[string]any{"title": "x"})
	out, err := tool.Reconcile.Check(context.Background(), in)
	if err != nil || out.Outcome != connectors.ReconcileFound {
		t.Errorf("check = %+v, %v", out, err)
	}
}
