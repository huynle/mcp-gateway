package google_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: sheets.batch_get, clear_range and the tab helpers
// (add_sheet, delete_sheet, rename_sheet, duplicate_sheet) and
// find_replace.

const (
	batchGetPath   = "GET /v4/spreadsheets/" + sheetID + "/values:batchGet"
	clearRangePath = "POST /v4/spreadsheets/" + sheetID + "/values/Budget!A1:C4:clear"
	batchGetBody   = `{"spreadsheetId":"` + sheetID + `","valueRanges":[{"range":"Budget!A1:B2","values":[["a","b"],["c","d"]]},{"range":"Other!A1","values":[["x"]]},{"range":"Empty!A1"}]}`
	sheetsReply    = `{"spreadsheetId":"` + sheetID + `","replies":[{}]}`
)

func sheetsWithIDs(ids ...int64) string {
	var parts []string
	for _, id := range ids {
		parts = append(parts, `{"properties":{"sheetId":`+strconv.FormatInt(id, 10)+`}}`)
	}
	return `{"spreadsheetId":"` + sheetID + `","sheets":[` + strings.Join(parts, ",") + `]}`
}

func TestSheetIDIsDerivedFromTheOperation(t *testing.T) {
	a, b := google.SheetID(opID), google.SheetID("another-operation")
	if a <= 0 || a > 1<<31-1 || a == b || a != google.SheetID(opID) {
		t.Errorf("SheetID = %d, %d", a, b)
	}
}

func TestSheetsFullDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	w := connectors.KindWrite
	declared(t, c, "sheets.batch_get", connectors.KindRead, []string{google.ScopeSpreadsheetsReadonly}, "")
	declared(t, c, "sheets.clear_range", w, []string{google.ScopeSpreadsheets}, connectors.ReconcileNone)
	declared(t, c, "sheets.add_sheet", w, []string{google.ScopeSpreadsheets}, connectors.ReconcileStableID)
	declared(t, c, "sheets.delete_sheet", w, []string{google.ScopeSpreadsheets}, connectors.ReconcileStableID)
	declared(t, c, "sheets.duplicate_sheet", w, []string{google.ScopeSpreadsheets}, connectors.ReconcileStableID)
	declared(t, c, "sheets.rename_sheet", w, []string{google.ScopeSpreadsheets}, connectors.ReconcileNone)
	declared(t, c, "sheets.find_replace", w, []string{google.ScopeSpreadsheets}, connectors.ReconcileNone)
	for name, want := range map[string]map[string]string{
		"sheets.batch_get":       {"spreadsheet_id": sheetID},
		"sheets.clear_range":     {"spreadsheet_id": sheetID},
		"sheets.add_sheet":       {"spreadsheet_id": sheetID},
		"sheets.delete_sheet":    {"spreadsheet_id": sheetID, "sheet_id": "7"},
		"sheets.duplicate_sheet": {"spreadsheet_id": sheetID, "sheet_id": "7"},
		"sheets.rename_sheet":    {"spreadsheet_id": sheetID, "sheet_id": "7"},
		"sheets.find_replace":    {"spreadsheet_id": sheetID},
	} {
		id := toolOf(t, c, name).ResourceIdentity(map[string]any{"spreadsheet_id": sheetID, "sheet_id": float64(7), "title": "secret", "find": "secret", "range": "A1", "ranges": []any{"A1"}})
		if len(id) != len(want) {
			t.Errorf("%s identity = %v, want %v", name, id, want)
		}
		for k, v := range want {
			if id[k] != v {
				t.Errorf("%s identity = %v, want %v", name, id, want)
			}
		}
	}
}

func TestSheetsBatchGet(t *testing.T) {
	srv := newAPIServer(t, map[string]route{batchGetPath: {status: 200, body: batchGetBody}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("sheets.batch_get", map[string]any{"spreadsheet_id": sheetID, "ranges": []any{"Budget!A1:B2", "Other!A1", "Empty!A1"}}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		SpreadsheetID string `json:"spreadsheet_id"`
		Ranges        []struct {
			Range    string     `json:"range"`
			RowCount int        `json:"row_count"`
			Rows     [][]string `json:"rows"`
		} `json:"ranges"`
		Truncated bool `json:"truncated"`
	}
	decode(t, res, &out)
	if out.SpreadsheetID != sheetID || len(out.Ranges) != 3 || out.Ranges[0].RowCount != 2 || out.Ranges[0].Rows[1][1] != "d" || out.Ranges[2].RowCount != 0 || res.Partial {
		t.Errorf("out = %+v", out)
	}
	q := query(t, srv, "/v4/spreadsheets/"+sheetID+"/values:batchGet")
	if len(q["ranges"]) != 3 || q.Get("valueRenderOption") != "FORMATTED_VALUE" {
		t.Errorf("query = %v", q)
	}
	// max_rows per range.
	if res, err = run(t, c, call("sheets.batch_get", map[string]any{"spreadsheet_id": sheetID, "ranges": []any{"Budget!A1:B2"}, "max_rows": 1})); err != nil {
		t.Fatal(err)
	}
	decode(t, res, &out)
	if len(out.Ranges[0].Rows) != 1 || !out.Truncated || !res.Partial {
		t.Errorf("max_rows = %+v", out)
	}
	calls := len(tk.calls)
	for _, args := range []map[string]any{
		{"spreadsheet_id": sheetID},
		{"spreadsheet_id": sheetID, "ranges": []any{}},
		{"spreadsheet_id": sheetID, "ranges": []any{"A\n1"}},
		{"spreadsheet_id": sheetID, "ranges": make([]any, google.MaxBatchRanges+1)},
	} {
		if r, ok := args["ranges"].([]any); ok && len(r) > 1 {
			for i := range r {
				r[i] = "A1"
			}
		}
		_, err := run(t, c, call("sheets.batch_get", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != calls {
		t.Error("invalid arguments must not fetch the token")
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{batchGetPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("sheets.batch_get", map[string]any{"spreadsheet_id": sheetID, "ranges": []any{"A1"}}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestSheetsClearRange(t *testing.T) {
	srv := newAPIServer(t, map[string]route{clearRangePath: {status: 200, body: `{"spreadsheetId":"` + sheetID + `","clearedRange":"Budget!A1:C4"}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("sheets.clear_range", map[string]any{"spreadsheet_id": sheetID, "range": "Budget!A1:C4"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "sheets.clear_range").ResultIDs(res); ids["spreadsheet_id"] != sheetID || ids["cleared_range"] != "Budget!A1:C4" {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err = run(t, c, write("sheets.clear_range", map[string]any{"spreadsheet_id": sheetID}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases(sheetsReply) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{clearRangePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("sheets.clear_range", map[string]any{"spreadsheet_id": sheetID, "range": "Budget!A1:C4"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestSheetsTabHelpers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{sheetsBatchPath: {status: 200, body: sheetsReply}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	derived := strconv.FormatInt(google.SheetID(opID), 10)
	for _, tc := range []struct {
		tool    string
		args    map[string]any
		want    []string
		sheetID string
	}{
		{"sheets.add_sheet", map[string]any{"title": "Q4", "index": 1, "rows": 100, "columns": 8},
			[]string{`"addSheet"`, `"sheetId":` + derived, `"title":"Q4"`, `"index":1`, `"rowCount":100`, `"columnCount":8`}, derived},
		{"sheets.add_sheet", map[string]any{}, []string{`"addSheet":{"properties":{"sheetId":` + derived + `}}`}, derived},
		{"sheets.delete_sheet", map[string]any{"sheet_id": 7}, []string{`"deleteSheet":{"sheetId":7}`}, "7"},
		{"sheets.rename_sheet", map[string]any{"sheet_id": 7, "title": "Renamed"},
			[]string{`"updateSheetProperties"`, `"fields":"title"`, `"sheetId":7`, `"title":"Renamed"`}, "7"},
		{"sheets.duplicate_sheet", map[string]any{"sheet_id": 7, "title": "Copy", "index": 2},
			[]string{`"duplicateSheet"`, `"sourceSheetId":7`, `"newSheetId":` + derived, `"newSheetName":"Copy"`, `"insertSheetIndex":2`}, derived},
		{"sheets.find_replace", map[string]any{"find": "2025", "replacement": "2026"},
			[]string{`"findReplace"`, `"find":"2025"`, `"replacement":"2026"`, `"allSheets":true`, `"matchCase":false`}, ""},
		{"sheets.find_replace", map[string]any{"find": "^a.*", "replacement": "", "sheet_id": 7, "regex": true, "match_case": true, "entire_cell": true, "include_formulas": true},
			[]string{`"sheetId":7`, `"searchByRegex":true`, `"matchCase":true`, `"matchEntireCell":true`, `"includeFormulas":true`, `"replacement":""`}, ""},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			tc.args["spreadsheet_id"] = sheetID
			res, err := run(t, c, write(tc.tool, tc.args))
			if err != nil {
				t.Fatal(err)
			}
			body := srv.Last(t, sheetsBatchPath).Body
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("body %s lacks %s", body, w)
				}
			}
			ids := toolOf(t, c, tc.tool).ResultIDs(res)
			if ids["spreadsheet_id"] != sheetID || ids["sheet_id"] != tc.sheetID {
				t.Errorf("ResultIDs = %v, want sheet_id %q", ids, tc.sheetID)
			}
		})
	}
	calls := len(tk.calls)
	for tool, args := range map[string][]map[string]any{
		"sheets.add_sheet":       {{"index": -1}, {"rows": 0}},
		"sheets.delete_sheet":    {{}, {"sheet_id": -1}, {"sheet_id": "x"}},
		"sheets.rename_sheet":    {{"sheet_id": 7}, {"title": "x"}},
		"sheets.duplicate_sheet": {{}},
		"sheets.find_replace":    {{"replacement": "x"}, {"find": "x"}},
	} {
		for _, a := range args {
			a["spreadsheet_id"] = sheetID
			_, err := run(t, c, write(tool, a))
			if err == nil {
				t.Errorf("%s %v: no error", tool, a)
				continue
			}
			wantClass(t, err, google.ClassInvalidArgument, 0)
		}
	}
	if len(tk.calls) != calls {
		t.Error("invalid arguments must not fetch the token")
	}
	for _, tc := range writeErrorCases(sheetsReply) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{sheetsBatchPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("sheets.add_sheet", map[string]any{"spreadsheet_id": sheetID}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestSheetsTabChecks(t *testing.T) {
	derived := google.SheetID(opID)
	for _, tc := range []struct {
		tool string
		rt   route
		want string
		id   string
	}{
		{"sheets.add_sheet", route{status: 200, body: sheetsWithIDs(0, derived)}, "found", strconv.FormatInt(derived, 10)},
		{"sheets.add_sheet", route{status: 200, body: sheetsWithIDs(0)}, "not_found", ""},
		{"sheets.duplicate_sheet", route{status: 200, body: sheetsWithIDs(7, derived)}, "found", strconv.FormatInt(derived, 10)},
		{"sheets.duplicate_sheet", route{status: 200, body: sheetsWithIDs(7)}, "not_found", ""},
		{"sheets.delete_sheet", route{status: 200, body: sheetsWithIDs(0)}, "found", "7"},
		{"sheets.delete_sheet", route{status: 200, body: sheetsWithIDs(0, 7)}, "not_found", ""},
		{"sheets.add_sheet", route{status: 404, body: "error_not_found.json"}, "cannot_tell", ""},
		{"sheets.delete_sheet", route{status: 500, body: "error_server.json"}, "cannot_tell", ""},
	} {
		t.Run(tc.tool+" "+tc.want, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{sheetMetaPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, tc.tool, map[string]any{"spreadsheet_id": sheetID, "sheet_id": float64(7)})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, tc.id)
			if tc.rt.status == 200 {
				if q := query(t, srv, "/v4/spreadsheets/"+sheetID); !strings.Contains(q.Get("fields"), "sheetId") {
					t.Errorf("fields = %q", q.Get("fields"))
				}
			}
		})
	}
}
