package google_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

const (
	sheetID        = "1SheetAbCdEfGhIjKlMnOpQrStUvWxYz0123"
	sheetRange     = "Budget!A1:C4"
	getValuesPath  = "GET /v4/spreadsheets/" + sheetID + "/values/" + sheetRange
	appendRowsPath = "POST /v4/spreadsheets/" + sheetID + "/values/Budget!A:C:append"
)

func TestSheetsReadRange(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getValuesPath: {status: 200, body: "values_get.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("sheets.read_range", map[string]any{"spreadsheet_id": sheetID, "range": sheetRange}))
	if err != nil {
		t.Fatalf("sheets.read_range: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	q := query(t, srv, "/v4/spreadsheets/"+sheetID+"/values/"+sheetRange)
	if q.Get("majorDimension") != "ROWS" || q.Get("valueRenderOption") != "FORMATTED_VALUE" {
		t.Errorf("query = %v", q)
	}
	var values google.RangeValues
	decode(t, res, &values)
	if values.SpreadsheetID != sheetID || values.Range != sheetRange || values.RowCount != 4 || values.Truncated || len(values.Rows) != 4 ||
		strings.Join(values.Rows[0], "|") != "Item|Owner|Amount" || strings.Join(values.Rows[2], "|") != "Travel||3500.5" {
		t.Errorf("values = %+v", values)
	}
}

func TestSheetsReadRangeEmpty(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v4/spreadsheets/" + sheetID + "/values/Budget!Z1:Z10": {status: 200, body: "values_get_empty.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("sheets.read_range", map[string]any{"spreadsheet_id": sheetID, "range": "Budget!Z1:Z10"}))
	if err != nil {
		t.Fatal(err)
	}
	var values google.RangeValues
	decode(t, res, &values)
	if !res.Empty || values.RowCount != 0 || len(values.Rows) != 0 || values.Range != "Budget!Z1:Z10" {
		t.Errorf("res = %+v values = %+v, want Empty", res, values)
	}
}

func TestSheetsReadRangeBounds(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getValuesPath: {status: 200, body: "values_get.json"}})
	t.Run("max_rows", func(t *testing.T) {
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := run(t, c, call("sheets.read_range", map[string]any{"spreadsheet_id": sheetID, "range": sheetRange, "max_rows": 2}))
		if err != nil {
			t.Fatal(err)
		}
		var values google.RangeValues
		decode(t, res, &values)
		if !res.Partial || !values.Truncated || len(values.Rows) != 2 || values.RowCount != 4 || values.Rows[1][0] != "Laptops" {
			t.Errorf("res = %+v values = %+v, want the first two rows, partial", res, values)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 180})
		res, err := run(t, c, call("sheets.read_range", map[string]any{"spreadsheet_id": sheetID, "range": sheetRange}))
		if err != nil {
			t.Fatal(err)
		}
		var values google.RangeValues
		decode(t, res, &values)
		if !res.Partial || !values.Truncated || len(values.Rows) == 0 || len(values.Rows) >= 4 || values.RowCount != 4 || encodedSizeOf(t, res) > 180 {
			t.Errorf("res = %+v values = %+v size %d, want rows dropped to the bounds", res, values, encodedSizeOf(t, res))
		}
	})
	t.Run("max_rows above the ceiling is clamped", func(t *testing.T) {
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := run(t, c, call("sheets.read_range", map[string]any{"spreadsheet_id": sheetID, "range": sheetRange, "max_rows": google.MaxSheetRows + 1}))
		if err != nil {
			t.Fatal(err)
		}
		if !res.Partial {
			t.Errorf("res = %+v, want Partial when max_rows was clamped", res)
		}
	})
}

func TestSheetsReadRangeArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing spreadsheet_id": {"range": sheetRange},
		"bad spreadsheet_id":     {"spreadsheet_id": "a/b", "range": sheetRange},
		"missing range":          {"spreadsheet_id": sheetID},
		"range with newline":     {"spreadsheet_id": sheetID, "range": "A1\nB2"},
		"max_rows 0":             {"spreadsheet_id": sheetID, "range": sheetRange, "max_rows": 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, call("sheets.read_range", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getValuesPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("sheets.read_range", map[string]any{"spreadsheet_id": sheetID, "range": sheetRange}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestSheetsResourceIdentityAndScopes(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	read := toolOf(t, c, "sheets.read_range")
	if got := read.ResourceIdentity(map[string]any{"spreadsheet_id": " " + sheetID + " ", "range": sheetRange}); got["spreadsheet_id"] != sheetID || len(got) != 1 {
		t.Errorf("read identity = %v (the range is not identity)", got)
	}
	if got := read.ResourceIdentity(nil); len(got) != 0 {
		t.Errorf("read identity(nil) = %v", got)
	}
	if read.RequiredScopes[0] != google.ScopeSpreadsheetsReadonly || read.Kind != connectors.KindRead || read.Bounds.MaxPageSize != 0 {
		t.Errorf("read tool = %+v", read)
	}
	appendRows := toolOf(t, c, "sheets.append_rows")
	if got := appendRows.ResourceIdentity(map[string]any{"spreadsheet_id": sheetID, "range": "Budget!A:C", "rows": []any{[]any{"secret"}}}); got["spreadsheet_id"] != sheetID || len(got) != 1 {
		t.Errorf("append identity = %v", got)
	}
	if appendRows.RequiredScopes[0] != google.ScopeSpreadsheets || appendRows.Reconcile.Kind != connectors.ReconcileNone || appendRows.Reconcile.Check != nil || appendRows.ResultIDs == nil {
		t.Errorf("append tool = %+v", appendRows)
	}
	var schema struct {
		Properties map[string]struct {
			Type  string `json:"type"`
			Items struct {
				Type  string            `json:"type"`
				Items map[string]string `json:"items"`
			} `json:"items"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(appendRows.InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	if rows := schema.Properties["rows"]; rows.Type != "array" || rows.Items.Type != "array" || rows.Items.Items["type"] != "string" {
		t.Errorf("rows schema = %+v, want an array of arrays of strings", rows)
	}
}

// --- sheets.append_rows -------------------------------------------------------------------

func TestSheetsAppendRows(t *testing.T) {
	srv := newAPIServer(t, map[string]route{appendRowsPath: {status: 200, body: "values_append.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("sheets.append_rows", map[string]any{
		"spreadsheet_id": sheetID, "range": "Budget!A:C",
		"rows": []any{[]any{"Chairs", "bob@example.test", "=SUM(1,2)"}, []any{"Desks", 2, true}},
	}))
	if err != nil {
		t.Fatalf("sheets.append_rows: %v", err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	req := srv.Last(t, appendRowsPath)
	q := req.URL.Query()
	if q.Get("valueInputOption") != "RAW" || q.Get("insertDataOption") != "INSERT_ROWS" || q.Get("includeValuesInResponse") == "true" {
		t.Errorf("query = %v (RAW by default so '=' cells are text, rows inserted)", q)
	}
	var body struct {
		MajorDimension string     `json:"majorDimension"`
		Values         [][]string `json:"values"`
	}
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		t.Fatalf("body %s: %v", req.Body, err)
	}
	if body.MajorDimension != "ROWS" || len(body.Values) != 2 || strings.Join(body.Values[0], "|") != "Chairs|bob@example.test|=SUM(1,2)" || strings.Join(body.Values[1], "|") != "Desks|2|true" {
		t.Errorf("request body = %s", req.Body)
	}
	appended, ok := res.Content.(google.AppendedRows)
	if !ok || appended.SpreadsheetID != sheetID || appended.UpdatedRange != "Budget!A5:C6" || appended.UpdatedRows != 2 || appended.UpdatedCells != 6 {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolOf(t, c, "sheets.append_rows")
	if ids := tool.ResultIDs(res); ids["spreadsheet_id"] != sheetID || ids["updated_range"] != "Budget!A5:C6" || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.ResultIDs(connectors.Result{Content: "junk"}) != nil {
		t.Error("ResultIDs of a foreign result should be nil")
	}
	t.Run("USER_ENTERED on request", func(t *testing.T) {
		if _, err := run(t, c, write("sheets.append_rows", map[string]any{"spreadsheet_id": sheetID, "range": "Budget!A:C", "rows": []any{[]any{"x"}}, "value_input_option": "USER_ENTERED"})); err != nil {
			t.Fatal(err)
		}
		if got := srv.Last(t, appendRowsPath).URL.Query().Get("valueInputOption"); got != "USER_ENTERED" {
			t.Errorf("valueInputOption = %q", got)
		}
	})
}

func TestSheetsAppendRowsArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tooMany := make([]any, google.MaxAppendRows+1)
	for i := range tooMany {
		tooMany[i] = []any{"x"}
	}
	wide := make([]any, google.MaxAppendCells+1)
	for i := range wide {
		wide[i] = "x"
	}
	for name, args := range map[string]map[string]any{
		"missing spreadsheet_id": {"range": "A:C", "rows": []any{[]any{"x"}}},
		"missing range":          {"spreadsheet_id": sheetID, "rows": []any{[]any{"x"}}},
		"missing rows":           {"spreadsheet_id": sheetID, "range": "A:C"},
		"empty rows":             {"spreadsheet_id": sheetID, "range": "A:C", "rows": []any{}},
		"rows not arrays":        {"spreadsheet_id": sheetID, "range": "A:C", "rows": []any{"x"}},
		"cell not scalar":        {"spreadsheet_id": sheetID, "range": "A:C", "rows": []any{[]any{map[string]any{}}}},
		"too many rows":          {"spreadsheet_id": sheetID, "range": "A:C", "rows": tooMany},
		"too many cells":         {"spreadsheet_id": sheetID, "range": "A:C", "rows": []any{wide}},
		"bad value_input_option": {"spreadsheet_id": sheetID, "range": "A:C", "rows": []any{[]any{"x"}}, "value_input_option": "FORMULA"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("sheets.append_rows", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("values_append.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{appendRowsPath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("sheets.append_rows", map[string]any{"spreadsheet_id": sheetID, "range": "Budget!A:C", "rows": []any{[]any{"x"}}}))
			checkWriteError(t, tc, res, err)
		})
	}
}
