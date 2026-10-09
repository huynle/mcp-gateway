package google

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/api/sheets/v4"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Sheets tool names.
const (
	ToolReadRange  = "read_range"
	ToolAppendRows = "append_rows"
)

// Bounds of the Sheets tools: read_range returns at most MaxSheetRows
// rows (default defaultSheetRows; the byte bounds apply on top);
// append_rows sends at most MaxAppendRows rows and MaxAppendCells cells.
const (
	MaxSheetRows     = 1000
	defaultSheetRows = 200
	MaxAppendRows    = 500
	MaxAppendCells   = 10000
)

// Values of append_rows's value_input_option: RAW (default) stores every
// cell as given, so a value starting with "=" is text, not a formula;
// USER_ENTERED parses cells as if typed (formulas, numbers, dates).
var valueInputOptions = []string{"RAW", "USER_ENTERED"}

// RangeValues is read_range's result: the rows of the range as strings
// (formatted as the sheet shows them), cut to max_rows and the result
// bounds (Truncated); RowCount counts the rows Google returned.
type RangeValues struct {
	SpreadsheetID string     `json:"spreadsheet_id"`
	Range         string     `json:"range"`
	RowCount      int        `json:"row_count"`
	Truncated     bool       `json:"truncated,omitempty"`
	Rows          [][]string `json:"rows"`
}

// AppendedRows is append_rows's result: where the rows went.
type AppendedRows struct {
	SpreadsheetID  string `json:"spreadsheet_id"`
	UpdatedRange   string `json:"updated_range,omitempty"`
	UpdatedRows    int64  `json:"updated_rows"`
	UpdatedColumns int64  `json:"updated_columns,omitempty"`
	UpdatedCells   int64  `json:"updated_cells"`
}

var (
	spreadsheetIDProperty = property{"spreadsheet_id", "string", "The spreadsheet's id (from drive.search, or the id in its URL).", nil}
	rangeProperty         = property{"range", "string", "A1 notation, with the sheet name: Sheet1!A1:D20, Budget!A:C (whole columns), or Sheet1 (the whole sheet).", nil}
)

// sheetsReadTools declares sheets.read_range.
func (c *Connector) sheetsReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppSheets, Name: ToolReadRange, Kind: connectors.KindRead,
		Description: "Read a range of a Google Sheet as rows of strings (values as the sheet displays them). " +
			"At most max_rows rows (default 200, up to 1000) and the result bounds; truncated says rows were dropped and row_count how many the range had.",
		InputSchema: objectSchema([]property{
			spreadsheetIDProperty,
			rangeProperty,
			{"max_rows", "integer", "Rows to return (1-1000; default 200).", nil},
		}, []string{"spreadsheet_id", "range"}),
		RequiredScopes:   []string{ScopeSpreadsheetsReadonly},
		ResourceIdentity: spreadsheetIdentity,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) sheetsReadHandlers() map[string]handler {
	return map[string]handler{ToolReadRange: c.readRange}
}

// sheetsWriteTools declares sheets.append_rows.
func (c *Connector) sheetsWriteTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppSheets, Name: ToolAppendRows, Kind: connectors.KindWrite,
		Description: "Append rows after the last row of the table that range points at (Sheet1!A:C appends under the data of columns A-C). " +
			"rows is an array of rows, each an array of cell strings; cells are stored as text unless value_input_option is USER_ENTERED. " +
			"Returns the updated range and cell count. Cannot be verified after an unknown outcome: check the sheet.",
		InputSchema: objectSchema([]property{
			spreadsheetIDProperty,
			rangeProperty,
			{"rows", "matrix", "Rows to append: an array of rows, each an array of cell values (strings).", nil},
			{"value_input_option", "string", "RAW (default: cells stored as given, '=' is text) or USER_ENTERED (parsed as if typed: formulas, numbers, dates).", valueInputOptions},
		}, []string{"spreadsheet_id", "range", "rows"}),
		RequiredScopes:   []string{ScopeSpreadsheets},
		ResourceIdentity: spreadsheetIdentity,
		Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
		ResultIDs:        appendedRowsResultIDs,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) sheetsWriteHandlers() map[string]handler {
	return map[string]handler{ToolAppendRows: c.appendRows}
}

// spreadsheetIdentity extracts spreadsheet_id from the arguments; the
// range and the cells are not identity.
func spreadsheetIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if id, _ := args["spreadsheet_id"].(string); strings.TrimSpace(id) != "" {
		out["spreadsheet_id"] = strings.TrimSpace(id)
	}
	return out
}

func appendedRowsResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(AppendedRows)
	if !ok || v.SpreadsheetID == "" {
		return nil
	}
	return map[string]string{"spreadsheet_id": v.SpreadsheetID, "updated_range": v.UpdatedRange}
}

// rangeArg reads the A1 range: non-blank, one line.
func rangeArg(args map[string]any) (string, error) {
	r, err := requiredString(args, "range")
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(r, "\r\n") {
		return "", invalid("range must be A1 notation on one line")
	}
	return r, nil
}

// cellString renders a cell value as text.
func cellString(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "", nil
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case json.Number:
		return x.String(), nil
	}
	return "", fmt.Errorf("not a cell value: %T", v)
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) readRange(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	spreadsheetID, err := idArg(call.Args, "spreadsheet_id")
	if err != nil {
		return connectors.Result{}, err
	}
	rng, err := rangeArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	maxRows, clamped := defaultSheetRows, false
	if v, ok := call.Args["max_rows"]; ok && v != nil {
		if maxRows, err = toInt(v); err != nil || maxRows < 1 {
			return connectors.Result{}, invalid("max_rows must be a positive integer")
		}
		if maxRows > MaxSheetRows {
			maxRows, clamped = MaxSheetRows, true
		}
	}
	svc, err := cl.sheets(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	vr, err := svc.Spreadsheets.Values.Get(spreadsheetID, rng).Context(ctx).MajorDimension("ROWS").ValueRenderOption("FORMATTED_VALUE").Do()
	if err := classify("read range", err); err != nil {
		return connectors.Result{}, err
	}
	out := RangeValues{SpreadsheetID: spreadsheetID, Range: vr.Range, RowCount: len(vr.Values), Rows: make([][]string, 0, min(len(vr.Values), maxRows))}
	if out.Range == "" {
		out.Range = rng
	}
	for _, row := range vr.Values {
		if len(out.Rows) == maxRows {
			out.Truncated = true
			break
		}
		cells := make([]string, len(row))
		for i, cell := range row {
			s, err := cellString(cell)
			if err != nil {
				s = fmt.Sprint(cell)
			}
			cells[i] = s
		}
		out.Rows = append(out.Rows, cells)
	}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Rows) > 1 {
		out.Rows = out.Rows[:len(out.Rows)-1]
		out.Truncated = true
	}
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: out.RowCount == 0}, nil
}

// rowsArg reads rows: a non-empty array of arrays of cell values, at
// most MaxAppendRows rows and MaxAppendCells cells.
func rowsArg(args map[string]any) ([][]any, error) {
	v, ok := args["rows"]
	if !ok || v == nil {
		return nil, invalid("rows is required")
	}
	list, ok := v.([]any)
	if !ok {
		return nil, invalid("rows must be an array of rows (each an array of cell values)")
	}
	if len(list) == 0 {
		return nil, invalid("rows must have at least one row")
	}
	if len(list) > MaxAppendRows {
		return nil, invalid("rows has %d rows; at most %d per call", len(list), MaxAppendRows)
	}
	out := make([][]any, 0, len(list))
	cells := 0
	for _, item := range list {
		var row []any
		switch r := item.(type) {
		case []any:
			row = r
		case []string:
			for _, s := range r {
				row = append(row, s)
			}
		default:
			return nil, invalid("rows must be an array of rows (each an array of cell values)")
		}
		cells += len(row)
		if cells > MaxAppendCells {
			return nil, invalid("rows has more than %d cells", MaxAppendCells)
		}
		values := make([]any, len(row))
		for i, cell := range row {
			s, err := cellString(cell)
			if err != nil {
				return nil, invalid("rows cells must be strings, numbers or booleans")
			}
			values[i] = s
		}
		out = append(out, values)
	}
	return out, nil
}

func (c *Connector) appendRows(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	spreadsheetID, err := idArg(call.Args, "spreadsheet_id")
	if err != nil {
		return connectors.Result{}, err
	}
	rng, err := rangeArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	rows, err := rowsArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	option, err := optionalString(call.Args, "value_input_option")
	if err != nil {
		return connectors.Result{}, err
	}
	if option = strings.TrimSpace(option); option == "" {
		option = valueInputOptions[0]
	}
	if !slices.Contains(valueInputOptions, option) {
		return connectors.Result{}, invalid("value_input_option must be RAW or USER_ENTERED")
	}
	svc, err := cl.sheets(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := svc.Spreadsheets.Values.Append(spreadsheetID, rng, &sheets.ValueRange{MajorDimension: "ROWS", Values: rows}).
		Context(ctx).ValueInputOption(option).InsertDataOption("INSERT_ROWS").Do()
	if err := classifyWrite("append rows", err); err != nil {
		return connectors.Result{}, err
	}
	out := AppendedRows{SpreadsheetID: spreadsheetID}
	if resp.Updates != nil {
		out.UpdatedRange, out.UpdatedRows, out.UpdatedColumns, out.UpdatedCells = resp.Updates.UpdatedRange, resp.Updates.UpdatedRows, resp.Updates.UpdatedColumns, resp.Updates.UpdatedCells
	}
	return connectors.Result{Content: out}, nil
}
