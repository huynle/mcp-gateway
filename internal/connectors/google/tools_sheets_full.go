package google

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/api/sheets/v4"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// MaxBatchRanges bounds the ranges of one sheets.batch_get.
const MaxBatchRanges = 50

// Sheets tool names (increment 5).
const (
	ToolBatchGet       = "batch_get"
	ToolClearRange     = "clear_range"
	ToolAddSheet       = "add_sheet"
	ToolDeleteSheet    = "delete_sheet"
	ToolRenameSheet    = "rename_sheet"
	ToolDuplicateSheet = "duplicate_sheet"
	ToolFindReplace    = "find_replace"
)

// maxSheetID is the largest sheet id (Sheets ids are int32).
const maxSheetID = 1<<31 - 1

// SheetID returns the sheet id add_sheet and duplicate_sheet give the new
// sheet: the first 31 bits of sha256(operation id), never 0 (the id of a
// spreadsheet's first sheet). Sheets accepts a client-chosen id unique in
// the spreadsheet, so a retry of the same operation is refused rather
// than adding a second sheet, and the check finds the sheet by it.
func SheetID(operationID string) int64 {
	sum := sha256.Sum256([]byte(operationID))
	id := int64(binary.BigEndian.Uint32(sum[:4]) & maxSheetID)
	if id == 0 {
		id = 1
	}
	return id
}

// RangeRows is one range of batch_get's result.
type RangeRows struct {
	Range     string     `json:"range"`
	RowCount  int        `json:"row_count"`
	Rows      [][]string `json:"rows"`
	Truncated bool       `json:"truncated,omitempty"`
}

// BatchValues is batch_get's result.
type BatchValues struct {
	SpreadsheetID string      `json:"spreadsheet_id"`
	Ranges        []RangeRows `json:"ranges"`
	Truncated     bool        `json:"truncated,omitempty"`
}

// ClearedRange is clear_range's result.
type ClearedRange struct {
	SpreadsheetID string `json:"spreadsheet_id"`
	ClearedRange  string `json:"cleared_range"`
}

var sheetIDProperty = property{"sheet_id", "integer", "The sheet's (tab's) id: sheet_id from get_metadata (not its title).", nil}

// sheetIdentity is spreadsheet_id and sheet_id (the tab, a number).
func sheetIdentity(args map[string]any) map[string]string {
	out := spreadsheetIdentity(args)
	if v, ok := args["sheet_id"]; ok && v != nil {
		if n, err := toInt(v); err == nil {
			out["sheet_id"] = strconv.Itoa(n)
		}
	}
	return out
}

func (c *Connector) sheetsFullReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppSheets, Name: ToolBatchGet, Kind: connectors.KindRead,
		Description: fmt.Sprintf("Read several ranges of a Google Sheet at once (at most %d, A1 notation with the sheet name), values as displayed: "+
			"per range its rows (the first max_rows each; default %d, at most %d). Trailing rows are dropped to the result bounds (truncated).",
			MaxBatchRanges, defaultSheetRows, MaxSheetRows),
		InputSchema: objectSchema([]property{
			spreadsheetIDProperty,
			{"ranges", "array", "A1 ranges: Sheet1!A1:D20, Budget!A:C, Sheet2.", nil},
			{"max_rows", "integer", "Rows per range (default 200, at most 1000).", nil},
		}, []string{"spreadsheet_id", "ranges"}),
		RequiredScopes:   []string{ScopeSpreadsheetsReadonly},
		ResourceIdentity: spreadsheetIdentity,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) sheetsFullReadHandlers() map[string]handler {
	return map[string]handler{ToolBatchGet: c.batchGet}
}

func (c *Connector) sheetsFullWriteTools() []connectors.Tool {
	addSheet := c.helperTool(sheetsBatch, ToolAddSheet, "Add a sheet (tab) to a Google Sheet: optional title (Google's \"SheetN\" when omitted), "+
		"index (position, 0 first), rows and columns. Returns the new sheet_id.",
		[]property{
			{"title", "string", "The new sheet's title (unique in the spreadsheet).", nil},
			{"index", "integer", "Position of the tab (0 is first; the end when omitted).", nil},
			{"rows", "integer", "Number of rows (default 1000).", nil},
			{"columns", "integer", "Number of columns (default 26).", nil},
		}, nil, spreadsheetIdentity)
	addSheet.Reconcile = connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSheet(sheetCreated)}
	deleteSheet := c.helperTool(sheetsBatch, ToolDeleteSheet, "Delete a sheet (tab) and everything in it from a Google Sheet.",
		[]property{sheetIDProperty}, []string{"sheet_id"}, sheetIdentity)
	deleteSheet.Reconcile = connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSheet(sheetDeleted)}
	duplicate := c.helperTool(sheetsBatch, ToolDuplicateSheet, "Duplicate a sheet (tab) of a Google Sheet with its contents and formatting: "+
		"optional title for the copy and index (position). Returns the copy's sheet_id.",
		[]property{
			sheetIDProperty,
			{"title", "string", "The copy's title (Google's \"Copy of ...\" when omitted).", nil},
			{"index", "integer", "Position of the copy (0 is first; after the source when omitted).", nil},
		}, []string{"sheet_id"}, sheetIdentity)
	duplicate.Reconcile = connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSheet(sheetCreated)}
	return []connectors.Tool{
		c.batchTool(sheetsBatch),
		{
			App: AppSheets, Name: ToolClearRange, Kind: connectors.KindWrite,
			Description: "Clear the values of a range of a Google Sheet (A1 notation with the sheet name); formatting stays. Cannot be verified " +
				"after an unknown outcome: check the sheet.",
			InputSchema:      objectSchema([]property{spreadsheetIDProperty, rangeProperty}, []string{"spreadsheet_id", "range"}),
			RequiredScopes:   []string{ScopeSpreadsheets},
			ResourceIdentity: spreadsheetIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(ClearedRange); ok && v.SpreadsheetID != "" {
					return map[string]string{"spreadsheet_id": v.SpreadsheetID, "cleared_range": v.ClearedRange}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
		addSheet,
		deleteSheet,
		c.helperTool(sheetsBatch, ToolRenameSheet, "Rename a sheet (tab) of a Google Sheet.",
			[]property{sheetIDProperty, {"title", "string", "The new title (unique in the spreadsheet).", nil}}, []string{"sheet_id", "title"}, sheetIdentity),
		duplicate,
		c.helperTool(sheetsBatch, ToolFindReplace, "Find and replace in a Google Sheet's cells: every sheet, or only sheet_id; match_case "+
			"(default false), entire_cell, regex (find is a regular expression; replacement may use $1), include_formulas. Google's reply "+
			"counts the values, formulas, rows and sheets changed.",
			[]property{
				{"find", "string", "Text (or regular expression) to find.", nil},
				{"replacement", "string", "Replacement (may be empty).", nil},
				sheetIDProperty,
				{"match_case", "boolean", "Case-sensitive. Default false.", nil},
				{"entire_cell", "boolean", "Match whole cells only. Default false.", nil},
				{"regex", "boolean", "find is a regular expression. Default false.", nil},
				{"include_formulas", "boolean", "Also search formulas. Default false.", nil},
			}, []string{"find", "replacement"}, spreadsheetIdentity),
	}
}

func (c *Connector) sheetsFullWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolBatchUpdate:    c.batchHandler(sheetsBatch),
		ToolClearRange:     c.clearRange,
		ToolAddSheet:       c.helperHandler(sheetsBatch, buildAddSheet),
		ToolDeleteSheet:    c.helperHandler(sheetsBatch, buildDeleteSheet),
		ToolRenameSheet:    c.helperHandler(sheetsBatch, buildRenameSheet),
		ToolDuplicateSheet: c.helperHandler(sheetsBatch, buildDuplicateSheet),
		ToolFindReplace:    c.helperHandler(sheetsBatch, buildFindReplace),
	}
}

// --- builders ---------------------------------------------------------------------

// sheetArg reads the required sheet_id.
func sheetArg(args map[string]any) (int64, error) {
	id, _, err := intArg(args, "sheet_id", true, 0, maxSheetID)
	return int64(id), err
}

// optionalTitle reads an optional non-blank title.
func optionalTitle(args map[string]any) (string, error) {
	t, err := optionalString(args, "title")
	if err != nil {
		return "", err
	}
	if t = strings.TrimSpace(t); len(t) > 1000 {
		return "", invalid("title is too long")
	}
	return t, nil
}

func buildAddSheet(call connectors.Call) (helperRequest, error) {
	id := SheetID(call.OperationID)
	props := map[string]any{"sheetId": id}
	title, err := optionalTitle(call.Args)
	if err != nil {
		return helperRequest{}, err
	}
	if title != "" {
		props["title"] = title
	}
	if index, ok, err := intArg(call.Args, "index", false, 0, 10000); err != nil {
		return helperRequest{}, err
	} else if ok {
		props["index"] = index
	}
	grid := map[string]any{}
	if rows, ok, err := intArg(call.Args, "rows", false, 1, 10_000_000); err != nil {
		return helperRequest{}, err
	} else if ok {
		grid["rowCount"] = rows
	}
	if columns, ok, err := intArg(call.Args, "columns", false, 1, 18278); err != nil {
		return helperRequest{}, err
	} else if ok {
		grid["columnCount"] = columns
	}
	if len(grid) > 0 {
		props["gridProperties"] = grid
	}
	return helperRequest{kind: "addSheet", params: map[string]any{"properties": props}, sheetID: &id}, nil
}

func buildDeleteSheet(call connectors.Call) (helperRequest, error) {
	id, err := sheetArg(call.Args)
	if err != nil {
		return helperRequest{}, err
	}
	return helperRequest{kind: "deleteSheet", params: map[string]any{"sheetId": id}, sheetID: &id}, nil
}

func buildRenameSheet(call connectors.Call) (helperRequest, error) {
	id, err := sheetArg(call.Args)
	if err != nil {
		return helperRequest{}, err
	}
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return helperRequest{}, err
	}
	return helperRequest{kind: "updateSheetProperties", params: map[string]any{
		"properties": map[string]any{"sheetId": id, "title": title}, "fields": "title",
	}, sheetID: &id}, nil
}

func buildDuplicateSheet(call connectors.Call) (helperRequest, error) {
	source, err := sheetArg(call.Args)
	if err != nil {
		return helperRequest{}, err
	}
	id := SheetID(call.OperationID)
	params := map[string]any{"sourceSheetId": source, "newSheetId": id}
	title, err := optionalTitle(call.Args)
	if err != nil {
		return helperRequest{}, err
	}
	if title != "" {
		params["newSheetName"] = title
	}
	if index, ok, err := intArg(call.Args, "index", false, 0, 10000); err != nil {
		return helperRequest{}, err
	} else if ok {
		params["insertSheetIndex"] = index
	}
	return helperRequest{kind: "duplicateSheet", params: params, sheetID: &id}, nil
}

func buildFindReplace(call connectors.Call) (helperRequest, error) {
	args := call.Args
	find, err := textArg(args, "find", true)
	if err != nil {
		return helperRequest{}, err
	}
	if _, ok := args["replacement"]; !ok {
		return helperRequest{}, invalid("replacement is required (empty deletes the matches)")
	}
	replacement, err := textArg(args, "replacement", false)
	if err != nil {
		return helperRequest{}, err
	}
	params := map[string]any{"find": find, "replacement": replacement}
	for arg, field := range map[string]string{"match_case": "matchCase", "entire_cell": "matchEntireCell", "regex": "searchByRegex", "include_formulas": "includeFormulas"} {
		v, err := optionalBool(args, arg, false)
		if err != nil {
			return helperRequest{}, err
		}
		params[field] = v
	}
	if id, ok, err := intArg(args, "sheet_id", false, 0, maxSheetID); err != nil {
		return helperRequest{}, err
	} else if ok {
		params["sheetId"] = id
	} else {
		params["allSheets"] = true
	}
	return helperRequest{kind: "findReplace", params: params}, nil
}

// --- handlers ---------------------------------------------------------------------

func (c *Connector) batchGet(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	spreadsheetID, err := idArg(call.Args, "spreadsheet_id")
	if err != nil {
		return connectors.Result{}, err
	}
	ranges, err := stringList(call.Args, "ranges")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(ranges) == 0 {
		return connectors.Result{}, invalid("ranges must hold at least one A1 range")
	}
	if len(ranges) > MaxBatchRanges {
		return connectors.Result{}, invalid("ranges holds %d ranges; at most %d per call", len(ranges), MaxBatchRanges)
	}
	for _, r := range ranges {
		if strings.ContainsAny(r, "\r\n") {
			return connectors.Result{}, invalid("each range must be A1 notation on one line")
		}
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
	resp, err := svc.Spreadsheets.Values.BatchGet(spreadsheetID).Ranges(ranges...).MajorDimension("ROWS").ValueRenderOption("FORMATTED_VALUE").Context(ctx).Do()
	if err := classify("read ranges", err); err != nil {
		return connectors.Result{}, err
	}
	out := BatchValues{SpreadsheetID: spreadsheetID, Ranges: []RangeRows{}}
	empty := true
	for _, vr := range resp.ValueRanges {
		if vr == nil {
			continue
		}
		rr := RangeRows{Range: vr.Range, RowCount: len(vr.Values), Rows: [][]string{}}
		for _, row := range vr.Values {
			if len(rr.Rows) == maxRows {
				rr.Truncated = true
				break
			}
			cells := make([]string, len(row))
			for i, cell := range row {
				if cells[i], err = cellString(cell); err != nil {
					cells[i] = fmt.Sprint(cell)
				}
			}
			rr.Rows = append(rr.Rows, cells)
		}
		if rr.RowCount > 0 {
			empty = false
		}
		out.Truncated = out.Truncated || rr.Truncated
		out.Ranges = append(out.Ranges, rr)
	}
	fitRanges(&out, c.bounds.MaxResultBytes)
	return connectors.Result{Content: out, Empty: empty, Partial: clamped || out.Truncated}, nil
}

// fitRanges drops trailing rows (from the last range that has some), then
// trailing ranges (never the first), until out fits max.
func fitRanges(out *BatchValues, max int) {
	for encodedSize(out) > max {
		i := len(out.Ranges) - 1
		for i >= 0 && len(out.Ranges[i].Rows) == 0 {
			i--
		}
		switch {
		case i >= 0:
			out.Ranges[i].Rows = out.Ranges[i].Rows[:len(out.Ranges[i].Rows)-1]
			out.Ranges[i].Truncated = true
		case len(out.Ranges) > 1:
			out.Ranges = out.Ranges[:len(out.Ranges)-1]
		default:
			return
		}
		out.Truncated = true
	}
}

func (c *Connector) clearRange(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	spreadsheetID, err := idArg(call.Args, "spreadsheet_id")
	if err != nil {
		return connectors.Result{}, err
	}
	rng, err := rangeArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.sheets(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := svc.Spreadsheets.Values.Clear(spreadsheetID, rng, &sheets.ClearValuesRequest{}).Context(ctx).Do()
	if err := classifyWrite("clear range", err); err != nil {
		return connectors.Result{}, err
	}
	out := ClearedRange{SpreadsheetID: spreadsheetID, ClearedRange: resp.ClearedRange}
	if out.ClearedRange == "" {
		out.ClearedRange = rng
	}
	return connectors.Result{Content: out}, nil
}

// --- reconciliation ---------------------------------------------------------------

// Sheet checks: a created sheet (add_sheet, duplicate_sheet: the id
// derived from the operation) or a deleted one (delete_sheet: the
// identity's sheet_id).
const (
	sheetCreated = iota
	sheetDeleted
)

// checkSheet reads the spreadsheet's sheet ids: a created sheet present
// (or a deleted one absent) is found, else not_found; any error is
// "cannot tell yet".
func (c *Connector) checkSheet(mode int) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		tg, err := c.target(in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ids, err := identityIDs(in, "spreadsheet_id")
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		want := SheetID(tg.operationID)
		if mode == sheetDeleted {
			if want, err = strconv.ParseInt(in.ResourceIdentity["sheet_id"], 10, 64); err != nil {
				return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no sheet", ErrNotReconcilable)
			}
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		svc, err := tg.client.sheets(ctx)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		s, err := svc.Spreadsheets.Get(ids[0]).Fields("sheets.properties.sheetId").Context(ctx).Do()
		if err := classify("reconcile: get spreadsheet", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		var present []int64
		for _, sh := range s.Sheets {
			if sh != nil && sh.Properties != nil {
				present = append(present, sh.Properties.SheetId)
			}
		}
		if slices.Contains(present, want) == (mode == sheetCreated) {
			return found(strconv.FormatInt(want, 10)), nil
		}
		return notFound, nil
	}
}
