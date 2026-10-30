package google

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	"google.golang.org/api/docs/v1"
	"google.golang.org/api/sheets/v4"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Docs and Sheets management tool names.
const (
	ToolReplaceText       = "replace_text"
	ToolGetSheetMetadata  = "get_metadata"
	ToolUpdateRange       = "update_range"
	ToolCreateSpreadsheet = "create"
)

// MimeSpreadsheet is the Google Sheets MIME type sheets.create creates.
const MimeSpreadsheet = "application/vnd.google-apps.spreadsheet"

// ReplacedText is replace_text's result.
type ReplacedText struct {
	DocumentID         string `json:"document_id"`
	OccurrencesChanged int64  `json:"occurrences_changed"`
}

// SheetInfo is one sheet (tab) of a spreadsheet.
type SheetInfo struct {
	SheetID int64  `json:"sheet_id"`
	Title   string `json:"title"`
	Index   int64  `json:"index"`
	Type    string `json:"type,omitempty"`
	Rows    int64  `json:"rows,omitempty"`
	Columns int64  `json:"columns,omitempty"`
	Hidden  bool   `json:"hidden,omitempty"`
}

// SpreadsheetMetadata is get_metadata's result.
type SpreadsheetMetadata struct {
	SpreadsheetID string      `json:"spreadsheet_id"`
	Title         string      `json:"title"`
	URL           string      `json:"url,omitempty"`
	Locale        string      `json:"locale,omitempty"`
	TimeZone      string      `json:"time_zone,omitempty"`
	Sheets        []SheetInfo `json:"sheets"`
	Truncated     bool        `json:"truncated,omitempty"`
}

func (c *Connector) docsManageWriteTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppDocs, Name: ToolReplaceText, Kind: connectors.KindWrite,
		Description: "Replace every occurrence of find with replace in a Google Doc's body (match_case default true; an empty replace " +
			"deletes the matches). Returns how many occurrences changed. Cannot be verified after an unknown outcome: check the document.",
		InputSchema: objectSchema([]property{
			documentIDProperty,
			{"find", "string", "Text to find.", nil},
			{"replace", "string", "Replacement text (may be empty).", nil},
			{"match_case", "boolean", "Case-sensitive match. Default true.", nil},
		}, []string{"document_id", "find", "replace"}),
		RequiredScopes:   []string{ScopeDocuments},
		ResourceIdentity: documentIdentity,
		Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
		ResultIDs: func(res connectors.Result) map[string]string {
			if v, ok := res.Content.(ReplacedText); ok && v.DocumentID != "" {
				return map[string]string{"document_id": v.DocumentID}
			}
			return nil
		},
		Bounds: c.singleBounds(),
	}}
}

func (c *Connector) docsManageWriteHandlers() map[string]handler {
	return map[string]handler{ToolReplaceText: c.replaceText}
}

func (c *Connector) sheetsManageReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppSheets, Name: ToolGetSheetMetadata, Kind: connectors.KindRead,
		Description: "Get a Google Sheet's title, url, locale, time zone and its sheets (tabs): sheet_id, title, index, type, rows, columns, hidden. " +
			"Use a tab's title in read_range's A1 range. Never cell values.",
		InputSchema:      objectSchema([]property{spreadsheetIDProperty}, []string{"spreadsheet_id"}),
		RequiredScopes:   []string{ScopeSpreadsheetsReadonly},
		ResourceIdentity: spreadsheetIdentity,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) sheetsManageReadHandlers() map[string]handler {
	return map[string]handler{ToolGetSheetMetadata: c.getSheetMetadata}
}

func (c *Connector) sheetsManageWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppSheets, Name: ToolUpdateRange, Kind: connectors.KindWrite,
			Description: "Overwrite the cells of a range (Sheet1!A1:C2) with rows (an array of rows, each an array of cell values), " +
				"stored as text unless value_input_option is USER_ENTERED. At most 500 rows and 10 000 cells. Returns the updated range and cell count. " +
				"Cannot be verified after an unknown outcome: check the sheet.",
			InputSchema: objectSchema([]property{
				spreadsheetIDProperty,
				rangeProperty,
				{"rows", "matrix", "Rows to write: an array of rows, each an array of cell values (strings).", nil},
				{"value_input_option", "string", "RAW (default: cells stored as given, '=' is text) or USER_ENTERED (parsed as if typed).", valueInputOptions},
			}, []string{"spreadsheet_id", "range", "rows"}),
			RequiredScopes:   []string{ScopeSpreadsheets},
			ResourceIdentity: spreadsheetIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        appendedRowsResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppSheets, Name: ToolCreateSpreadsheet, Kind: connectors.KindWrite,
			Description: "Create an empty Google Sheet with a title, in the root of My Drive, under parent_id, or in the shared drive drive_id. " +
				"Returns the new spreadsheet's id and url; fill it with update_range or append_rows.",
			InputSchema: objectSchema([]property{
				{"title", "string", "Spreadsheet title.", nil},
				{"parent_id", "string", "Id of the folder to create it in; the root of My Drive (or of drive_id) when omitted.", nil},
				{"drive_id", "string", "Shared drive to create it in (its root when parent_id is omitted).", nil},
			}, []string{"title"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: driveIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDriveMarker},
			ResultIDs:        createdFileResultIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) sheetsManageWriteHandlers() map[string]handler {
	return map[string]handler{ToolUpdateRange: c.updateRange, ToolCreateSpreadsheet: c.createSpreadsheet}
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) replaceText(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	documentID, err := idArg(call.Args, "document_id")
	if err != nil {
		return connectors.Result{}, err
	}
	find, err := textArg(call.Args, "find", true)
	if err != nil {
		return connectors.Result{}, err
	}
	if _, ok := call.Args["replace"]; !ok {
		return connectors.Result{}, invalid("replace is required (empty deletes the matches)")
	}
	replace, err := optionalString(call.Args, "replace") // kept as given: empty or whitespace is a valid replacement
	if err != nil {
		return connectors.Result{}, err
	}
	if utf8.RuneCountInString(replace) > MaxAppendTextChars {
		return connectors.Result{}, invalid("replace is longer than %d characters", MaxAppendTextChars)
	}
	matchCase, err := optionalBool(call.Args, "match_case", true)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.docs(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := &docs.ReplaceAllTextRequest{ContainsText: &docs.SubstringMatchCriteria{Text: find, MatchCase: matchCase}, ReplaceText: replace}
	req.ForceSendFields = []string{"ReplaceText"}
	req.ContainsText.ForceSendFields = []string{"MatchCase"}
	resp, err := svc.Documents.BatchUpdate(documentID, &docs.BatchUpdateDocumentRequest{Requests: []*docs.Request{{ReplaceAllText: req}}}).Context(ctx).Do()
	if err := classifyWrite("replace text", err); err != nil {
		return connectors.Result{}, err
	}
	out := ReplacedText{DocumentID: documentID}
	for _, r := range resp.Replies {
		if r != nil && r.ReplaceAllText != nil {
			out.OccurrencesChanged += r.ReplaceAllText.OccurrencesChanged
		}
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) getSheetMetadata(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	spreadsheetID, err := idArg(call.Args, "spreadsheet_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.sheets(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	ss, err := svc.Spreadsheets.Get(spreadsheetID).Context(ctx).IncludeGridData(false).
		Fields("spreadsheetId,spreadsheetUrl,properties(title,locale,timeZone),sheets(properties(sheetId,title,index,sheetType,hidden,gridProperties(rowCount,columnCount)))").Do()
	if err := classify("get spreadsheet", err); err != nil {
		return connectors.Result{}, err
	}
	out := SpreadsheetMetadata{SpreadsheetID: spreadsheetID, URL: ss.SpreadsheetUrl, Sheets: []SheetInfo{}}
	if ss.Properties != nil {
		out.Title, out.Locale, out.TimeZone = ss.Properties.Title, ss.Properties.Locale, ss.Properties.TimeZone
	}
	for _, s := range ss.Sheets {
		if s == nil || s.Properties == nil {
			continue
		}
		p := s.Properties
		info := SheetInfo{SheetID: p.SheetId, Title: p.Title, Index: p.Index, Type: p.SheetType, Hidden: p.Hidden}
		if p.GridProperties != nil {
			info.Rows, info.Columns = p.GridProperties.RowCount, p.GridProperties.ColumnCount
		}
		out.Sheets = append(out.Sheets, info)
	}
	res := connectors.Result{}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Sheets) > 1 {
		out.Sheets = out.Sheets[:len(out.Sheets)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) updateRange(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
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
	resp, err := svc.Spreadsheets.Values.Update(spreadsheetID, rng, &sheets.ValueRange{MajorDimension: "ROWS", Values: rows}).
		Context(ctx).ValueInputOption(option).Do()
	if err := classifyWrite("update range", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: AppendedRows{
		SpreadsheetID: spreadsheetID, UpdatedRange: resp.UpdatedRange, UpdatedRows: resp.UpdatedRows, UpdatedColumns: resp.UpdatedColumns, UpdatedCells: resp.UpdatedCells,
	}}, nil
}

// createSpreadsheet creates the sheet through Drive (files.create with
// the Sheets MIME type and the operation's marker, one request), like
// docs.create.
func (c *Connector) createSpreadsheet(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := newDriveFile(call, title, MimeSpreadsheet)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Files.Create(f).Context(ctx).SupportsAllDrives(true).Fields(createdFileFields).Do()
	if err := classifyWrite("create spreadsheet", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedFile{ID: created.Id, Name: title, MimeType: created.MimeType, URL: created.WebViewLink, Parents: created.Parents, DriveID: created.DriveId}}, nil
}
