package google

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/api/docs/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// MaxStructureText bounds the text preview of one docs.get_structure
// element or table cell (bytes).
const MaxStructureText = 500

// Docs tool names (increment 5).
const (
	ToolGetStructure = "get_structure"
	ToolInsertText   = "insert_text"
	ToolInsertTable  = "insert_table"
	ToolInsertImage  = "insert_image"
	ToolDeleteRange  = "delete_range"
)

// Limits of insert_table (the Docs editor's own).
const (
	maxTableRows    = 1000
	maxTableColumns = 20
)

// DocCell is one table cell of get_structure: its position, indexes and
// a text preview.
type DocCell struct {
	Row           int    `json:"row"`
	Column        int    `json:"column"`
	Start         int64  `json:"start"`
	End           int64  `json:"end"`
	Text          string `json:"text"`
	TextTruncated bool   `json:"text_truncated,omitempty"`
}

// DocElement is one structural element of the body: its index range
// (what insert_text, delete_range and batch_update address), its type
// (paragraph, table, section_break, table_of_contents), and for a
// paragraph its named style, bullet and a text preview; for a table its
// size and cells.
type DocElement struct {
	Start         int64     `json:"start"`
	End           int64     `json:"end"`
	Type          string    `json:"type"`
	Style         string    `json:"style,omitempty"`
	Bullet        bool      `json:"bullet,omitempty"`
	Text          string    `json:"text,omitempty"`
	TextTruncated bool      `json:"text_truncated,omitempty"`
	Rows          int64     `json:"rows,omitempty"`
	Columns       int64     `json:"columns,omitempty"`
	Cells         []DocCell `json:"cells,omitempty"`
}

// DocStructure is get_structure's result.
type DocStructure struct {
	DocumentID string       `json:"document_id"`
	Title      string       `json:"title"`
	RevisionID string       `json:"revision_id,omitempty"`
	EndIndex   int64        `json:"end_index"`
	Headers    []string     `json:"headers,omitempty"`
	Footers    []string     `json:"footers,omitempty"`
	Elements   []DocElement `json:"elements"`
	Truncated  bool         `json:"truncated,omitempty"`
}

func (c *Connector) docsFullReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppDocs, Name: ToolGetStructure, Kind: connectors.KindRead,
		Description: "Get a Google Doc's structure: the body's elements in order with their start and end indexes (what insert_text, " +
			"delete_range and batch_update address), type (paragraph, table, section_break, table_of_contents), a paragraph's named style " +
			"(HEADING_1, NORMAL_TEXT, ...), bullet and text preview, a table's rows, columns and cells; end_index (the body's end), header " +
			"and footer ids and revision_id. Trailing elements are dropped to the result bounds (truncated).",
		InputSchema:      objectSchema([]property{documentIDProperty}, []string{"document_id"}),
		RequiredScopes:   []string{ScopeDocumentsReadonly},
		ResourceIdentity: documentIdentity,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) docsFullReadHandlers() map[string]handler {
	return map[string]handler{ToolGetStructure: c.getDocStructure}
}

var indexProperty = property{"index", "integer", "Body index to insert at (from get_structure; 1 is the start). The end of the body when omitted.", nil}

func (c *Connector) docsFullWriteTools() []connectors.Tool {
	return []connectors.Tool{
		c.batchTool(docsBatch),
		c.helperTool(docsBatch, ToolInsertText, "Insert text into a Google Doc's body at index (from get_structure), or at its end.",
			[]property{{"text", "string", "Text to insert (line breaks start paragraphs).", nil}, indexProperty}, []string{"text"}),
		c.helperTool(docsBatch, ToolInsertTable, "Insert an empty table (rows x columns) into a Google Doc's body at index, or at its end; "+
			"fill it with insert_text at the cells' indexes (get_structure).",
			[]property{{"rows", "integer", "Number of rows (1-1000).", nil}, {"columns", "integer", "Number of columns (1-20).", nil}, indexProperty},
			[]string{"rows", "columns"}),
		c.helperTool(docsBatch, ToolInsertImage, "Insert an image from a public URL (PNG, JPEG or GIF, under 50 MB) into a Google Doc's body at "+
			"index, or at its end, optionally sized in points.",
			[]property{
				{"uri", "string", "Public http(s) URL of the image (Google fetches it once).", nil}, indexProperty,
				{"width_pt", "number", "Width in points.", nil}, {"height_pt", "number", "Height in points.", nil},
			}, []string{"uri"}),
		c.helperTool(docsBatch, ToolDeleteRange, "Delete the content between start_index and end_index (from get_structure) of a Google Doc's body.",
			[]property{
				{"start_index", "integer", "First index to delete (inclusive, at least 1).", nil},
				{"end_index", "integer", "Index after the last one to delete (exclusive).", nil},
			}, []string{"start_index", "end_index"}),
	}
}

func (c *Connector) docsFullWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolBatchUpdate: c.batchHandler(docsBatch),
		ToolInsertText:  c.helperHandler(docsBatch, fromArgs(buildInsertText)),
		ToolInsertTable: c.helperHandler(docsBatch, fromArgs(buildInsertTable)),
		ToolInsertImage: c.helperHandler(docsBatch, fromArgs(buildInsertImage)),
		ToolDeleteRange: c.helperHandler(docsBatch, fromArgs(buildDeleteRange)),
	}
}

// docLocation is {"location": {"index": n}} or, without an index,
// {"endOfSegmentLocation": {}} (the body's end).
func docLocation(args map[string]any, params map[string]any) error {
	index, ok, err := intArg(args, "index", false, 1, 1<<30)
	if err != nil {
		return err
	}
	if ok {
		params["location"] = map[string]any{"index": index}
	} else {
		params["endOfSegmentLocation"] = map[string]any{}
	}
	return nil
}

func buildInsertText(args map[string]any) (string, map[string]any, error) {
	text, err := textArg(args, "text", true)
	if err != nil {
		return "", nil, err
	}
	params := map[string]any{"text": text}
	return "insertText", params, docLocation(args, params)
}

func buildInsertTable(args map[string]any) (string, map[string]any, error) {
	rows, _, err := intArg(args, "rows", true, 1, maxTableRows)
	if err != nil {
		return "", nil, err
	}
	columns, _, err := intArg(args, "columns", true, 1, maxTableColumns)
	if err != nil {
		return "", nil, err
	}
	params := map[string]any{"rows": rows, "columns": columns}
	return "insertTable", params, docLocation(args, params)
}

func buildInsertImage(args map[string]any) (string, map[string]any, error) {
	uri, err := imageURIArg(args, "uri")
	if err != nil {
		return "", nil, err
	}
	params := map[string]any{"uri": uri}
	size := map[string]any{}
	for arg, field := range map[string]string{"width_pt": "width", "height_pt": "height"} {
		v, ok, err := numberArg(args, arg)
		if err != nil {
			return "", nil, err
		}
		if ok {
			size[field] = map[string]any{"magnitude": v, "unit": "PT"}
		}
	}
	if len(size) > 0 {
		params["objectSize"] = size
	}
	return "insertInlineImage", params, docLocation(args, params)
}

func buildDeleteRange(args map[string]any) (string, map[string]any, error) {
	start, _, err := intArg(args, "start_index", true, 1, 1<<30)
	if err != nil {
		return "", nil, err
	}
	end, _, err := intArg(args, "end_index", true, 2, 1<<30)
	if err != nil {
		return "", nil, err
	}
	if end <= start {
		return "", nil, invalid("end_index must be greater than start_index")
	}
	return "deleteContentRange", map[string]any{"range": map[string]any{"startIndex": start, "endIndex": end}}, nil
}

// --- get_structure ----------------------------------------------------------------

// preview cuts text to MaxStructureText bytes on a rune boundary.
func preview(text string) (string, bool) {
	text = strings.TrimRight(text, "\n")
	if len(text) <= MaxStructureText {
		return text, false
	}
	cut := MaxStructureText
	for cut > 0 && !isRuneStart(text[cut]) {
		cut--
	}
	return text[:cut], true
}

// paragraphText is a paragraph's text without its bullet prefix.
func paragraphText(p *docs.Paragraph) string {
	plain := *p
	plain.Bullet = nil
	var b strings.Builder
	writeParagraph(&b, &plain)
	return b.String()
}

func toDocElement(el *docs.StructuralElement) DocElement {
	out := DocElement{Start: el.StartIndex, End: el.EndIndex}
	switch {
	case el.Paragraph != nil:
		out.Type, out.Bullet = "paragraph", el.Paragraph.Bullet != nil
		if el.Paragraph.ParagraphStyle != nil {
			out.Style = el.Paragraph.ParagraphStyle.NamedStyleType
		}
		out.Text, out.TextTruncated = preview(paragraphText(el.Paragraph))
	case el.Table != nil:
		out.Type, out.Rows, out.Columns = "table", el.Table.Rows, el.Table.Columns
		for r, row := range el.Table.TableRows {
			if row == nil {
				continue
			}
			for col, cell := range row.TableCells {
				if cell == nil {
					continue
				}
				var b strings.Builder
				writeStructuralElements(&b, cell.Content)
				dc := DocCell{Row: r, Column: col, Start: cell.StartIndex, End: cell.EndIndex}
				dc.Text, dc.TextTruncated = preview(b.String())
				out.Cells = append(out.Cells, dc)
			}
		}
	case el.SectionBreak != nil:
		out.Type = "section_break"
	case el.TableOfContents != nil:
		out.Type = "table_of_contents"
		var b strings.Builder
		writeStructuralElements(&b, el.TableOfContents.Content)
		out.Text, out.TextTruncated = preview(b.String())
	default:
		out.Type = "other"
	}
	return out
}

func (c *Connector) getDocStructure(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "document_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.docs(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	doc, err := svc.Documents.Get(id).Context(ctx).Fields("documentId,title,revisionId,body,headers,footers").Do()
	if err := classify("get document", err); err != nil {
		return connectors.Result{}, err
	}
	out := DocStructure{DocumentID: id, Title: doc.Title, RevisionID: doc.RevisionId, Elements: []DocElement{}}
	for hid := range doc.Headers {
		out.Headers = append(out.Headers, hid)
	}
	for fid := range doc.Footers {
		out.Footers = append(out.Footers, fid)
	}
	slices.Sort(out.Headers)
	slices.Sort(out.Footers)
	if doc.Body != nil {
		for _, el := range doc.Body.Content {
			if el != nil {
				out.Elements = append(out.Elements, toDocElement(el))
			}
		}
	}
	if n := len(out.Elements); n > 0 {
		out.EndIndex = out.Elements[n-1].End
	}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Elements) > 1 {
		out.Elements = out.Elements[:len(out.Elements)-1]
		out.Truncated = true
	}
	return connectors.Result{Content: out, Empty: len(out.Elements) == 0, Partial: out.Truncated}, nil
}
