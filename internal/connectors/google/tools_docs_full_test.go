package google_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: docs.get_structure and the Docs edit helpers
// (insert_text, insert_table, insert_image, delete_range), each one
// batchUpdate request.

const docsReply = `{"documentId":"` + docID + `","replies":[{}],"writeControl":{"requiredRevisionId":"rev-9"}}`

type docElement struct {
	Start   int64  `json:"start"`
	End     int64  `json:"end"`
	Type    string `json:"type"`
	Style   string `json:"style"`
	Text    string `json:"text"`
	Bullet  bool   `json:"bullet"`
	Rows    int64  `json:"rows"`
	Columns int64  `json:"columns"`
	Cells   []struct {
		Row    int    `json:"row"`
		Column int    `json:"column"`
		Text   string `json:"text"`
	} `json:"cells"`
	TextTruncated bool `json:"text_truncated"`
}

type docStructure struct {
	DocumentID string       `json:"document_id"`
	Title      string       `json:"title"`
	RevisionID string       `json:"revision_id"`
	EndIndex   int64        `json:"end_index"`
	Elements   []docElement `json:"elements"`
	Truncated  bool         `json:"truncated"`
}

func TestDocsFullDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	declared(t, c, "docs.get_structure", connectors.KindRead, []string{google.ScopeDocumentsReadonly}, "")
	for _, name := range []string{"docs.insert_text", "docs.insert_table", "docs.insert_image", "docs.delete_range"} {
		tool := declared(t, c, name, connectors.KindWrite, []string{google.ScopeDocuments}, connectors.ReconcileNone)
		id := tool.ResourceIdentity(map[string]any{"document_id": docID, "text": "secret", "uri": "https://secret.test/x.png", "index": 5})
		if id["document_id"] != docID || len(id) != 1 {
			t.Errorf("%s identity = %v", name, id)
		}
	}
}

func TestDocsGetStructure(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getDocPath: {status: 200, body: "document.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("docs.get_structure", map[string]any{"document_id": docID}))
	if err != nil {
		t.Fatal(err)
	}
	var out docStructure
	decode(t, res, &out)
	if out.DocumentID != docID || out.RevisionID != "ALBJ4LtExample" || out.Title != "Gateway notes" || len(out.Elements) < 6 {
		t.Fatalf("out = %+v", out)
	}
	byType := map[string]docElement{}
	for _, e := range out.Elements {
		if _, ok := byType[e.Type]; !ok {
			byType[e.Type] = e
		}
	}
	if h := out.Elements[1]; h.Type != "paragraph" || h.Style != "HEADING_1" || h.Start != 1 || h.End != 16 || h.Text != "Gateway notes" {
		t.Errorf("heading = %+v", h)
	}
	if tb := byType["table"]; tb.Rows != 2 || tb.Columns != 2 || tb.Start != 68 || len(tb.Cells) != 4 || tb.Cells[3].Text != "Owner\n(acting)" || tb.Cells[3].Row != 1 {
		t.Errorf("table = %+v", tb)
	}
	if _, ok := byType["section_break"]; !ok {
		t.Error("no section_break")
	}
	if _, ok := byType["table_of_contents"]; !ok {
		t.Error("no table_of_contents")
	}
	if out.EndIndex == 0 || out.EndIndex != out.Elements[len(out.Elements)-1].End {
		t.Errorf("end_index = %d", out.EndIndex)
	}
	if q := query(t, srv, "/v1/documents/"+docID); q.Get("fields") == "" {
		t.Error("documents.get needs fields")
	}
	// Bounds: trailing elements dropped.
	c, _ = newConnector(t, srv, connectors.Bounds{MaxResultBytes: 600})
	res, err = run(t, c, call("docs.get_structure", map[string]any{"document_id": docID}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &out)
	if !out.Truncated || !res.Partial || encodedSizeOf(t, res) > 600 || len(out.Elements) == 0 {
		t.Errorf("bounded: truncated %v partial %v size %d elements %d", out.Truncated, res.Partial, encodedSizeOf(t, res), len(out.Elements))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getDocPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("docs.get_structure", map[string]any{"document_id": docID}))
			checkReadError(t, tc, res, err)
		})
	}
}

// A paragraph's long text is cut to a preview; the indexes stay exact.
func TestDocsGetStructureCutsLongText(t *testing.T) {
	long := strings.Repeat("word ", 400)
	doc := `{"documentId":"` + docID + `","title":"t","body":{"content":[{"startIndex":1,"endIndex":2001,"paragraph":{"elements":[{"startIndex":1,"endIndex":2001,"textRun":{"content":"` + long + `\n"}}]}}]}}`
	srv := newAPIServer(t, map[string]route{getDocPath: {status: 200, body: doc}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("docs.get_structure", map[string]any{"document_id": docID}))
	if err != nil {
		t.Fatal(err)
	}
	var out docStructure
	decode(t, res, &out)
	if e := out.Elements[0]; !e.TextTruncated || len(e.Text) > google.MaxStructureText || e.End != 2001 {
		t.Errorf("element = %+v", e)
	}
}

func TestDocsEditHelpers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{batchUpdatePath: {status: 200, body: docsReply}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	for _, tc := range []struct {
		tool string
		args map[string]any
		want []string
	}{
		{"docs.insert_text", map[string]any{"text": "Hello", "index": 5}, []string{`"insertText"`, `"text":"Hello"`, `"location":{"index":5}`}},
		{"docs.insert_text", map[string]any{"text": "Tail"}, []string{`"insertText"`, `"endOfSegmentLocation":{}`}},
		{"docs.insert_table", map[string]any{"rows": 3, "columns": 2, "index": 10}, []string{`"insertTable"`, `"rows":3`, `"columns":2`, `"location":{"index":10}`}},
		{"docs.insert_table", map[string]any{"rows": 1, "columns": 1}, []string{`"insertTable"`, `"endOfSegmentLocation":{}`}},
		{"docs.insert_image", map[string]any{"uri": "https://example.test/a.png", "width_pt": 100, "height_pt": 50},
			[]string{`"insertInlineImage"`, `"uri":"https://example.test/a.png"`, `"endOfSegmentLocation":{}`, `"width":{"magnitude":100,"unit":"PT"}`}},
		{"docs.delete_range", map[string]any{"start_index": 3, "end_index": 9}, []string{`"deleteContentRange"`, `"range":{"endIndex":9,"startIndex":3}`}},
		{"docs.delete_range", map[string]any{"start_index": 3, "end_index": 9, "required_revision_id": "rev-1"}, []string{`"writeControl":{"requiredRevisionId":"rev-1"}`}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			tc.args["document_id"] = docID
			res, err := run(t, c, write(tc.tool, tc.args))
			if err != nil {
				t.Fatal(err)
			}
			body := srv.Last(t, batchUpdatePath).Body
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("body %s lacks %s", body, w)
				}
			}
			var out struct {
				DocumentID string `json:"document_id"`
				RevisionID string `json:"revision_id"`
			}
			decode(t, res, &out)
			if out.DocumentID != docID || out.RevisionID != "rev-9" {
				t.Errorf("out = %+v", out)
			}
			if ids := toolOf(t, c, tc.tool).ResultIDs(res); ids["document_id"] != docID {
				t.Errorf("ResultIDs = %v", ids)
			}
		})
	}
	calls := len(tk.calls)
	for tool, args := range map[string][]map[string]any{
		"docs.insert_text":  {{"text": ""}, {"text": "x", "index": 0}, {"text": "x", "index": "five"}},
		"docs.insert_table": {{"rows": 0, "columns": 1}, {"rows": 1}, {"rows": 1, "columns": 21}, {"rows": 1001, "columns": 1}},
		"docs.insert_image": {{}, {"uri": "ftp://x/a.png"}, {"uri": "not a uri"}, {"uri": "https://x.test/a.png", "width_pt": -1}},
		"docs.delete_range": {{"start_index": 3}, {"start_index": 5, "end_index": 5}, {"start_index": 0, "end_index": 2}},
	} {
		for _, a := range args {
			a["document_id"] = docID
			_, err := run(t, c, write(tool, a))
			if err == nil {
				t.Errorf("%s %v: no error", tool, a)
				continue
			}
			wantClass(t, err, google.ClassInvalidArgument, 0)
		}
	}
	if len(tk.calls) != calls {
		t.Errorf("invalid arguments fetched the token %d times", len(tk.calls)-calls)
	}
	for _, tc := range writeErrorCases(docsReply) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{batchUpdatePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("docs.insert_text", map[string]any{"document_id": docID, "text": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
}
