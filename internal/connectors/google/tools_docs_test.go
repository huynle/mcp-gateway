package google_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/docs/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// loadDocument decodes a testdata Docs API document.
func loadDocument(t *testing.T, name string) *docs.Document {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var doc docs.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

// DocumentText renders the body as plain text: paragraphs keep their
// trailing newline, bullets get a "- " prefix (indented per nesting
// level), person chips and rich links render their name or title,
// footnote references and section breaks vanish, tables render one row
// per line with cells separated by tabs (a cell's paragraphs joined by a
// space), tables of contents render their entries.
func TestDocumentText(t *testing.T) {
	got := google.DocumentText(loadDocument(t, "document.json"))
	want := "Gateway notes\n" +
		"Reviewed with Bob Example and Design doc today.\n" +
		"- First item\n" +
		"  - Second item\n" +
		"Name\tRole\n" +
		"Alice\tOwner (acting)\n" +
		"\n" +
		"Contents entry\n" +
		"The end\n"
	if got != want {
		t.Errorf("DocumentText =\n%q\nwant\n%q", got, want)
	}
	if google.DocumentText(&docs.Document{}) != "" || google.DocumentText(nil) != "" {
		t.Error("a document without a body renders as empty text")
	}
}

// --- docs.get_text ----------------------------------------------------------------------

const (
	docID           = "1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	getDocPath      = "GET /v1/documents/" + docID
	newDocID        = "1NewDoc0000000000000000000000000000"
	batchUpdatePath = "POST /v1/documents/" + docID + ":batchUpdate"
	newDocBatchPath = "POST /v1/documents/" + newDocID + ":batchUpdate"
)

func TestDocsGetText(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getDocPath: {status: 200, body: "document.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("docs.get_text", map[string]any{"document_id": docID}))
	if err != nil {
		t.Fatalf("docs.get_text: %v", err)
	}
	if res.Empty || res.Partial || res.Unavailable {
		t.Errorf("markers = %+v", res)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	if q := query(t, srv, "/v1/documents/"+docID); q.Get("includeTabsContent") != "" {
		t.Errorf("query = %v", q)
	}
	var doc google.DocumentContent
	decode(t, res, &doc)
	if doc.ID != docID || doc.Title != "Gateway notes" || doc.RevisionID != "ALBJ4LtExample" || doc.URL != "https://docs.google.com/document/d/"+docID+"/edit" ||
		!strings.HasPrefix(doc.Text, "Gateway notes\nReviewed with Bob Example") || !strings.HasSuffix(doc.Text, "The end\n") || doc.Characters != len([]rune(doc.Text)) || doc.Truncated {
		t.Errorf("doc = %+v", doc)
	}
	t.Run("empty document", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1/documents/1EmptyDoc000000000000000000000000000": {status: 200, body: "document_empty.json"}})
		c, _ := newConnector(t, srv, connectors.Bounds{})
		res, err := run(t, c, call("docs.get_text", map[string]any{"document_id": "1EmptyDoc000000000000000000000000000"}))
		if err != nil {
			t.Fatal(err)
		}
		var doc google.DocumentContent
		decode(t, res, &doc)
		if !res.Empty || doc.Title != "Empty" || strings.TrimSpace(doc.Text) != "" {
			t.Errorf("res = %+v doc = %+v, want Empty", res, doc)
		}
	})
	t.Run("text cut to the bounds", func(t *testing.T) {
		c, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 300})
		res, err := run(t, c, call("docs.get_text", map[string]any{"document_id": docID}))
		if err != nil {
			t.Fatal(err)
		}
		var doc google.DocumentContent
		decode(t, res, &doc)
		if !res.Partial || !doc.Truncated || doc.ID != docID || doc.Text == "" || !strings.HasPrefix(doc.Text, "Gateway notes\n") || encodedSizeOf(t, res) > 300 {
			t.Errorf("res = %+v doc = %+v", res, doc)
		}
		if doc.Characters <= len([]rune(doc.Text)) {
			t.Errorf("characters = %d should count the whole text, not the %d returned", doc.Characters, len([]rune(doc.Text)))
		}
	})
	t.Run("arguments and errors", func(t *testing.T) {
		c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
		for name, args := range map[string]map[string]any{"missing": {}, "slash": {"document_id": "a/b"}} {
			_, err := run(t, c, call("docs.get_text", args))
			if err == nil {
				t.Errorf("%s: no error", name)
				continue
			}
			wantClass(t, err, google.ClassInvalidArgument, 0)
		}
		if len(tk.calls) != 0 {
			t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
		}
		for _, tc := range readErrorCases() {
			t.Run(tc.name, func(t *testing.T) {
				srv := newAPIServer(t, map[string]route{getDocPath: tc.rt})
				c, _ := newConnector(t, srv, connectors.Bounds{})
				res, err := run(t, c, call("docs.get_text", map[string]any{"document_id": docID}))
				checkReadError(t, tc, res, err)
			})
		}
	})
}

func TestDocsResourceIdentityAndScopes(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	get := toolOf(t, c, "docs.get_text")
	if got := get.ResourceIdentity(map[string]any{"document_id": " " + docID + " "}); got["document_id"] != docID || len(got) != 1 {
		t.Errorf("get identity = %v", got)
	}
	if got := get.ResourceIdentity(nil); len(got) != 0 {
		t.Errorf("get identity(nil) = %v", got)
	}
	if get.RequiredScopes[0] != google.ScopeDocumentsReadonly || get.Kind != connectors.KindRead || get.Bounds.MaxPageSize != 0 {
		t.Errorf("get tool = %+v", get)
	}
	create := toolOf(t, c, "docs.create")
	if got := create.ResourceIdentity(map[string]any{"title": "secret", "body_text": "secret"}); got["drive"] != "my" || len(got) != 1 {
		t.Errorf("create identity = %v", got)
	}
	if create.RequiredScopes[0] != google.ScopeDriveFile || create.Reconcile.Kind != connectors.ReconcileMarker || create.Reconcile.Check == nil || create.ResultIDs == nil {
		t.Errorf("create tool = %+v", create)
	}
	appendText := toolOf(t, c, "docs.append_text")
	if got := appendText.ResourceIdentity(map[string]any{"document_id": docID, "text": "secret"}); got["document_id"] != docID || len(got) != 1 {
		t.Errorf("append identity = %v", got)
	}
	if appendText.RequiredScopes[0] != google.ScopeDocuments || appendText.Reconcile.Kind != connectors.ReconcileNone || appendText.Reconcile.Check != nil || appendText.ResultIDs == nil {
		t.Errorf("append tool = %+v", appendText)
	}
}

// --- docs.create -------------------------------------------------------------------------

// batchUpdateBody is the shape of an insertText batchUpdate request.
type batchUpdateBody struct {
	Requests []struct {
		InsertText struct {
			Text                 string          `json:"text"`
			EndOfSegmentLocation *map[string]any `json:"endOfSegmentLocation"`
			Location             *map[string]any `json:"location"`
		} `json:"insertText"`
	} `json:"requests"`
}

func TestDocsCreate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		createFilePath:  {status: 200, body: "created_document.json"},
		newDocBatchPath: {status: 200, body: "document_batch_update.json"},
	})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("docs.create", map[string]any{"title": "Gateway notes", "body_text": "First line.\nSecond line."}))
	if err != nil {
		t.Fatalf("docs.create: %v", err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v (one token per call, two requests)", tk.calls)
	}
	req := srv.Last(t, createFilePath)
	var file struct {
		Name          string            `json:"name"`
		MimeType      string            `json:"mimeType"`
		Parents       []string          `json:"parents"`
		AppProperties map[string]string `json:"appProperties"`
	}
	if err := json.Unmarshal([]byte(req.Body), &file); err != nil {
		t.Fatal(err)
	}
	if file.Name != "Gateway notes" || file.MimeType != google.MimeDocument || len(file.Parents) != 0 || file.AppProperties[google.DriveMarkerKey] != opID {
		t.Errorf("files.create body = %s", req.Body)
	}
	var batch batchUpdateBody
	if err := json.Unmarshal([]byte(srv.Last(t, newDocBatchPath).Body), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Requests) != 1 || batch.Requests[0].InsertText.Text != "First line.\nSecond line." || batch.Requests[0].InsertText.EndOfSegmentLocation == nil || batch.Requests[0].InsertText.Location != nil {
		t.Errorf("batchUpdate body = %s", srv.Last(t, newDocBatchPath).Body)
	}
	created, ok := res.Content.(google.CreatedDocument)
	if !ok || created.ID != newDocID || created.URL == "" || created.BodyStatus != "applied" || created.BodyError != "" {
		t.Errorf("content = %#v", res.Content)
	}
	tool := toolOf(t, c, "docs.create")
	if ids := tool.ResultIDs(res); ids["id"] != newDocID || ids["url"] != created.URL || len(ids) != 2 {
		t.Errorf("ResultIDs = %v", ids)
	}
	if tool.ResultIDs(connectors.Result{Content: "junk"}) != nil {
		t.Error("ResultIDs of a foreign result should be nil")
	}
}

func TestDocsCreateWithoutBodyAndInFolder(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFilePath: {status: 200, body: "created_document.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("docs.create", map[string]any{"title": "Blank", "parent_id": "1Folder0000000000000000000000000"}))
	if err != nil {
		t.Fatal(err)
	}
	if n := srv.Count(newDocBatchPath); n != 0 {
		t.Errorf("batchUpdate requests = %d, want none without body_text", n)
	}
	var file struct {
		Parents []string `json:"parents"`
	}
	if err := json.Unmarshal([]byte(srv.Last(t, createFilePath).Body), &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Parents) != 1 || file.Parents[0] != "1Folder0000000000000000000000000" {
		t.Errorf("parents = %v", file.Parents)
	}
	if created, ok := res.Content.(google.CreatedDocument); !ok || created.ID != newDocID || created.BodyStatus != "" {
		t.Errorf("content = %#v", res.Content)
	}
}

// The document exists once files.create answered: a failing body insert
// does not make the outcome unknown (the reconciler would only re-find
// the document). A known refusal reports body_status failed; a 5xx or
// timeout reports unknown (the text may be there).
func TestDocsCreateBodyInsertFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		rt     route
		status string
	}{
		"400 is failed":      {route{status: 400, body: "error_bad_request.json"}, "failed"},
		"403 is failed":      {route{status: 403, body: "error_insufficient_scope.json"}, "failed"},
		"500 is unknown":     {route{status: 500, body: "error_server.json"}, "unknown"},
		"timeout is unknown": {route{status: 200, body: "document_batch_update.json", delay: 2 * time.Second}, "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createFilePath: {status: 200, body: "created_document.json"}, newDocBatchPath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("docs.create", map[string]any{"title": "x", "body_text": "y"}))
			if err != nil {
				t.Fatalf("err = %v, want the created document", err)
			}
			created, ok := res.Content.(google.CreatedDocument)
			if !ok || created.ID != newDocID || created.BodyStatus != tc.status || created.BodyError == "" {
				t.Errorf("content = %#v, want body_status %s with an error", res.Content, tc.status)
			}
			if strings.Contains(created.BodyError, testToken) {
				t.Errorf("body_error leaks the token: %q", created.BodyError)
			}
		})
	}
}

func TestDocsCreateArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing title": {},
		"blank title":   {"title": " "},
		"bad body_text": {"title": "x", "body_text": 7},
		"bad parent_id": {"title": "x", "parent_id": "a b"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("docs.create", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("created_document.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createFilePath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("docs.create", map[string]any{"title": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestCheckDocsCreateUsesTheDriveMarker(t *testing.T) {
	srv := newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list_marker_doc_hit.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	tool, in := reconcileInput(t, c, "docs.create", map[string]any{"title": "x"})
	out, err := tool.Reconcile.Check(context.Background(), in)
	wantFound(t, out, err, newDocID)
	if q := query(t, srv, "/drive/v3/files"); q.Get("q") != google.DriveMarkerQuery(opID) {
		t.Errorf("listing query = %v", q)
	}
	srv = newAPIServer(t, map[string]route{listFilesPath: {status: 200, body: "files_list_empty.json"}})
	c, _ = newConnector(t, srv, connectors.Bounds{})
	tool, in = reconcileInput(t, c, "docs.create", map[string]any{"title": "x"})
	out, err = tool.Reconcile.Check(context.Background(), in)
	wantNotFound(t, out, err)
}

// --- docs.append_text ----------------------------------------------------------------------

func TestDocsAppendText(t *testing.T) {
	srv := newAPIServer(t, map[string]route{batchUpdatePath: {status: 200, body: `{"documentId":"` + docID + `","replies":[{}]}`}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("docs.append_text", map[string]any{"document_id": docID, "text": "Appended paragraph."}))
	if err != nil {
		t.Fatalf("docs.append_text: %v", err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	var batch batchUpdateBody
	if err := json.Unmarshal([]byte(srv.Last(t, batchUpdatePath).Body), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Requests) != 1 || batch.Requests[0].InsertText.Text != "\nAppended paragraph." || batch.Requests[0].InsertText.EndOfSegmentLocation == nil {
		t.Errorf("batchUpdate body = %s (the text starts a new paragraph at the end of the body)", srv.Last(t, batchUpdatePath).Body)
	}
	appended, ok := res.Content.(google.AppendedText)
	if !ok || appended.DocumentID != docID || appended.Characters != len([]rune("Appended paragraph.")) {
		t.Errorf("content = %#v", res.Content)
	}
	if ids := toolOf(t, c, "docs.append_text").ResultIDs(res); ids["document_id"] != docID || len(ids) != 1 {
		t.Errorf("ResultIDs = %v", ids)
	}
}

func TestDocsAppendTextArgumentsAndErrors(t *testing.T) {
	c, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for name, args := range map[string]map[string]any{
		"missing document_id": {"text": "x"},
		"bad document_id":     {"document_id": "a/b", "text": "x"},
		"missing text":        {"document_id": docID},
		"blank text":          {"document_id": docID, "text": " \n"},
		"text too long":       {"document_id": docID, "text": strings.Repeat("x", google.MaxAppendTextChars+1)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("docs.append_text", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases(`{"documentId":"` + docID + `"}`) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{batchUpdatePath: tc.rt})
			c := shortTimeout(t, srv)
			res, err := run(t, c, write("docs.append_text", map[string]any{"document_id": docID, "text": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
}
