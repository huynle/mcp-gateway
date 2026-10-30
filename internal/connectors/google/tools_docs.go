package google

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"google.golang.org/api/docs/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// DocumentText renders a Docs API document's body as plain text (what
// docs.get_text returns): paragraphs keep their trailing newline,
// bulleted paragraphs get a "- " prefix indented two spaces per nesting
// level, person chips render their name (else their email), rich links
// their title (else their URI), footnote references, page breaks and
// section breaks vanish, tables render one row per line with the cells
// separated by tabs (a cell's paragraphs joined by a space) and tables
// of contents render their entries. Only the body is rendered: headers,
// footers, footnotes and further tabs are left out.
func DocumentText(doc *docs.Document) string {
	if doc == nil || doc.Body == nil {
		return ""
	}
	var b strings.Builder
	writeStructuralElements(&b, doc.Body.Content)
	return b.String()
}

func writeStructuralElements(b *strings.Builder, content []*docs.StructuralElement) {
	for _, el := range content {
		if el == nil {
			continue
		}
		switch {
		case el.Paragraph != nil:
			writeParagraph(b, el.Paragraph)
		case el.Table != nil:
			writeTable(b, el.Table)
		case el.TableOfContents != nil:
			writeStructuralElements(b, el.TableOfContents.Content)
		}
	}
}

func writeParagraph(b *strings.Builder, p *docs.Paragraph) {
	if p.Bullet != nil {
		b.WriteString(strings.Repeat("  ", int(p.Bullet.NestingLevel)))
		b.WriteString("- ")
	}
	for _, pe := range p.Elements {
		if pe == nil {
			continue
		}
		switch {
		case pe.TextRun != nil:
			b.WriteString(pe.TextRun.Content)
		case pe.Person != nil && pe.Person.PersonProperties != nil:
			if pe.Person.PersonProperties.Name != "" {
				b.WriteString(pe.Person.PersonProperties.Name)
			} else {
				b.WriteString(pe.Person.PersonProperties.Email)
			}
		case pe.RichLink != nil && pe.RichLink.RichLinkProperties != nil:
			if pe.RichLink.RichLinkProperties.Title != "" {
				b.WriteString(pe.RichLink.RichLinkProperties.Title)
			} else {
				b.WriteString(pe.RichLink.RichLinkProperties.Uri)
			}
		}
	}
}

func writeTable(b *strings.Builder, t *docs.Table) {
	for _, row := range t.TableRows {
		if row == nil {
			continue
		}
		for i, cell := range row.TableCells {
			if i > 0 {
				b.WriteByte('\t')
			}
			if cell == nil {
				continue
			}
			var cb strings.Builder
			writeStructuralElements(&cb, cell.Content)
			b.WriteString(strings.Join(strings.Fields(cb.String()), " "))
		}
		b.WriteByte('\n')
	}
}

// Docs tool names.
const (
	ToolGetText        = "get_text"
	ToolCreateDocument = "create"
	ToolAppendText     = "append_text"
)

// MaxAppendTextChars bounds the text one docs.append_text (or one
// docs.create body_text) sends.
const MaxAppendTextChars = 100_000

// Body statuses of docs.create's result.
const (
	BodyApplied = "applied"
	BodyFailed  = "failed"
	BodyUnknown = "unknown"
)

// DocumentContent is get_text's result: the document's plain text
// (DocumentText), cut to the result bounds (Truncated); Characters counts
// the whole text.
type DocumentContent struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	RevisionID string `json:"revision_id,omitempty"`
	URL        string `json:"url"`
	Characters int    `json:"characters"`
	Text       string `json:"text"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// CreatedDocument is create's result: the identifiers of the new
// document and, when body_text was given, whether it was inserted
// (BodyStatus applied, failed or unknown; BodyError says why not).
type CreatedDocument struct {
	ID         string `json:"id"`
	URL        string `json:"url,omitempty"`
	ParentID   string `json:"parent_id,omitempty"`
	DriveID    string `json:"drive_id,omitempty"`
	BodyStatus string `json:"body_status,omitempty"`
	BodyError  string `json:"body_error,omitempty"`
}

// AppendedText is append_text's result.
type AppendedText struct {
	DocumentID string `json:"document_id"`
	Characters int    `json:"characters"`
}

// docURL is the editor URL of a document.
func docURL(id string) string { return "https://docs.google.com/document/d/" + id + "/edit" }

var documentIDProperty = property{"document_id", "string", "The document's id (from drive.search, or the id in its URL).", nil}

// docsReadTools declares docs.get_text.
func (c *Connector) docsReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppDocs, Name: ToolGetText, Kind: connectors.KindRead,
		Description: "Get a Google Doc's text by id: the body as plain text (headings and paragraphs on their own lines, bullets as \"- \", " +
			"tables one row per line with tab-separated cells), cut to the result bounds (truncated says so; characters counts the whole text). " +
			"Headers, footers, footnotes and further tabs are left out.",
		InputSchema:      objectSchema([]property{documentIDProperty}, []string{"document_id"}),
		RequiredScopes:   []string{ScopeDocumentsReadonly},
		ResourceIdentity: documentIdentity,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) docsReadHandlers() map[string]handler {
	return map[string]handler{ToolGetText: c.getText}
}

// docsWriteTools declares docs.create and docs.append_text.
func (c *Connector) docsWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppDocs, Name: ToolCreateDocument, Kind: connectors.KindWrite,
			Description: "Create a Google Doc with a title and optionally its initial plain text (body_text), in the root of My Drive, under parent_id, " +
				"or in the shared drive drive_id. Returns the new document's id and url; body_status says whether body_text was inserted " +
				"(applied, failed: use append_text, unknown: check the document).",
			InputSchema: objectSchema([]property{
				{"title", "string", "Document title.", nil},
				{"body_text", "string", "Initial plain text of the document (line breaks start new paragraphs).", nil},
				{"parent_id", "string", "Id of the folder to create the document in; the root of My Drive (or of drive_id) when omitted.", nil},
				{"drive_id", "string", "Shared drive to create the document in (its root when parent_id is omitted).", nil},
			}, []string{"title"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: driveIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDriveMarker},
			ResultIDs:        documentResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppDocs, Name: ToolAppendText, Kind: connectors.KindWrite,
			Description: "Append plain text to the end of a Google Doc as a new paragraph (line breaks start further paragraphs). " +
				"Returns the document id and the number of characters appended. Cannot be verified after an unknown outcome: check the document.",
			InputSchema: objectSchema([]property{
				documentIDProperty,
				{"text", "string", "Text to append.", nil},
			}, []string{"document_id", "text"}),
			RequiredScopes:   []string{ScopeDocuments},
			ResourceIdentity: documentIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        appendedTextResultIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) docsWriteHandlers() map[string]handler {
	return map[string]handler{ToolCreateDocument: c.createDocument, ToolAppendText: c.appendText}
}

// documentIdentity extracts document_id from the arguments; never the
// text.
func documentIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if id, _ := args["document_id"].(string); strings.TrimSpace(id) != "" {
		out["document_id"] = strings.TrimSpace(id)
	}
	return out
}

func documentResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedDocument)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "url": v.URL}
}

func appendedTextResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(AppendedText)
	if !ok || v.DocumentID == "" {
		return nil
	}
	return map[string]string{"document_id": v.DocumentID}
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) getText(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	documentID, err := idArg(call.Args, "document_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.docs(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	doc, err := svc.Documents.Get(documentID).Context(ctx).Fields("documentId,title,revisionId,body").Do()
	if err := classify("get document", err); err != nil {
		return connectors.Result{}, err
	}
	id := doc.DocumentId
	if id == "" {
		id = documentID
	}
	text := DocumentText(doc)
	out := DocumentContent{ID: id, Title: doc.Title, RevisionID: doc.RevisionId, URL: docURL(id), Characters: utf8.RuneCountInString(text), Text: text}
	fitBody(&out.Text, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated, Empty: strings.TrimSpace(text) == ""}, nil
}

// textArg reads a text argument bounded by MaxAppendTextChars; required
// means it must not be blank.
func textArg(args map[string]any, name string, required bool) (string, error) {
	text, err := optionalString(args, name)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(text) == "" {
		if required {
			return "", invalid("%s is required", name)
		}
		return "", nil
	}
	if utf8.RuneCountInString(text) > MaxAppendTextChars {
		return "", invalid("%s is longer than %d characters", name, MaxAppendTextChars)
	}
	return text, nil
}

// insertAtEnd is the batchUpdate that appends text to the body.
func insertAtEnd(text string) *docs.BatchUpdateDocumentRequest {
	return &docs.BatchUpdateDocumentRequest{Requests: []*docs.Request{{
		InsertText: &docs.InsertTextRequest{Text: text, EndOfSegmentLocation: &docs.EndOfSegmentLocation{}},
	}}}
}

// createDocument creates the document through Drive (files.create with
// the Docs MIME type and the operation's marker, in one request, like
// create_folder) and then inserts body_text with the Docs API. Once the
// file exists the write succeeded whatever the insert does: a known
// refusal is reported as BodyFailed, an open outcome as BodyUnknown.
func (c *Connector) createDocument(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	body, err := textArg(call.Args, "body_text", false)
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := newDriveFile(call, title, MimeDocument)
	if err != nil {
		return connectors.Result{}, err
	}
	driveSvc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := driveSvc.Files.Create(f).Context(ctx).SupportsAllDrives(true).Fields(createdFileFields).Do()
	if err := classifyWrite("create document", err); err != nil {
		return connectors.Result{}, err
	}
	out := CreatedDocument{ID: created.Id, URL: created.WebViewLink, DriveID: created.DriveId}
	if len(created.Parents) > 0 {
		out.ParentID = created.Parents[0]
	}
	if body == "" {
		return connectors.Result{Content: out}, nil
	}
	out.BodyStatus = BodyApplied
	docsSvc, err := cl.docs(ctx)
	if err != nil {
		out.BodyStatus, out.BodyError = BodyFailed, err.Error()
		return connectors.Result{Content: out}, nil
	}
	_, err = docsSvc.Documents.BatchUpdate(out.ID, insertAtEnd(body)).Context(ctx).Do()
	if err := classifyWrite("insert the document's text", err); err != nil {
		out.BodyStatus, out.BodyError = BodyFailed, err.Error()
		if errors.Is(err, connectors.ErrOutcomeUnknown) {
			out.BodyStatus = BodyUnknown
		}
	}
	return connectors.Result{Content: out}, nil
}

// appendText inserts "\n" + text at the end of the body: the text starts
// a new paragraph after the document's last one.
func (c *Connector) appendText(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	documentID, err := idArg(call.Args, "document_id")
	if err != nil {
		return connectors.Result{}, err
	}
	text, err := textArg(call.Args, "text", true)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.docs(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	_, err = svc.Documents.BatchUpdate(documentID, insertAtEnd("\n"+text)).Context(ctx).Do()
	if err := classifyWrite("append text", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: AppendedText{DocumentID: documentID, Characters: utf8.RuneCountInString(text)}}, nil
}
