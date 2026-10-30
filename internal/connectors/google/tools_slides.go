package google

import (
	"context"
	"strings"
	"unicode/utf8"

	"google.golang.org/api/slides/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Slides tool names (increment 4).
const (
	ToolSlidesGetText      = "get_text"
	ToolCreatePresentation = "create"
	ToolSlidesReplaceText  = "replace_text"
)

// MimePresentation is the Google Slides MIME type slides.create creates.
const MimePresentation = "application/vnd.google-apps.presentation"

// presentationFields are the fields get_text asks for: the slides'
// elements and speaker notes, nothing about layouts or masters.
const presentationFields = "presentationId,title,slides(objectId,pageElements,slideProperties/notesPage)"

// SlideText is one slide of get_text's result.
type SlideText struct {
	ObjectID string `json:"object_id"`
	Index    int    `json:"index"`
	Text     string `json:"text"`
	Notes    string `json:"notes,omitempty"`
	// Truncated says this slide's text or notes were cut to the bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// PresentationText is slides.get_text's result.
type PresentationText struct {
	PresentationID string      `json:"presentation_id"`
	Title          string      `json:"title"`
	URL            string      `json:"url"`
	Slides         []SlideText `json:"slides"`
	Truncated      bool        `json:"truncated,omitempty"`
}

// ReplacedSlidesText is slides.replace_text's result.
type ReplacedSlidesText struct {
	PresentationID     string `json:"presentation_id"`
	OccurrencesChanged int64  `json:"occurrences_changed"`
}

// presentationURL is the editor URL of a presentation.
func presentationURL(id string) string {
	return "https://docs.google.com/presentation/d/" + id + "/edit"
}

var presentationIDProperty = property{"presentation_id", "string", "The presentation's id (from drive.search, or the id in its URL).", nil}

func (c *Connector) slidesReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppSlides, Name: ToolSlidesGetText, Kind: connectors.KindRead,
		Description: "Get a Google Slides presentation's text by id: per slide its object_id, index, text (text boxes and shapes one per line, " +
			"tables one row per line with tab-separated cells) and speaker notes. Text is cut from the end of the deck to the result bounds " +
			"(truncated says so). Images and charts are left out.",
		InputSchema:      objectSchema([]property{presentationIDProperty}, []string{"presentation_id"}),
		RequiredScopes:   []string{ScopePresentationsReadonly},
		ResourceIdentity: presentationIdentity,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) slidesReadHandlers() map[string]handler {
	return map[string]handler{ToolSlidesGetText: c.getSlidesText}
}

func (c *Connector) slidesWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppSlides, Name: ToolCreatePresentation, Kind: connectors.KindWrite,
			Description: "Create an empty Google Slides presentation with a title, in the root of My Drive, under parent_id, or in the shared " +
				"drive drive_id. Returns the new presentation's id and url.",
			InputSchema: objectSchema([]property{
				{"title", "string", "Presentation title.", nil},
				{"parent_id", "string", "Id of the folder to create it in; the root of My Drive (or of drive_id) when omitted.", nil},
				{"drive_id", "string", "Shared drive to create it in (its root when parent_id is omitted).", nil},
			}, []string{"title"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: driveIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDriveMarker},
			ResultIDs:        createdFileResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppSlides, Name: ToolSlidesReplaceText, Kind: connectors.KindWrite,
			Description: "Replace every occurrence of find with replace on every slide of a Google Slides presentation (match_case default true; " +
				"an empty replace deletes the matches). Returns how many occurrences changed. Cannot be verified after an unknown outcome: check the presentation.",
			InputSchema: objectSchema([]property{
				presentationIDProperty,
				{"find", "string", "Text to find.", nil},
				{"replace", "string", "Replacement text (may be empty).", nil},
				{"match_case", "boolean", "Case-sensitive match. Default true.", nil},
			}, []string{"presentation_id", "find", "replace"}),
			RequiredScopes:   []string{ScopePresentations},
			ResourceIdentity: presentationIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(ReplacedSlidesText); ok && v.PresentationID != "" {
					return map[string]string{"presentation_id": v.PresentationID}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
	}
}

func (c *Connector) slidesWriteHandlers() map[string]handler {
	return map[string]handler{ToolCreatePresentation: c.createPresentation, ToolSlidesReplaceText: c.replaceSlidesText}
}

// presentationIdentity extracts presentation_id; never the text.
func presentationIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if id, _ := args["presentation_id"].(string); strings.TrimSpace(id) != "" {
		out["presentation_id"] = strings.TrimSpace(id)
	}
	return out
}

// --- text rendering ------------------------------------------------------------

// textContent renders a shape's or a cell's text: its runs and auto text
// (slide numbers) without the trailing newline.
func textContent(tc *slides.TextContent) string {
	if tc == nil {
		return ""
	}
	var b strings.Builder
	for _, el := range tc.TextElements {
		switch {
		case el == nil:
		case el.TextRun != nil:
			b.WriteString(el.TextRun.Content)
		case el.AutoText != nil:
			b.WriteString(el.AutoText.Content)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// elementsText renders page elements one per line: shapes as their text,
// tables one row per line with tab-separated cells, groups element by
// element. Images, videos, lines and charts have no text.
func elementsText(elements []*slides.PageElement) string {
	var parts []string
	for _, el := range elements {
		if el == nil {
			continue
		}
		var s string
		switch {
		case el.Shape != nil:
			s = textContent(el.Shape.Text)
		case el.Table != nil:
			var rows []string
			for _, row := range el.Table.TableRows {
				if row == nil {
					continue
				}
				cells := make([]string, 0, len(row.TableCells))
				for _, cell := range row.TableCells {
					if cell != nil {
						cells = append(cells, strings.ReplaceAll(textContent(cell.Text), "\n", " "))
					}
				}
				rows = append(rows, strings.Join(cells, "\t"))
			}
			s = strings.Join(rows, "\n")
		case el.ElementGroup != nil:
			s = elementsText(el.ElementGroup.Children)
		}
		if strings.TrimSpace(s) != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n")
}

// speakerNotes renders a slide's speaker notes: the notes page's shape
// named by notesProperties.speakerNotesObjectId.
func speakerNotes(slide *slides.Page) string {
	if slide.SlideProperties == nil || slide.SlideProperties.NotesPage == nil {
		return ""
	}
	notes := slide.SlideProperties.NotesPage
	if notes.NotesProperties == nil || notes.NotesProperties.SpeakerNotesObjectId == "" {
		return ""
	}
	for _, el := range notes.PageElements {
		if el != nil && el.ObjectId == notes.NotesProperties.SpeakerNotesObjectId && el.Shape != nil {
			return textContent(el.Shape.Text)
		}
	}
	return ""
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) getSlidesText(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "presentation_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.slides(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	p, err := svc.Presentations.Get(id).Context(ctx).Fields(presentationFields).Do()
	if err := classify("get presentation", err); err != nil {
		return connectors.Result{}, err
	}
	out := PresentationText{PresentationID: id, Title: p.Title, URL: presentationURL(id), Slides: []SlideText{}}
	empty := true
	for i, s := range p.Slides {
		if s == nil {
			continue
		}
		st := SlideText{ObjectID: s.ObjectId, Index: i, Text: elementsText(s.PageElements), Notes: speakerNotes(s)}
		if st.Text != "" || st.Notes != "" {
			empty = false
		}
		out.Slides = append(out.Slides, st)
	}
	c.fitSlides(&out)
	return connectors.Result{Content: out, Empty: empty, Partial: out.Truncated}, nil
}

// fitSlides cuts the deck's text from its end (the last slide's notes,
// then its text, then the slide before) until the result fits the
// bounds; every slide keeps its id and index. Should the ids alone
// overflow, trailing slides are dropped (never below one).
func (c *Connector) fitSlides(out *PresentationText) {
	max := c.bounds.MaxResultBytes
	obj := func() any { return *out }
	if encodedSize(out) > max {
		out.Truncated = true // counted while cutting
	}
	for i := len(out.Slides) - 1; i >= 0 && encodedSize(out) > max; i-- {
		s := &out.Slides[i]
		for _, body := range []*string{&s.Notes, &s.Text} {
			if *body != "" {
				fitBody(body, &s.Truncated, max, obj)
			}
		}
	}
	for encodedSize(out) > max && len(out.Slides) > 1 {
		out.Slides = out.Slides[:len(out.Slides)-1]
		out.Truncated = true
	}
}

// createPresentation creates the presentation through Drive (files.create
// with the Slides MIME type and the operation's marker, one request),
// like docs.create and sheets.create.
func (c *Connector) createPresentation(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := newDriveFile(call, title, MimePresentation)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Files.Create(f).Context(ctx).SupportsAllDrives(true).Fields(createdFileFields).Do()
	if err := classifyWrite("create presentation", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedFile{ID: created.Id, Name: title, MimeType: created.MimeType, URL: created.WebViewLink, Parents: created.Parents, DriveID: created.DriveId}}, nil
}

func (c *Connector) replaceSlidesText(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "presentation_id")
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
	svc, err := cl.slides(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := &slides.ReplaceAllTextRequest{ContainsText: &slides.SubstringMatchCriteria{Text: find, MatchCase: matchCase}, ReplaceText: replace}
	req.ForceSendFields = []string{"ReplaceText"}
	req.ContainsText.ForceSendFields = []string{"MatchCase"}
	resp, err := svc.Presentations.BatchUpdate(id, &slides.BatchUpdatePresentationRequest{Requests: []*slides.Request{{ReplaceAllText: req}}}).Context(ctx).Do()
	if err := classifyWrite("replace text", err); err != nil {
		return connectors.Result{}, err
	}
	out := ReplacedSlidesText{PresentationID: id}
	for _, r := range resp.Replies {
		if r != nil && r.ReplaceAllText != nil {
			out.OccurrencesChanged += r.ReplaceAllText.OccurrencesChanged
		}
	}
	return connectors.Result{Content: out}, nil
}
