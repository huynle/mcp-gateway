package google

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/api/slides/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Slides tool names (increment 5).
const (
	ToolSlidesStructure = "get_structure"
	ToolGetThumbnail    = "get_thumbnail"
	ToolAddSlide        = "add_slide"
	ToolDeleteSlide     = "delete_slide"
	ToolReorderSlides   = "reorder_slides"
	ToolSlidesInsert    = "insert_text"
	ToolSlidesImage     = "insert_image"
)

// predefinedLayouts are the layouts add_slide accepts (Slides'
// PredefinedLayout values).
var predefinedLayouts = []string{"BLANK", "CAPTION_ONLY", "TITLE", "TITLE_AND_BODY", "TITLE_AND_TWO_COLUMNS", "TITLE_ONLY",
	"SECTION_HEADER", "SECTION_TITLE_AND_DESCRIPTION", "ONE_COLUMN_TEXT", "MAIN_POINT", "BIG_NUMBER"}

// thumbnailSizes are get_thumbnail's sizes.
var thumbnailSizes = []string{"SMALL", "MEDIUM", "LARGE"}

// SlideObjectID returns the object id add_slide and insert_image give
// what they create: "mcpgw_" + EventID(operation id) (38 characters of
// [a-z0-9_], within Slides' 5-50 character object id rules). A retry of
// the same operation is refused (the id exists) rather than creating a
// second object, and the check finds the object by it.
func SlideObjectID(operationID string) string { return "mcpgw_" + EventID(operationID) }

// SlideElement is one page element of get_structure.
type SlideElement struct {
	ObjectID      string `json:"object_id"`
	Type          string `json:"type"`
	ShapeType     string `json:"shape_type,omitempty"`
	Placeholder   string `json:"placeholder,omitempty"`
	Text          string `json:"text,omitempty"`
	TextTruncated bool   `json:"text_truncated,omitempty"`
	Rows          int64  `json:"rows,omitempty"`
	Columns       int64  `json:"columns,omitempty"`
	Children      int    `json:"children,omitempty"`
}

// SlideStructure is one slide of get_structure.
type SlideStructure struct {
	ObjectID string         `json:"object_id"`
	Index    int            `json:"index"`
	LayoutID string         `json:"layout_id,omitempty"`
	Elements []SlideElement `json:"elements"`
}

// SlideLayout is one layout of the deck's master.
type SlideLayout struct {
	ObjectID    string `json:"object_id"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// PresentationStructure is get_structure's result.
type PresentationStructure struct {
	PresentationID string           `json:"presentation_id"`
	Title          string           `json:"title"`
	RevisionID     string           `json:"revision_id,omitempty"`
	Slides         []SlideStructure `json:"slides"`
	Layouts        []SlideLayout    `json:"layouts,omitempty"`
	Truncated      bool             `json:"truncated,omitempty"`
}

// SlideThumbnail is get_thumbnail's result: a PNG URL valid for about 30
// minutes (anyone with it sees the image).
type SlideThumbnail struct {
	PresentationID string `json:"presentation_id"`
	SlideID        string `json:"slide_id"`
	URL            string `json:"url"`
	Width          int64  `json:"width"`
	Height         int64  `json:"height"`
}

var slideIDProperty = property{"slide_id", "string", "The slide's object id (from get_structure).", nil}

func (c *Connector) slidesFullReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppSlides, Name: ToolSlidesStructure, Kind: connectors.KindRead,
			Description: "Get a Google Slides presentation's structure: per slide its object_id, index, layout and page elements (object_id, " +
				"type: shape, image, table, line, video, chart, group, word_art; shape_type, placeholder, a text preview, table size), the " +
				"layouts add_slide can use, and revision_id. Trailing elements and slides are dropped to the result bounds (truncated).",
			InputSchema:      objectSchema([]property{presentationIDProperty}, []string{"presentation_id"}),
			RequiredScopes:   []string{ScopePresentationsReadonly},
			ResourceIdentity: presentationIdentity,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppSlides, Name: ToolGetThumbnail, Kind: connectors.KindRead,
			Description: "Get a PNG thumbnail of one slide: a URL valid for about 30 minutes (anyone with the URL can see the image), width " +
				"and height; size SMALL (200 px wide), MEDIUM (800, default) or LARGE (1600).",
			InputSchema: objectSchema([]property{
				presentationIDProperty, slideIDProperty,
				{"size", "string", "SMALL, MEDIUM (default) or LARGE.", thumbnailSizes},
			}, []string{"presentation_id", "slide_id"}),
			RequiredScopes:   []string{ScopePresentationsReadonly},
			ResourceIdentity: func(args map[string]any) map[string]string { return identityOf(args, "presentation_id", "slide_id") },
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) slidesFullReadHandlers() map[string]handler {
	return map[string]handler{ToolSlidesStructure: c.getSlidesStructure, ToolGetThumbnail: c.getThumbnail}
}

func (c *Connector) slidesFullWriteTools() []connectors.Tool {
	withSlide := func(args map[string]any) map[string]string { return identityOf(args, "presentation_id", "slide_id") }
	addSlide := c.helperTool(slidesBatch, ToolAddSlide, "Add a slide to a Google Slides presentation: optional predefined layout and "+
		"index (position, 0 first; the end when omitted). Returns the new slide's object_id.",
		[]property{
			{"layout", "string", "Predefined layout of the new slide.", predefinedLayouts},
			{"index", "integer", "Position of the slide (0 is first).", nil},
		}, nil)
	addSlide.Reconcile = connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSlideObject(slideCreated)}
	deleteSlide := c.helperTool(slidesBatch, ToolDeleteSlide, "Delete a slide from a Google Slides presentation.",
		[]property{slideIDProperty}, []string{"slide_id"}, withSlide)
	deleteSlide.Reconcile = connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSlideObject(slideDeleted)}
	insertImage := c.helperTool(slidesBatch, ToolSlidesImage, "Insert an image from a public URL (PNG, JPEG or GIF, under 50 MB) onto a "+
		"slide, optionally sized (width_pt, height_pt) and placed (x_pt, y_pt from the top left) in points. Returns the image's object_id.",
		[]property{
			slideIDProperty,
			{"uri", "string", "Public http(s) URL of the image (Google fetches it once).", nil},
			{"width_pt", "number", "Width in points.", nil}, {"height_pt", "number", "Height in points.", nil},
			{"x_pt", "number", "Distance from the slide's left edge in points.", nil}, {"y_pt", "number", "Distance from the top in points.", nil},
		}, []string{"slide_id", "uri"}, withSlide)
	insertImage.Reconcile = connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSlideObject(elementCreated)}
	return []connectors.Tool{
		c.batchTool(slidesBatch),
		addSlide,
		deleteSlide,
		c.helperTool(slidesBatch, ToolReorderSlides, "Move slides (slide_ids, in their current order) so the first lands at index (0 first).",
			[]property{
				{"slide_ids", "array", "Object ids of the slides to move.", nil},
				{"index", "integer", "Where the slides go, counted before the move.", nil},
			}, []string{"slide_ids", "index"}),
		c.helperTool(slidesBatch, ToolSlidesInsert, "Insert text into a shape or text box of a Google Slides presentation (object_id from "+
			"get_structure) at a character index (the start when omitted).",
			[]property{
				{"object_id", "string", "The shape's object id.", nil},
				{"text", "string", "Text to insert.", nil},
				{"index", "integer", "Character index in the shape's text (0 is the start).", nil},
			}, []string{"object_id", "text"}, func(args map[string]any) map[string]string { return identityOf(args, "presentation_id", "object_id") }),
		insertImage,
	}
}

func (c *Connector) slidesFullWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolBatchUpdate:   c.batchHandler(slidesBatch),
		ToolAddSlide:      c.helperHandler(slidesBatch, buildAddSlide),
		ToolDeleteSlide:   c.helperHandler(slidesBatch, buildDeleteSlide),
		ToolReorderSlides: c.helperHandler(slidesBatch, buildReorderSlides),
		ToolSlidesInsert:  c.helperHandler(slidesBatch, buildSlidesInsertText),
		ToolSlidesImage:   c.helperHandler(slidesBatch, buildSlidesImage),
	}
}

// --- builders ---------------------------------------------------------------------

func buildAddSlide(call connectors.Call) (helperRequest, error) {
	id := SlideObjectID(call.OperationID)
	params := map[string]any{"objectId": id}
	layout, err := optionalString(call.Args, "layout")
	if err != nil {
		return helperRequest{}, err
	}
	if layout = strings.TrimSpace(layout); layout != "" {
		if !slices.Contains(predefinedLayouts, layout) {
			return helperRequest{}, invalid("layout must be one of %s", strings.Join(predefinedLayouts, ", "))
		}
		params["slideLayoutReference"] = map[string]any{"predefinedLayout": layout}
	}
	if index, ok, err := intArg(call.Args, "index", false, 0, 10000); err != nil {
		return helperRequest{}, err
	} else if ok {
		params["insertionIndex"] = index
	}
	return helperRequest{kind: "createSlide", params: params, objectID: id}, nil
}

func buildDeleteSlide(call connectors.Call) (helperRequest, error) {
	id, err := idArg(call.Args, "slide_id")
	if err != nil {
		return helperRequest{}, err
	}
	return helperRequest{kind: "deleteObject", params: map[string]any{"objectId": id}, objectID: id}, nil
}

func buildReorderSlides(call connectors.Call) (helperRequest, error) {
	ids, err := stringList(call.Args, "slide_ids")
	if err != nil {
		return helperRequest{}, err
	}
	if len(ids) == 0 {
		return helperRequest{}, invalid("slide_ids must name at least one slide")
	}
	for _, id := range ids {
		if !idRE.MatchString(id) {
			return helperRequest{}, invalid("slide_ids must be slide object ids")
		}
	}
	index, _, err := intArg(call.Args, "index", true, 0, 10000)
	if err != nil {
		return helperRequest{}, err
	}
	return helperRequest{kind: "updateSlidesPosition", params: map[string]any{"slideObjectIds": ids, "insertionIndex": index}}, nil
}

func buildSlidesInsertText(call connectors.Call) (helperRequest, error) {
	id, err := idArg(call.Args, "object_id")
	if err != nil {
		return helperRequest{}, err
	}
	text, err := textArg(call.Args, "text", true)
	if err != nil {
		return helperRequest{}, err
	}
	params := map[string]any{"objectId": id, "text": text}
	if index, ok, err := intArg(call.Args, "index", false, 0, 1<<30); err != nil {
		return helperRequest{}, err
	} else if ok {
		params["insertionIndex"] = index
	}
	return helperRequest{kind: "insertText", params: params, objectID: id}, nil
}

func buildSlidesImage(call connectors.Call) (helperRequest, error) {
	slideID, err := idArg(call.Args, "slide_id")
	if err != nil {
		return helperRequest{}, err
	}
	uri, err := imageURIArg(call.Args, "uri")
	if err != nil {
		return helperRequest{}, err
	}
	props := map[string]any{"pageObjectId": slideID}
	size := map[string]any{}
	for arg, field := range map[string]string{"width_pt": "width", "height_pt": "height"} {
		v, ok, err := numberArg(call.Args, arg)
		if err != nil {
			return helperRequest{}, err
		}
		if ok {
			size[field] = map[string]any{"magnitude": v, "unit": "PT"}
		}
	}
	if len(size) > 0 {
		props["size"] = size
	}
	x, hasX, err := numberArg(call.Args, "x_pt")
	if err != nil {
		return helperRequest{}, err
	}
	y, hasY, err := numberArg(call.Args, "y_pt")
	if err != nil {
		return helperRequest{}, err
	}
	if hasX || hasY {
		props["transform"] = map[string]any{"scaleX": 1, "scaleY": 1, "translateX": x, "translateY": y, "unit": "PT"}
	}
	id := SlideObjectID(call.OperationID)
	return helperRequest{kind: "createImage", params: map[string]any{"objectId": id, "url": uri, "elementProperties": props}, objectID: id}, nil
}

// --- reads ------------------------------------------------------------------------

func toSlideElement(el *slides.PageElement) SlideElement {
	out := SlideElement{ObjectID: el.ObjectId}
	switch {
	case el.Shape != nil:
		out.Type, out.ShapeType = "shape", el.Shape.ShapeType
		if el.Shape.Placeholder != nil {
			out.Placeholder = el.Shape.Placeholder.Type
		}
		out.Text, out.TextTruncated = preview(textContent(el.Shape.Text))
	case el.Image != nil:
		out.Type = "image"
	case el.Table != nil:
		out.Type, out.Rows, out.Columns = "table", el.Table.Rows, el.Table.Columns
	case el.Line != nil:
		out.Type = "line"
	case el.Video != nil:
		out.Type = "video"
	case el.SheetsChart != nil:
		out.Type = "chart"
	case el.ElementGroup != nil:
		out.Type, out.Children = "group", len(el.ElementGroup.Children)
	case el.WordArt != nil:
		out.Type = "word_art"
	default:
		out.Type = "other"
	}
	return out
}

func (c *Connector) getSlidesStructure(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "presentation_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.slides(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	p, err := svc.Presentations.Get(id).Context(ctx).
		Fields("presentationId,title,revisionId,slides(objectId,slideProperties/layoutObjectId,pageElements),layouts(objectId,layoutProperties(name,displayName))").Do()
	if err := classify("get presentation", err); err != nil {
		return connectors.Result{}, err
	}
	out := PresentationStructure{PresentationID: id, Title: p.Title, RevisionID: p.RevisionId, Slides: []SlideStructure{}}
	for i, s := range p.Slides {
		if s == nil {
			continue
		}
		ss := SlideStructure{ObjectID: s.ObjectId, Index: i, Elements: []SlideElement{}}
		if s.SlideProperties != nil {
			ss.LayoutID = s.SlideProperties.LayoutObjectId
		}
		for _, el := range s.PageElements {
			if el != nil {
				ss.Elements = append(ss.Elements, toSlideElement(el))
			}
		}
		out.Slides = append(out.Slides, ss)
	}
	for _, l := range p.Layouts {
		if l == nil {
			continue
		}
		sl := SlideLayout{ObjectID: l.ObjectId}
		if l.LayoutProperties != nil {
			sl.Name, sl.DisplayName = l.LayoutProperties.Name, l.LayoutProperties.DisplayName
		}
		out.Layouts = append(out.Layouts, sl)
	}
	fitSlideStructure(&out, c.bounds.MaxResultBytes)
	return connectors.Result{Content: out, Empty: len(out.Slides) == 0, Partial: out.Truncated}, nil
}

// fitSlideStructure drops the layouts, then trailing elements of the
// last slide that has some, then trailing slides (never the first),
// until out fits max.
func fitSlideStructure(out *PresentationStructure, max int) {
	for encodedSize(out) > max {
		last := len(out.Slides) - 1
		switch {
		case len(out.Layouts) > 0:
			out.Layouts = nil
		case last >= 0 && len(out.Slides[last].Elements) > 0:
			out.Slides[last].Elements = out.Slides[last].Elements[:len(out.Slides[last].Elements)-1]
		case last > 0:
			out.Slides = out.Slides[:last]
		default:
			return
		}
		out.Truncated = true
	}
}

func (c *Connector) getThumbnail(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "presentation_id")
	if err != nil {
		return connectors.Result{}, err
	}
	slideID, err := idArg(call.Args, "slide_id")
	if err != nil {
		return connectors.Result{}, err
	}
	size, err := optionalString(call.Args, "size")
	if err != nil {
		return connectors.Result{}, err
	}
	if size = strings.TrimSpace(size); size == "" {
		size = "MEDIUM"
	}
	if !slices.Contains(thumbnailSizes, size) {
		return connectors.Result{}, invalid("size must be SMALL, MEDIUM or LARGE")
	}
	svc, err := cl.slides(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	th, err := svc.Presentations.Pages.GetThumbnail(id, slideID).ThumbnailPropertiesThumbnailSize(size).ThumbnailPropertiesMimeType("PNG").Context(ctx).Do()
	if err := classify("get thumbnail", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: SlideThumbnail{PresentationID: id, SlideID: slideID, URL: th.ContentUrl, Width: th.Width, Height: th.Height}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// Slide object checks: a slide add_slide created, an element
// insert_image created (both by SlideObjectID), a slide delete_slide
// removed (the identity's slide_id).
const (
	slideCreated = iota
	elementCreated
	slideDeleted
)

// checkSlideObject reads the deck's slide and element ids: the object
// present (absent for a deleted slide) is found, else not_found; any
// error is "cannot tell yet".
func (c *Connector) checkSlideObject(mode int) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		tg, err := c.target(in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ids, err := identityIDs(in, "presentation_id")
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		want := SlideObjectID(tg.operationID)
		if mode == slideDeleted {
			if want = in.ResourceIdentity["slide_id"]; want == "" {
				return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no slide", ErrNotReconcilable)
			}
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		svc, err := tg.client.slides(ctx)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		p, err := svc.Presentations.Get(ids[0]).Context(ctx).Fields("presentationId,slides(objectId,pageElements(objectId))").Do()
		if err := classify("reconcile: get presentation", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		present := false
		for _, s := range p.Slides {
			if s == nil {
				continue
			}
			if mode != elementCreated && s.ObjectId == want {
				present = true
			}
			for _, el := range s.PageElements {
				if mode == elementCreated && el != nil && el.ObjectId == want {
					present = true
				}
			}
		}
		if present == (mode != slideDeleted) {
			return found(want), nil
		}
		return notFound, nil
	}
}
