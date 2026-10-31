package google_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: slides.get_structure, get_thumbnail and the edit helpers
// (add_slide, delete_slide, reorder_slides, insert_text, insert_image).

const (
	thumbnailPath = "GET /v1/presentations/" + presID + "/pages/s2/thumbnail"
	slidesReply   = `{"presentationId":"` + presID + `","replies":[{}],"writeControl":{"requiredRevisionId":"rev-3"}}`
	structureDeck = `{"presentationId":"` + presID + `","title":"Deck","revisionId":"rev-1","slides":[` +
		`{"objectId":"s1","slideProperties":{"layoutObjectId":"l1"},"pageElements":[` +
		`{"objectId":"t1","shape":{"shapeType":"TEXT_BOX","placeholder":{"type":"TITLE"},"text":{"textElements":[{"textRun":{"content":"Hello\n"}}]}}},` +
		`{"objectId":"i1","image":{"contentUrl":"https://lh3.example.test/secret"}},` +
		`{"objectId":"tb1","table":{"rows":2,"columns":3}},` +
		`{"objectId":"g1","elementGroup":{"children":[{"objectId":"c1","shape":{"shapeType":"RECTANGLE"}}]}}]},` +
		`{"objectId":"s2","pageElements":[]}],` +
		`"layouts":[{"objectId":"l1","layoutProperties":{"name":"TITLE","displayName":"Title slide"}}]}`
)

func TestSlideObjectID(t *testing.T) {
	id := google.SlideObjectID(opID)
	if !regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_:-]{4,49}$`).MatchString(id) || id == google.SlideObjectID("other") || strings.Contains(id, opID) {
		t.Errorf("SlideObjectID = %q", id)
	}
}

func TestSlidesFullDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "slides.get_structure", r, []string{google.ScopePresentationsReadonly}, "")
	declared(t, c, "slides.get_thumbnail", r, []string{google.ScopePresentationsReadonly}, "")
	declared(t, c, "slides.add_slide", w, []string{google.ScopePresentations}, connectors.ReconcileStableID)
	declared(t, c, "slides.delete_slide", w, []string{google.ScopePresentations}, connectors.ReconcileStableID)
	declared(t, c, "slides.reorder_slides", w, []string{google.ScopePresentations}, connectors.ReconcileNone)
	declared(t, c, "slides.insert_text", w, []string{google.ScopePresentations}, connectors.ReconcileNone)
	declared(t, c, "slides.insert_image", w, []string{google.ScopePresentations}, connectors.ReconcileStableID)
	args := map[string]any{"presentation_id": presID, "slide_id": "s2", "object_id": "t1", "text": "secret", "uri": "https://secret.test/a.png", "slide_ids": []any{"s1"}}
	for name, want := range map[string]map[string]string{
		"slides.get_structure":  {"presentation_id": presID},
		"slides.get_thumbnail":  {"presentation_id": presID, "slide_id": "s2"},
		"slides.add_slide":      {"presentation_id": presID},
		"slides.delete_slide":   {"presentation_id": presID, "slide_id": "s2"},
		"slides.reorder_slides": {"presentation_id": presID},
		"slides.insert_text":    {"presentation_id": presID, "object_id": "t1"},
		"slides.insert_image":   {"presentation_id": presID, "slide_id": "s2"},
	} {
		id := toolOf(t, c, name).ResourceIdentity(args)
		if len(id) != len(want) {
			t.Errorf("%s identity = %v, want %v", name, id, want)
		}
		for k, v := range want {
			if id[k] != v {
				t.Errorf("%s identity = %v, want %v", name, id, want)
			}
		}
	}
}

func TestSlidesGetStructure(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getPresPath: {status: 200, body: structureDeck}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("slides.get_structure", map[string]any{"presentation_id": presID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		PresentationID string `json:"presentation_id"`
		RevisionID     string `json:"revision_id"`
		Slides         []struct {
			ObjectID string `json:"object_id"`
			Index    int    `json:"index"`
			LayoutID string `json:"layout_id"`
			Elements []struct {
				ObjectID    string `json:"object_id"`
				Type        string `json:"type"`
				ShapeType   string `json:"shape_type"`
				Placeholder string `json:"placeholder"`
				Text        string `json:"text"`
				Rows        int64  `json:"rows"`
				Columns     int64  `json:"columns"`
				Children    int    `json:"children"`
			} `json:"elements"`
		} `json:"slides"`
		Layouts []struct {
			ObjectID string `json:"object_id"`
			Name     string `json:"name"`
		} `json:"layouts"`
		Truncated bool `json:"truncated"`
	}
	decode(t, res, &out)
	if out.PresentationID != presID || out.RevisionID != "rev-1" || len(out.Slides) != 2 || out.Slides[1].Index != 1 || out.Slides[0].LayoutID != "l1" ||
		len(out.Layouts) != 1 || out.Layouts[0].Name != "TITLE" {
		t.Fatalf("out = %+v", out)
	}
	els := out.Slides[0].Elements
	if len(els) != 4 || els[0].Type != "shape" || els[0].Placeholder != "TITLE" || els[0].Text != "Hello" || els[1].Type != "image" ||
		els[2].Type != "table" || els[2].Columns != 3 || els[3].Type != "group" || els[3].Children != 1 {
		t.Errorf("elements = %+v", els)
	}
	raw := encodedSizeOf(t, res)
	if strings.Contains(srv.Last(t, getPresPath).URL.Query().Get("fields"), "notesPage") || raw == 0 {
		t.Error("structure needs no notes")
	}
	c, _ = newConnector(t, srv, connectors.Bounds{MaxResultBytes: 300})
	res, err = run(t, c, call("slides.get_structure", map[string]any{"presentation_id": presID}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, res, &out)
	if !out.Truncated || !res.Partial || encodedSizeOf(t, res) > 300 {
		t.Errorf("bounded: %+v size %d", out, encodedSizeOf(t, res))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getPresPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("slides.get_structure", map[string]any{"presentation_id": presID}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestSlidesGetThumbnail(t *testing.T) {
	srv := newAPIServer(t, map[string]route{thumbnailPath: {status: 200, body: `{"width":800,"height":450,"contentUrl":"https://lh3.example.test/thumb"}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("slides.get_thumbnail", map[string]any{"presentation_id": presID, "slide_id": "s2", "size": "LARGE"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		URL    string `json:"url"`
		Width  int64  `json:"width"`
		Height int64  `json:"height"`
	}
	decode(t, res, &out)
	if out.URL != "https://lh3.example.test/thumb" || out.Width != 800 {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/v1/presentations/"+presID+"/pages/s2/thumbnail"); q.Get("thumbnailProperties.thumbnailSize") != "LARGE" {
		t.Errorf("query = %v", q)
	}
	for _, args := range []map[string]any{{"presentation_id": presID}, {"presentation_id": presID, "slide_id": "s2", "size": "HUGE"}} {
		_, err := run(t, c, call("slides.get_thumbnail", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{thumbnailPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("slides.get_thumbnail", map[string]any{"presentation_id": presID, "slide_id": "s2"}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestSlidesEditHelpers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{presBatchPath: {status: 200, body: slidesReply}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	derived := google.SlideObjectID(opID)
	for _, tc := range []struct {
		tool     string
		args     map[string]any
		want     []string
		objectID string
	}{
		{"slides.add_slide", map[string]any{"layout": "TITLE_AND_BODY", "index": 2},
			[]string{`"createSlide"`, `"objectId":"` + derived + `"`, `"insertionIndex":2`, `"predefinedLayout":"TITLE_AND_BODY"`}, derived},
		{"slides.add_slide", map[string]any{}, []string{`"createSlide":{"objectId":"` + derived + `"}`}, derived},
		{"slides.delete_slide", map[string]any{"slide_id": "s2"}, []string{`"deleteObject":{"objectId":"s2"}`}, "s2"},
		{"slides.reorder_slides", map[string]any{"slide_ids": []any{"s2", "s1"}, "index": 0}, []string{`"updateSlidesPosition"`, `"slideObjectIds":["s2","s1"]`, `"insertionIndex":0`}, ""},
		{"slides.insert_text", map[string]any{"object_id": "t1", "text": "Hi", "index": 3}, []string{`"insertText"`, `"objectId":"t1"`, `"text":"Hi"`, `"insertionIndex":3`}, "t1"},
		{"slides.insert_image", map[string]any{"slide_id": "s2", "uri": "https://example.test/a.png", "width_pt": 200, "height_pt": 100, "x_pt": 10, "y_pt": 20},
			[]string{`"createImage"`, `"objectId":"` + derived + `"`, `"url":"https://example.test/a.png"`, `"pageObjectId":"s2"`, `"width":{"magnitude":200,"unit":"PT"}`, `"translateX":10`, `"translateY":20`, `"scaleX":1`}, derived},
		{"slides.insert_image", map[string]any{"slide_id": "s2", "uri": "https://example.test/a.png", "required_revision_id": "rev-1"},
			[]string{`"elementProperties":{"pageObjectId":"s2"}`, `"writeControl":{"requiredRevisionId":"rev-1"}`}, derived},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			tc.args["presentation_id"] = presID
			res, err := run(t, c, write(tc.tool, tc.args))
			if err != nil {
				t.Fatal(err)
			}
			body := srv.Last(t, presBatchPath).Body
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("body %s lacks %s", body, w)
				}
			}
			ids := toolOf(t, c, tc.tool).ResultIDs(res)
			if ids["presentation_id"] != presID || ids["object_id"] != tc.objectID {
				t.Errorf("ResultIDs = %v, want object_id %q", ids, tc.objectID)
			}
		})
	}
	calls := len(tk.calls)
	for tool, args := range map[string][]map[string]any{
		"slides.add_slide":      {{"layout": "FANCY"}, {"index": -1}},
		"slides.delete_slide":   {{}, {"slide_id": "a b"}},
		"slides.reorder_slides": {{"index": 0}, {"slide_ids": []any{"s1"}}, {"slide_ids": []any{}, "index": 0}},
		"slides.insert_text":    {{"object_id": "t1"}, {"text": "x"}},
		"slides.insert_image":   {{"uri": "https://x.test/a.png"}, {"slide_id": "s2"}, {"slide_id": "s2", "uri": "file:///etc/passwd"}},
	} {
		for _, a := range args {
			a["presentation_id"] = presID
			_, err := run(t, c, write(tool, a))
			if err == nil {
				t.Errorf("%s %v: no error", tool, a)
				continue
			}
			wantClass(t, err, google.ClassInvalidArgument, 0)
		}
	}
	if len(tk.calls) != calls {
		t.Error("invalid arguments must not fetch the token")
	}
	for _, tc := range writeErrorCases(slidesReply) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{presBatchPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("slides.add_slide", map[string]any{"presentation_id": presID}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestSlidesObjectChecks(t *testing.T) {
	derived := google.SlideObjectID(opID)
	deck := func(slides string) string { return `{"presentationId":"` + presID + `","slides":[` + slides + `]}` }
	for _, tc := range []struct {
		tool string
		rt   route
		want string
		id   string
	}{
		{"slides.add_slide", route{status: 200, body: deck(`{"objectId":"s1"},{"objectId":"` + derived + `"}`)}, "found", derived},
		{"slides.add_slide", route{status: 200, body: deck(`{"objectId":"s1"}`)}, "not_found", ""},
		{"slides.insert_image", route{status: 200, body: deck(`{"objectId":"s2","pageElements":[{"objectId":"` + derived + `"}]}`)}, "found", derived},
		{"slides.insert_image", route{status: 200, body: deck(`{"objectId":"s2","pageElements":[{"objectId":"x"}]}`)}, "not_found", ""},
		{"slides.delete_slide", route{status: 200, body: deck(`{"objectId":"s1"}`)}, "found", "s2"},
		{"slides.delete_slide", route{status: 200, body: deck(`{"objectId":"s2"}`)}, "not_found", ""},
		{"slides.add_slide", route{status: 500, body: "error_server.json"}, "cannot_tell", ""},
		{"slides.delete_slide", route{status: 404, body: "error_not_found.json"}, "cannot_tell", ""},
	} {
		t.Run(tc.tool+" "+tc.want, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getPresPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, tc.tool, map[string]any{"presentation_id": presID, "slide_id": "s2"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, tc.id)
		})
	}
}
