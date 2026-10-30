package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 4: the slides app (Google Slides API, + Drive for create).

const (
	presID          = "1PresExample00000000000000000000000"
	getPresPath     = "GET /v1/presentations/" + presID
	presBatchPath   = "POST /v1/presentations/" + presID + ":batchUpdate"
	newPresentation = "1NewPres0000000000000000000000000000"
)

type slideText struct {
	ObjectID  string `json:"object_id"`
	Index     int    `json:"index"`
	Text      string `json:"text"`
	Notes     string `json:"notes"`
	Truncated bool   `json:"truncated"`
}

type presentationText struct {
	PresentationID string      `json:"presentation_id"`
	Title          string      `json:"title"`
	URL            string      `json:"url"`
	Slides         []slideText `json:"slides"`
	Truncated      bool        `json:"truncated"`
}

func TestSlidesDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	declared(t, c, "slides.get_text", connectors.KindRead, []string{google.ScopePresentationsReadonly}, "")
	declared(t, c, "slides.create", connectors.KindWrite, []string{google.ScopeDriveFile}, connectors.ReconcileMarker)
	declared(t, c, "slides.replace_text", connectors.KindWrite, []string{google.ScopePresentations}, connectors.ReconcileNone)
	for _, full := range []string{"slides.get_text", "slides.replace_text"} {
		id := toolOf(t, c, full).ResourceIdentity(map[string]any{"presentation_id": presID, "find": "secret", "replace": "secret"})
		if len(id) != 1 || id["presentation_id"] != presID {
			t.Errorf("%s identity = %v, want only presentation_id", full, id)
		}
	}
	id := toolOf(t, c, "slides.create").ResourceIdentity(map[string]any{"title": "secret", "parent_id": folderID})
	if len(id) != 2 || id["drive"] != "my" || id["folder_id"] != folderID {
		t.Errorf("create identity = %v", id)
	}
}

func TestSlidesGetText(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getPresPath: {status: 200, body: "presentation.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("slides.get_text", map[string]any{"presentation_id": presID}))
	if err != nil {
		t.Fatal(err)
	}
	var out presentationText
	decode(t, res, &out)
	if out.PresentationID != presID || out.Title != "Q4 review" || out.URL != "https://docs.google.com/presentation/d/"+presID+"/edit" || len(out.Slides) != 3 {
		t.Fatalf("out = %+v", out)
	}
	s1, s2, s3 := out.Slides[0], out.Slides[1], out.Slides[2]
	if s1.ObjectID != "p1" || s1.Index != 0 || s1.Text != "Q4 review\nSlide 1" || s1.Notes != "Welcome everyone." {
		t.Errorf("slide 1 = %+v", s1)
	}
	if s2.Index != 1 || s2.Text != "Region\tRevenue\nEMEA\t1.2M\nGrouped note" || s2.Notes != "" {
		t.Errorf("slide 2 = %+v", s2)
	}
	if s3.ObjectID != "p3" || s3.Index != 2 || s3.Text != "" {
		t.Errorf("slide 3 = %+v", s3)
	}
	if res.Empty || res.Partial || out.Truncated || len(tk.calls) != 1 {
		t.Errorf("res = %+v, truncated %v", res, out.Truncated)
	}
	if q := query(t, srv, "/v1/presentations/"+presID); !strings.Contains(q.Get("fields"), "slides(") {
		t.Errorf("fields = %q", q.Get("fields"))
	}

	// Bounds: the deck's text is cut from its end; every slide keeps its id.
	c2, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 330})
	res, err = run(t, c2, call("slides.get_text", map[string]any{"presentation_id": presID}))
	if err != nil {
		t.Fatal(err)
	}
	out = presentationText{}
	decode(t, res, &out)
	if !out.Truncated || !res.Partial || encodedSizeOf(t, res) > 330 || len(out.Slides) == 0 || out.Slides[0].ObjectID != "p1" {
		t.Errorf("bounded: out = %+v (%d bytes)", out, encodedSizeOf(t, res))
	}
	if len(out.Slides) > 1 && !out.Slides[1].Truncated {
		t.Errorf("bounded: slide 2 kept its text while the deck was cut: %+v", out.Slides)
	}

	srvEmpty := newAPIServer(t, map[string]route{getPresPath: {status: 200, body: "presentation_empty.json"}})
	cEmpty, _ := newConnector(t, srvEmpty, connectors.Bounds{})
	res, err = run(t, cEmpty, call("slides.get_text", map[string]any{"presentation_id": presID}))
	if err != nil || !res.Empty {
		t.Errorf("blank deck: res = %+v, %v; want empty", res, err)
	}

	cl, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{{}, {"presentation_id": "a/b"}} {
		_, err := run(t, cl, call("slides.get_text", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getPresPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("slides.get_text", map[string]any{"presentation_id": presID}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestSlidesCreate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{createFilePath: {status: 200, body: "created_presentation.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("slides.create", map[string]any{"title": "Q1 plan", "parent_id": folderID}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "slides.create").ResultIDs(res); ids["id"] != newPresentation || !strings.Contains(ids["url"], "/presentation/d/") {
		t.Errorf("ResultIDs = %v", ids)
	}
	req := srv.Last(t, createFilePath)
	body := bodyOf(t, req)
	props, _ := body["appProperties"].(map[string]any)
	if body["mimeType"] != google.MimePresentation || body["name"] != "Q1 plan" || props["mcp-gateway-op"] != opID {
		t.Errorf("body = %v", body)
	}
	if parents, _ := body["parents"].([]any); len(parents) != 1 || parents[0] != folderID {
		t.Errorf("parents = %v", body["parents"])
	}
	if req.URL.Query().Get("supportsAllDrives") != "true" {
		t.Errorf("query = %v", req.URL.Query())
	}
	for _, args := range []map[string]any{{}, {"title": "x", "parent_id": "a/b"}} {
		_, err := run(t, c, write("slides.create", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases("created_presentation.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{createFilePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("slides.create", map[string]any{"title": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
	// The Drive marker check, as docs.create and sheets.create.
	for _, tc := range []struct {
		name string
		rt   route
		want string
	}{
		{"hit", route{status: 200, body: "files_list_marker_hit.json"}, "found"},
		{"miss", route{status: 200, body: "files_list_empty.json"}, "not_found"},
		{"500", route{status: 500, body: "error_server.json"}, "cannot_tell"},
	} {
		t.Run("check "+tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{listFilesPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "slides.create", map[string]any{"title": "x"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			if tc.want == "found" {
				if err != nil || out.Outcome != connectors.ReconcileFound {
					t.Errorf("check = %+v, %v", out, err)
				}
				return
			}
			wantOutcome(t, out, err, tc.want, "")
		})
	}
}

func TestSlidesReplaceText(t *testing.T) {
	srv := newAPIServer(t, map[string]route{presBatchPath: {status: 200, body: "presentation_replace_reply.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("slides.replace_text", map[string]any{"presentation_id": presID, "find": "{{quarter}}", "replace": "Q1"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		PresentationID     string `json:"presentation_id"`
		OccurrencesChanged int64  `json:"occurrences_changed"`
	}
	decode(t, res, &out)
	if out.PresentationID != presID || out.OccurrencesChanged != 4 {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "slides.replace_text").ResultIDs(res); ids["presentation_id"] != presID {
		t.Errorf("ResultIDs = %v", ids)
	}
	body := srv.Last(t, presBatchPath).Body
	if !strings.Contains(body, `"replaceAllText"`) || !strings.Contains(body, `"text":"{{quarter}}"`) || !strings.Contains(body, `"matchCase":true`) || !strings.Contains(body, `"replaceText":"Q1"`) {
		t.Errorf("body = %s", body)
	}
	if _, err := run(t, c, write("slides.replace_text", map[string]any{"presentation_id": presID, "find": "x", "replace": "", "match_case": false})); err != nil {
		t.Fatal(err)
	}
	if body := srv.Last(t, presBatchPath).Body; !strings.Contains(body, `"replaceText":""`) || strings.Contains(body, `"matchCase":true`) {
		t.Errorf("body = %s", body)
	}
	cl, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{{"presentation_id": presID, "replace": "x"}, {"presentation_id": presID, "find": "x"}, {"find": "x", "replace": "y"}} {
		_, err := run(t, cl, write("slides.replace_text", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("presentation_replace_reply.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{presBatchPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("slides.replace_text", map[string]any{"presentation_id": presID, "find": "a", "replace": "b"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

// presentations.get accepts presentations(.readonly), drive, drive.readonly
// and drive.file; batchUpdate presentations, drive and drive.file.
func TestSlidesScopeGate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		getPresPath:   {status: 200, body: "presentation.json"},
		presBatchPath: {status: 200, body: "presentation_replace_reply.json"},
	})
	cases := []struct {
		id         string
		scopes     []string
		read, edit bool
	}{
		{"a3000000-0000-4000-8000-000000000001", []string{google.ScopePresentationsReadonly}, true, false},
		{"a3000000-0000-4000-8000-000000000002", []string{google.ScopePresentations}, true, true},
		{"a3000000-0000-4000-8000-000000000003", []string{google.ScopeDriveReadonly}, true, false},
		{"a3000000-0000-4000-8000-000000000004", []string{google.ScopeDrive}, true, true},
		{"a3000000-0000-4000-8000-000000000005", []string{google.ScopeDriveFile}, true, true},
		{"a3000000-0000-4000-8000-000000000006", []string{google.ScopeDocuments}, false, false},
	}
	accounts := connectors.NewStaticAccountSource()
	for _, tc := range cases {
		accounts.Add(alice, connectors.Account{ID: tc.id, App: google.AppSlides, Label: connectors.LabelPersonal, Scopes: tc.scopes})
	}
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		cl := call("slides.get_text", map[string]any{"presentation_id": presID})
		cl.Account = tc.id
		_, err := run(t, c, cl)
		if tc.read && err != nil {
			t.Errorf("get_text with %v: %v", tc.scopes, err)
		} else if !tc.read {
			wantClass(t, err, google.ClassScopeRequired, 0)
		}
		cl = write("slides.replace_text", map[string]any{"presentation_id": presID, "find": "a", "replace": "b"})
		cl.Account = tc.id
		_, err = run(t, c, cl)
		if tc.edit && err != nil {
			t.Errorf("replace_text with %v: %v", tc.scopes, err)
		} else if !tc.edit {
			wantClass(t, err, google.ClassScopeRequired, 0)
		}
	}
	if !google.PerFile(google.ScopePresentations) || !google.PerFile(google.ScopePresentationsReadonly) {
		t.Error("drive.file must admit the Slides scopes per file")
	}
}
