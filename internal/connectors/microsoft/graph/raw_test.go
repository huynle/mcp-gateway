package graph_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

func TestDownloadReadsRawBytesWithinTheBound(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/drive/items/item-1/content": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("hello, file"))
		},
	})
	c := newClient(t, s)
	got, hdr, err := c.Download(context.Background(), "me/drive/items/item-1/content", nil, 64)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(got) != "hello, file" || hdr.Get("Content-Type") != "text/plain" {
		t.Errorf("Download = %q, %q", got, hdr.Get("Content-Type"))
	}
	if accept := s.Requests()[0].Header.Get("Accept"); accept != "*/*" {
		t.Errorf("Accept = %q, want */*", accept)
	}
}

func TestDownloadFollowsRedirectToTheContent(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/drive/items/item-1/content": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/v1.0/download/blob-1", http.StatusFound)
		},
		"GET /v1.0/download/blob-1": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("blob")) },
	})
	got, _, err := newClient(t, s).Download(context.Background(), "me/drive/items/item-1/content", nil, 64)
	if err != nil || string(got) != "blob" {
		t.Fatalf("Download = %q, %v", got, err)
	}
}

func TestDownloadRefusesMoreThanMax(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/big": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 65))) },
	})
	_, _, err := newClient(t, s).Download(context.Background(), "big", nil, 64)
	if !errors.Is(err, graph.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestDownloadErrorEnvelope(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/missing": jsonAnswer(404, `{"error":{"code":"itemNotFound","message":"gone"}}`),
	})
	_, _, err := newClient(t, s).Download(context.Background(), "missing", nil, 64)
	var ge *graph.Error
	if !errors.As(err, &ge) || ge.Status != 404 || ge.Code != "itemNotFound" {
		t.Fatalf("err = %v, want graph 404 itemNotFound", err)
	}
}

func TestRawBodyIsSentAsIs(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"PUT /v1.0/me/drive/items/root:/a.txt:/content": jsonAnswer(201, `{"id":"new-1"}`),
	})
	var out struct {
		ID string `json:"id"`
	}
	res, err := newClient(t, s).Do(context.Background(), graph.Request{
		Method: http.MethodPut, Path: "me/drive/items/root:/a.txt:/content", RawBody: []byte("raw bytes"), ContentType: "application/octet-stream",
	}, &out)
	if err != nil || res.Status != 201 || out.ID != "new-1" {
		t.Fatalf("Do = %+v, %+v, %v", res, out, err)
	}
	r := s.Requests()[0]
	if r.Body != "raw bytes" || r.Header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("body %q, content type %q", r.Body, r.Header.Get("Content-Type"))
	}
}

func TestPatchAndDeleteHelpers(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"PATCH /v1.0/me/messages/m-1":  jsonAnswer(200, `{"id":"m-1","isRead":true}`),
		"DELETE /v1.0/me/messages/m-1": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
	})
	c := newClient(t, s)
	var out map[string]any
	if err := c.Patch(context.Background(), "me/messages/m-1", map[string]any{"isRead": true}, &out); err != nil || out["isRead"] != true {
		t.Fatalf("Patch = %v, %v", out, err)
	}
	if err := c.Delete(context.Background(), "me/messages/m-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := s.Requests()[0].Body; got != `{"isRead":true}` {
		t.Errorf("patch body = %q", got)
	}
}
