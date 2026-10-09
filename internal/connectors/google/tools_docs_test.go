package google_test

import (
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/api/docs/v1"

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
