package snapshot

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
)

func contentSnapshot() *Snapshot {
	return &Snapshot{
		Tools:             []Tool{tool("search", "s", `{"type":"object"}`, &Annotations{ReadOnlyHint: true})},
		Resources:         []Resource{{URI: "docs://a", Name: "a"}, {URI: "docs://b", Name: "b"}},
		ResourceTemplates: []ResourceTemplate{{URITemplate: "docs://page/{slug}", Name: "page"}},
		Prompts:           []Prompt{{Name: "summarize"}, {Name: "translate"}},
	}
}

// A nil content review is an approved snapshot from before resources and
// prompts had review toggles: everything in it counts as enabled.
func TestContentReviewNilMeansAllEnabled(t *testing.T) {
	var c *ContentReview
	if !c.ResourceEnabled("docs://a") || !c.TemplateEnabled("docs://page/{slug}") || !c.PromptEnabled("summarize") {
		t.Error("a nil content review must enable everything (backward compatibility)")
	}
	c = &ContentReview{}
	if c.ResourceEnabled("docs://a") || c.TemplateEnabled("x") || c.PromptEnabled("summarize") {
		t.Error("an empty content review must enable nothing")
	}
}

func TestBuildContentReviewFirstSnapshotEnablesNothing(t *testing.T) {
	c, err := BuildContentReview(nil, nil, contentSnapshot(), ReviewDecisions{}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || len(c.Resources) != 2 || len(c.ResourceTemplates) != 1 || len(c.Prompts) != 2 {
		t.Fatalf("content review = %+v, want every item listed", c)
	}
	if c.ResourceEnabled("docs://a") || c.TemplateEnabled("docs://page/{slug}") || c.PromptEnabled("summarize") {
		t.Errorf("enabled without a decision: %+v", c)
	}
}

func TestBuildContentReviewDecisions(t *testing.T) {
	d := ReviewDecisions{
		Resources:         map[string]bool{"docs://a": true, "docs://b": false},
		ResourceTemplates: map[string]bool{"docs://page/{slug}": true},
		Prompts:           map[string]bool{"summarize": true},
	}
	c, err := BuildContentReview(nil, nil, contentSnapshot(), d, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ResourceEnabled("docs://a") || c.ResourceEnabled("docs://b") || !c.TemplateEnabled("docs://page/{slug}") ||
		!c.PromptEnabled("summarize") || c.PromptEnabled("translate") {
		t.Errorf("content review = %+v", c)
	}
	if r := c.Resources["docs://a"]; r.ReviewedBy != "alice" || r.ReviewedAt == nil || !r.ReviewedAt.Equal(t0) {
		t.Errorf("reviewed = %+v", r)
	}
	for _, bad := range []ReviewDecisions{
		{Resources: map[string]bool{"docs://zzz": true}},
		{ResourceTemplates: map[string]bool{"nope/{x}": true}},
		{Prompts: map[string]bool{"nope": true}},
	} {
		if _, err := BuildContentReview(nil, nil, contentSnapshot(), bad, "alice", t0); !errors.Is(err, ErrUnknownItem) {
			t.Errorf("%+v: err = %v, want ErrUnknownItem", bad, err)
		}
	}
}

// On a refresh, unchanged items keep their state; new and changed ones
// start disabled; removed ones are dropped.
func TestBuildContentReviewRefreshCarriesOver(t *testing.T) {
	base := contentSnapshot()
	baseReview, err := BuildContentReview(nil, nil, base, ReviewDecisions{
		Resources: map[string]bool{"docs://a": true, "docs://b": true}, ResourceTemplates: map[string]bool{"docs://page/{slug}": true},
		Prompts: map[string]bool{"summarize": true, "translate": false},
	}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	next := contentSnapshot()
	next.Resources = []Resource{{URI: "docs://a", Name: "a"}, {URI: "docs://b", Name: "b", Description: "changed"}, {URI: "docs://c", Name: "c"}}
	next.Prompts = []Prompt{{Name: "summarize"}, {Name: "translate"}, {Name: "zzz"}}
	c, err := BuildContentReview(base, baseReview, next, ReviewDecisions{}, "bob", t1)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ResourceEnabled("docs://a") || c.Resources["docs://a"].ReviewedBy != "alice" {
		t.Errorf("unchanged resource lost its review: %+v", c.Resources["docs://a"])
	}
	if c.ResourceEnabled("docs://b") || c.ResourceEnabled("docs://c") {
		t.Error("changed or new resource enabled")
	}
	if !c.TemplateEnabled("docs://page/{slug}") || !c.PromptEnabled("summarize") || c.PromptEnabled("translate") || c.PromptEnabled("zzz") {
		t.Errorf("content review = %+v", c)
	}
}

// An approved snapshot without content review (before the toggles
// existed) is all enabled: approving its refresh keeps the unchanged
// items enabled and disables only new and changed ones.
func TestBuildContentReviewFromLegacyBase(t *testing.T) {
	base := contentSnapshot()
	next := contentSnapshot()
	next.Resources = append(next.Resources, Resource{URI: "docs://new", Name: "new"})
	next.Prompts[1].Description = "changed"
	c, err := BuildContentReview(base, nil, next, ReviewDecisions{}, "bob", t1)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ResourceEnabled("docs://a") || !c.ResourceEnabled("docs://b") || !c.TemplateEnabled("docs://page/{slug}") || !c.PromptEnabled("summarize") {
		t.Errorf("legacy unchanged items not carried over as enabled: %+v", c)
	}
	if c.ResourceEnabled("docs://new") || c.PromptEnabled("translate") {
		t.Errorf("new or changed items enabled: %+v", c)
	}
}

// The review column: legacy rows (a flat tool map) decode with a nil
// content review; new rows carry tools and content.
func TestReviewColumnFormats(t *testing.T) {
	snap := contentSnapshot()
	row, err := encodeSnapshot("srv-1", snap)
	if err != nil {
		t.Fatal(err)
	}
	row.ID, row.Version, row.Status = "snap-1", 1, store.MCPSnapshotApproved

	// Legacy: flat map, even with a tool literally named "format".
	row.Review = json.RawMessage(`{"search":{"enabled":true,"kind":"read"},"format":{"enabled":false,"kind":"write"}}`)
	rec, err := decodeRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Content != nil || !rec.Review["search"].Enabled || rec.Review["format"].Kind != KindWrite {
		t.Errorf("legacy decode = %+v / %+v", rec.Review, rec.Content)
	}

	// New format round trip.
	content := &ContentReview{
		Resources:         map[string]ItemReview{"docs://a": {Enabled: true}},
		ResourceTemplates: map[string]ItemReview{},
		Prompts:           map[string]ItemReview{"summarize": {Enabled: false}},
	}
	row.Review, err = encodeFullReview(Review{"search": {Enabled: true, Kind: KindRead}}, content)
	if err != nil {
		t.Fatal(err)
	}
	rec, err = decodeRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Content == nil || !rec.Content.ResourceEnabled("docs://a") || rec.Content.ResourceEnabled("docs://b") || rec.Content.PromptEnabled("summarize") {
		t.Errorf("content = %+v", rec.Content)
	}
	if !rec.Review["search"].Enabled || len(rec.Review) != 1 {
		t.Errorf("tools = %+v", rec.Review)
	}
	// Corrupt new-format review.
	row.Review = json.RawMessage(`{"format":2,"tools":[]}`)
	if _, err := decodeRecord(row); !errors.Is(err, ErrCorrupt) {
		t.Errorf("corrupt = %v", err)
	}
}
