package snapshot

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	snap := &Snapshot{
		Tools: []Tool{{
			Name: "search", Title: "S", Description: "d\n<b>",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
			Annotations: &Annotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
		}},
		Resources:         []Resource{{URI: "file:///a", Name: "a"}},
		ResourceTemplates: []ResourceTemplate{{URITemplate: "x/{id}", Name: "x"}},
		Prompts:           []Prompt{{Name: "p", Arguments: []PromptArgument{{Name: "a", Required: true}}}},
	}
	row, err := encodeSnapshot("srv-1", snap)
	if err != nil {
		t.Fatal(err)
	}
	if row.ServerID != "srv-1" || row.Status != store.MCPSnapshotPending {
		t.Errorf("row = %+v", row)
	}
	approvedBy := "user-1"
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	row.ID, row.Version, row.ApprovedBy, row.ApprovedAt = "snap-1", 3, &approvedBy, &at
	row.Review, err = encodeReview(Review{"search": {Enabled: true, Kind: KindRead}})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := decodeRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID != "snap-1" || rec.ServerID != "srv-1" || rec.Version != 3 || rec.ApprovedBy != "user-1" || !rec.ApprovedAt.Equal(at) {
		t.Errorf("record = %+v", rec)
	}
	if d := Compare(snap, rec.Snapshot); !d.Empty() {
		t.Errorf("round trip changed the snapshot: %+v", d)
	}
	if !rec.Review["search"].Enabled || rec.Review["search"].Kind != KindRead {
		t.Errorf("review = %+v", rec.Review)
	}
}

func TestEncodeEmptySnapshotUsesEmptyArrays(t *testing.T) {
	row, err := encodeSnapshot("s", &Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]json.RawMessage{"tools": row.Tools, "resources": row.Resources, "templates": row.ResourceTemplates, "prompts": row.Prompts} {
		if string(v) != "[]" {
			t.Errorf("%s = %s, want []", name, v)
		}
	}
	r, err := encodeReview(nil)
	if err != nil || string(r) != "{}" {
		t.Errorf("empty review = %s, %v", r, err)
	}
}

func TestDecodeDefaultsAndLegacyReview(t *testing.T) {
	// Column defaults and the shape used by the store tests.
	row := &store.MCPSnapshot{
		ID: "x", Tools: json.RawMessage(`[{"name":"search","annotations":{"readOnlyHint":true}}]`),
		Resources: json.RawMessage(`[]`), ResourceTemplates: json.RawMessage(`[]`), Prompts: json.RawMessage(`[]`),
		Review: json.RawMessage(`{"search":{"enabled":true,"kind":"read"}}`),
	}
	rec, err := decodeRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Snapshot.Tools) != 1 || rec.Snapshot.Tools[0].HintKind() != KindRead || !rec.Review["search"].Enabled {
		t.Errorf("record = %+v", rec)
	}
	row.Review = json.RawMessage(`{}`)
	if rec, err = decodeRecord(row); err != nil || rec.Review == nil || len(rec.Review) != 0 {
		t.Errorf("empty review = %+v, %v", rec, err)
	}
	row.Tools = json.RawMessage(`{"not":"a list"}`)
	if _, err := decodeRecord(row); !errors.Is(err, ErrCorrupt) {
		t.Errorf("corrupt tools = %v, want ErrCorrupt", err)
	}
}
