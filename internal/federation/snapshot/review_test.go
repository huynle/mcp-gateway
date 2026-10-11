package snapshot

import (
	"errors"
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	t1 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
)

func enable(b bool) Decision       { return Decision{Enabled: &b} }
func kindDecision(k Kind) Decision { return Decision{Kind: &k} }

func firstSnapshot() *Snapshot {
	return &Snapshot{Tools: []Tool{
		tool("delete", "d", `{"type":"object"}`, &Annotations{DestructiveHint: boolPtr(true)}),
		tool("list", "l", `{"type":"object"}`, &Annotations{ReadOnlyHint: true}),
		tool("search", "s", `{"type":"object","properties":{"q":{"type":"string"}}}`, &Annotations{ReadOnlyHint: true}),
		tool("send", "s", `{"type":"object"}`, nil),
	}}
}

func TestBuildReviewFirstSnapshotEnablesNothing(t *testing.T) {
	r, err := BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 4 {
		t.Fatalf("review = %+v, want every tool listed", r)
	}
	for name, tr := range r {
		if tr.Enabled {
			t.Errorf("%s enabled without a decision", name)
		}
	}
	if r["list"].Kind != KindRead || r["search"].Kind != KindRead || r["send"].Kind != KindWrite || r["delete"].Kind != KindWrite {
		t.Errorf("kinds = %+v", r)
	}
}

func TestBuildReviewExplicitEnable(t *testing.T) {
	r, err := BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{Tools: map[string]Decision{
		"send": enable(true), "list": enable(true),
	}}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if !r["send"].Enabled || !r["list"].Enabled || r["search"].Enabled || r["delete"].Enabled {
		t.Errorf("review = %+v", r)
	}
	if r["send"].ReviewedBy != "alice" || r["send"].ReviewedAt == nil || !r["send"].ReviewedAt.Equal(t0) {
		t.Errorf("send reviewed = %q %v", r["send"].ReviewedBy, r["send"].ReviewedAt)
	}
}

func TestBuildReviewEnableReadsLeavesWritesDisabled(t *testing.T) {
	r, err := BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{
		EnableReads: true,
		Tools:       map[string]Decision{"search": enable(false)},
	}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if !r["list"].Enabled {
		t.Error("list (read) not enabled by EnableReads")
	}
	if r["search"].Enabled {
		t.Error("explicit disable overridden by EnableReads")
	}
	if r["send"].Enabled || r["delete"].Enabled {
		t.Error("EnableReads enabled a write")
	}
}

func TestBuildReviewKindOverrideRecorded(t *testing.T) {
	r, err := BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{
		EnableReads: true,
		Tools:       map[string]Decision{"list": kindDecision(KindWrite), "send": kindDecision(KindRead)},
	}, "admin", t0)
	if err != nil {
		t.Fatal(err)
	}
	l := r["list"]
	if l.Kind != KindWrite || l.Override == nil || l.Override.Kind != KindWrite || l.Override.By != "admin" || !l.Override.At.Equal(t0) {
		t.Errorf("list = %+v", l)
	}
	if l.Enabled {
		t.Error("EnableReads enabled a tool overridden to write")
	}
	if r["send"].Kind != KindRead {
		t.Errorf("send kind = %s", r["send"].Kind)
	}
}

func TestBuildReviewRejectsBadDecisions(t *testing.T) {
	if _, err := BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{Tools: map[string]Decision{"nope": enable(true)}}, "a", t0); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("unknown tool = %v", err)
	}
	if _, err := BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{Tools: map[string]Decision{"send": kindDecision("admin")}}, "a", t0); !errors.Is(err, ErrInvalidKind) {
		t.Errorf("bad kind = %v", err)
	}
}

func approvedFirst(t *testing.T) (*Snapshot, Review) {
	t.Helper()
	base := firstSnapshot()
	r, err := BuildReview(nil, nil, base, ReviewDecisions{Tools: map[string]Decision{
		"search": enable(true), "send": enable(true), "delete": enable(true), "list": enable(true),
	}}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	// An admin flagged send as a write and list as... write too.
	r2, err := BuildReview(base, r, base, ReviewDecisions{Tools: map[string]Decision{
		"list": kindDecision(KindWrite),
	}}, "admin", t0)
	if err != nil {
		t.Fatal(err)
	}
	return base, r2
}

func TestBuildReviewReapproveSameSnapshotKeepsState(t *testing.T) {
	base, r := approvedFirst(t)
	if !r["search"].Enabled || !r["send"].Enabled || r["search"].ReviewedBy != "alice" {
		t.Errorf("re-approval lost state: %+v", r)
	}
	if r["list"].Override == nil || r["list"].Kind != KindWrite {
		t.Errorf("override lost: %+v", r["list"])
	}
	_ = base
}

func TestBuildReviewRefresh(t *testing.T) {
	base, baseReview := approvedFirst(t)
	next := &Snapshot{Tools: []Tool{
		// delete: unchanged -> keeps enabled.
		tool("delete", "d", `{"type":"object"}`, &Annotations{DestructiveHint: boolPtr(true)}),
		// list: annotations changed; its write override is kept.
		tool("list", "l", `{"type":"object"}`, &Annotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(true)}),
		// search: input schema changed -> disabled until re-enabled.
		tool("search", "s", `{"type":"object","properties":{"q":{"type":"string"},"cmd":{"type":"string"}}}`, &Annotations{ReadOnlyHint: true}),
		// upload: new.
		tool("upload", "u", `{"type":"object"}`, &Annotations{ReadOnlyHint: true}),
		// send: removed.
	}}
	r, err := BuildReview(base, baseReview, next, ReviewDecisions{}, "bob", t1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r["send"]; ok {
		t.Error("removed tool still reviewed")
	}
	if !r["delete"].Enabled || r["delete"].ReviewedBy != "alice" {
		t.Errorf("unchanged tool lost review: %+v", r["delete"])
	}
	if r["search"].Enabled {
		t.Error("tool with changed input schema stays enabled")
	}
	if r["upload"].Enabled || r["upload"].Kind != KindRead {
		t.Errorf("added tool = %+v, want disabled read", r["upload"])
	}
	if r["list"].Enabled || r["list"].Kind != KindWrite || r["list"].Override == nil {
		t.Errorf("changed tool with write override = %+v, want disabled, override kept", r["list"])
	}

	// Re-enabling the changed tool explicitly works.
	r2, err := BuildReview(next, r, next, ReviewDecisions{Tools: map[string]Decision{"search": enable(true)}}, "bob", t1)
	if err != nil {
		t.Fatal(err)
	}
	if !r2["search"].Enabled || r2["search"].ReviewedBy != "bob" {
		t.Errorf("re-enabled search = %+v", r2["search"])
	}
	if !r2["delete"].Enabled {
		t.Error("delete lost on second approval")
	}
}

func TestBuildReviewChangedToolDropsReadOverride(t *testing.T) {
	base := &Snapshot{Tools: []Tool{tool("x", "old", `{"type":"object"}`, nil)}}
	r, err := BuildReview(nil, nil, base, ReviewDecisions{Tools: map[string]Decision{
		"x": {Enabled: boolPtr(true), Kind: kindPtr(KindRead)},
	}}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	next := &Snapshot{Tools: []Tool{tool("x", "new", `{"type":"object"}`, nil)}}
	r2, err := BuildReview(base, r, next, ReviewDecisions{}, "alice", t1)
	if err != nil {
		t.Fatal(err)
	}
	if r2["x"].Override != nil || r2["x"].Kind != KindWrite || r2["x"].Enabled {
		t.Errorf("changed tool = %+v, want read override dropped, write, disabled", r2["x"])
	}
}

func TestBuildReviewClearOverride(t *testing.T) {
	base, r := approvedFirst(t)
	r2, err := BuildReview(base, r, base, ReviewDecisions{Tools: map[string]Decision{"list": kindDecision("")}}, "admin", t1)
	if err != nil {
		t.Fatal(err)
	}
	if r2["list"].Override != nil || r2["list"].Kind != KindRead {
		t.Errorf("cleared override = %+v", r2["list"])
	}
}

func kindPtr(k Kind) *Kind { return &k }
