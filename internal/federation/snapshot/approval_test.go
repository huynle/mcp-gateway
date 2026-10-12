package snapshot

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func approvalDecision(a Approval) Decision { return Decision{Approval: &a} }

func withEnabled(d Decision, on bool) Decision { d.Enabled = &on; return d }

// Writes default to ask, reads count as auto; a reviewer sets auto per
// write tool and it is recorded with who and when.
func TestApprovalDefaultsAndDecision(t *testing.T) {
	r, err := BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{Tools: map[string]Decision{
		"send":   withEnabled(approvalDecision(ApprovalAuto), true),
		"delete": enable(true),
		"list":   enable(true),
	}}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if got := r["delete"].Mode(); got != ApprovalAsk {
		t.Errorf("write without decision: mode %q, want ask", got)
	}
	if got := r["list"].Mode(); got != ApprovalAuto {
		t.Errorf("read: mode %q, want auto", got)
	}
	send := r["send"]
	if send.Mode() != ApprovalAuto || send.Approval != ApprovalAuto {
		t.Fatalf("send = %+v, want auto", send)
	}
	if send.ApprovalBy != "alice" || send.ApprovalAt == nil || !send.ApprovalAt.Equal(t0) {
		t.Errorf("send approval recorded as %q %v", send.ApprovalBy, send.ApprovalAt)
	}
	if got := r.AutoRunWrites(); !slices.Equal(got, []string{"send"}) {
		t.Errorf("AutoRunWrites = %v, want [send]", got)
	}
	c := r.ApprovalCounts()
	if c.Enabled != 3 || c.Auto != 2 || c.Ask != 1 || c.AutoWrites != 1 {
		t.Errorf("counts = %+v", c)
	}
}

// An approval decision on a read tool is ignored (reads always run
// without approval); an invalid value is refused.
func TestApprovalDecisionValidation(t *testing.T) {
	r, err := BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{Tools: map[string]Decision{
		"list": withEnabled(approvalDecision(ApprovalAsk), true),
	}}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if r["list"].Approval != "" || r["list"].Mode() != ApprovalAuto {
		t.Errorf("read tool got approval %+v", r["list"])
	}
	_, err = BuildReview(nil, nil, firstSnapshot(), ReviewDecisions{Tools: map[string]Decision{
		"send": approvalDecision("sometimes"),
	}}, "alice", t0)
	if !errors.Is(err, ErrInvalidApproval) {
		t.Errorf("invalid approval: err = %v, want ErrInvalidApproval", err)
	}
}

// Refresh: unchanged tools keep their mode, changed and new ones reset to
// ask; a kind override that changes the effective kind resets it too.
func TestApprovalCarryOver(t *testing.T) {
	base := firstSnapshot()
	baseReview, err := BuildReview(nil, nil, base, ReviewDecisions{Tools: map[string]Decision{
		"send":   withEnabled(approvalDecision(ApprovalAuto), true),
		"delete": withEnabled(approvalDecision(ApprovalAuto), true),
	}}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	next := firstSnapshot()
	next.Tools[0].Description = "delete, now different" // delete changed
	next.Tools = append(next.Tools, tool("zap", "z", `{"type":"object"}`, nil))
	r, err := BuildReview(base, baseReview, next, ReviewDecisions{}, "bob", t1)
	if err != nil {
		t.Fatal(err)
	}
	if r["send"].Mode() != ApprovalAuto || r["send"].ApprovalBy != "alice" {
		t.Errorf("unchanged send = %+v, want auto by alice", r["send"])
	}
	if r["delete"].Mode() != ApprovalAsk || r["delete"].Approval != "" {
		t.Errorf("changed delete = %+v, want ask", r["delete"])
	}
	if r["zap"].Mode() != ApprovalAsk {
		t.Errorf("new zap = %+v, want ask", r["zap"])
	}
	// Override send to read and back to write: the auto mode does not
	// survive the kind change.
	r2, err := BuildReview(next, r, next, ReviewDecisions{Tools: map[string]Decision{"send": kindDecision(KindRead)}}, "bob", t1)
	if err != nil {
		t.Fatal(err)
	}
	r3, err := BuildReview(next, r2, next, ReviewDecisions{Tools: map[string]Decision{"send": kindDecision("")}}, "bob", t1)
	if err != nil {
		t.Fatal(err)
	}
	if r3["send"].Mode() != ApprovalAsk {
		t.Errorf("send after read->write = %+v, want ask", r3["send"])
	}
}

// A stored review written before approval modes existed has no approval
// field: every write is ask.
func TestApprovalBackwardCompatibleDecode(t *testing.T) {
	legacy := json.RawMessage(`{"send":{"enabled":true,"kind":"write"},"list":{"enabled":true,"kind":"read"}}`)
	v2 := json.RawMessage(`{"format":2,"tools":{"send":{"enabled":true,"kind":"write"}},"content":{}}`)
	for name, raw := range map[string]json.RawMessage{"legacy": legacy, "format2": v2} {
		r, _, err := DecodeReview(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r["send"].Mode() != ApprovalAsk {
			t.Errorf("%s: send mode %q, want ask", name, r["send"].Mode())
		}
		if len(r.AutoRunWrites()) != 0 {
			t.Errorf("%s: AutoRunWrites = %v, want none", name, r.AutoRunWrites())
		}
	}
	// A format-2 review with modes round-trips.
	r := Review{"send": {Enabled: true, Kind: KindWrite, Approval: ApprovalAuto, ApprovalBy: "alice", ApprovalAt: timePtr(t0)}}
	raw, err := encodeFullReview(r, &ContentReview{})
	if err != nil {
		t.Fatal(err)
	}
	back, _, err := DecodeReview(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back["send"].Mode() != ApprovalAuto || back["send"].ApprovalBy != "alice" {
		t.Errorf("round trip = %+v", back["send"])
	}
}

// ApplyApprovals edits the modes of an approved review without a new
// snapshot: writes change and are recorded, reads are left alone, unknown
// tools and invalid modes are refused.
func TestApplyApprovals(t *testing.T) {
	r := Review{
		"send": {Enabled: true, Kind: KindWrite},
		"del":  {Enabled: true, Kind: KindWrite, Approval: ApprovalAuto, ApprovalBy: "alice", ApprovalAt: timePtr(t0)},
		"list": {Enabled: true, Kind: KindRead},
	}
	out, changed, err := ApplyApprovals(r, map[string]Approval{"send": ApprovalAuto, "del": ApprovalAuto, "list": ApprovalAsk}, "bob", t1)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Errorf("changed = %d, want 1 (send)", changed)
	}
	if out["send"].Mode() != ApprovalAuto || out["send"].ApprovalBy != "bob" || !out["send"].ApprovalAt.Equal(t1) {
		t.Errorf("send = %+v", out["send"])
	}
	if out["del"].ApprovalBy != "alice" {
		t.Errorf("unchanged del re-recorded: %+v", out["del"])
	}
	if out["list"].Approval != "" {
		t.Errorf("read list got a mode: %+v", out["list"])
	}
	if r["send"].Approval != "" {
		t.Error("ApplyApprovals mutated its input")
	}
	if _, _, err := ApplyApprovals(r, map[string]Approval{"nope": ApprovalAuto}, "bob", t1); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("unknown tool: %v", err)
	}
	if _, _, err := ApplyApprovals(r, map[string]Approval{"send": "x"}, "bob", t1); !errors.Is(err, ErrInvalidApproval) {
		t.Errorf("invalid mode: %v", err)
	}
}
