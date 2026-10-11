package snapshot

import (
	"fmt"
	"time"
)

// BuildReview computes the review of snapshot next from the approved
// snapshot base and its review baseReview (both nil for a first snapshot)
// plus the reviewer's decisions, made by actor at now.
//
//   - A tool unchanged since base keeps its review (enabled state, kind
//     override, who reviewed it).
//   - A new tool, a changed tool (title, description, schemas or
//     annotations) and any tool without a prior review is disabled. A
//     changed tool keeps a kind override only when it was write (the
//     stricter kind); its kind is otherwise recomputed from the new hints.
//   - Tools missing from next are dropped.
//   - Then decisions apply: Kind (override, or "" to clear it) first, then
//     Enabled. EnableReads enables the read tools no reviewer has decided
//     on yet (new, changed, or never reviewed) that got no Enabled
//     decision; a tool a reviewer explicitly disabled stays disabled.
//
// Decisions naming a tool not in next return ErrUnknownTool; a kind other
// than read, write or "" returns ErrInvalidKind.
func BuildReview(base *Snapshot, baseReview Review, next *Snapshot, d ReviewDecisions, actor string, now time.Time) (Review, error) {
	if next == nil {
		next = &Snapshot{}
	}
	for name, dec := range d.Tools {
		if _, ok := next.Tool(name); !ok {
			return nil, ErrUnknownTool
		}
		if dec.Kind != nil && *dec.Kind != "" && !dec.Kind.Valid() {
			return nil, fmt.Errorf("%w: must be read or write", ErrInvalidKind)
		}
	}
	diff := Compare(base, next)
	out := make(Review, len(next.Tools))
	for _, t := range next.Tools {
		prev, had := baseReview[t.Name]
		var tr ToolReview
		switch {
		case had && !diff.ToolChanged(t.Name):
			tr = prev
		default:
			if had && prev.Override != nil && prev.Override.Kind == KindWrite {
				o := *prev.Override
				tr.Override = &o
			}
		}
		dec, decided := d.Tools[t.Name]
		if decided && dec.Kind != nil {
			if *dec.Kind == "" {
				tr.Override = nil
			} else {
				tr.Override = &KindOverride{Kind: *dec.Kind, By: actor, At: now}
			}
		}
		tr.Kind = t.HintKind()
		if tr.Override != nil {
			tr.Kind = tr.Override.Kind
		}
		switch {
		case decided && dec.Enabled != nil:
			tr.Enabled = *dec.Enabled
			tr.ReviewedBy, tr.ReviewedAt = actor, timePtr(now)
		case d.EnableReads && !tr.Enabled && tr.ReviewedBy == "" && tr.Kind == KindRead:
			tr.Enabled = true
			tr.ReviewedBy, tr.ReviewedAt = actor, timePtr(now)
		}
		out[t.Name] = tr
	}
	return out, nil
}

func timePtr(t time.Time) *time.Time { return &t }
