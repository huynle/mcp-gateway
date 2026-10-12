package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"
)

// Approval is a tool's approval mode: whether a call needs an approval
// first (ask) or runs without one (auto). It is stored per tool in the
// review (ToolReview.Approval) and compiled into the policy as the
// server-level default (internal/policy ServerApproval): an enabled write
// tool in auto mode is allowed for its owner and for roles that allow it;
// in ask mode it needs a confirmation. Role denies, user restrictions,
// token narrowing and a role's own confirm still win.
type Approval string

// Approval modes.
const (
	ApprovalAsk  Approval = "ask"
	ApprovalAuto Approval = "auto"
)

// Valid reports whether a is ask or auto.
func (a Approval) Valid() bool { return a == ApprovalAsk || a == ApprovalAuto }

// ErrInvalidApproval: an approval mode other than ask or auto.
var ErrInvalidApproval = errors.New("snapshot: invalid approval mode")

// Mode is the tool's effective approval mode: auto for a read tool, auto
// for a write tool set to auto, ask for every other write (including a
// review stored before modes existed).
func (tr ToolReview) Mode() Approval {
	if tr.Kind == KindRead || tr.Approval == ApprovalAuto {
		return ApprovalAuto
	}
	return ApprovalAsk
}

// AutoRun reports whether the tool is an enabled write set to auto (what
// the policy lifts the confirmation for).
func (tr ToolReview) AutoRun() bool {
	return tr.Enabled && tr.Kind == KindWrite && tr.Approval == ApprovalAuto
}

func (tr *ToolReview) setApproval(a Approval, actor string, now time.Time) bool {
	if tr.Kind != KindWrite || tr.Mode() == a {
		return false
	}
	tr.Approval, tr.ApprovalBy, tr.ApprovalAt = a, actor, timePtr(now)
	return true
}

func (tr *ToolReview) clearApproval() {
	tr.Approval, tr.ApprovalBy, tr.ApprovalAt = "", "", nil
}

// AutoRunWrites lists, by name, the enabled write tools set to auto.
func (r Review) AutoRunWrites() []string {
	var out []string
	for name, tr := range r {
		if tr.AutoRun() {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// ApprovalCounts summarises the approval modes of a review's enabled
// tools: Auto (reads plus auto writes) and Ask add up to Enabled;
// AutoWrites are the writes that run without approval.
type ApprovalCounts struct{ Enabled, Auto, Ask, AutoWrites int }

// ApprovalCounts counts the enabled tools by mode.
func (r Review) ApprovalCounts() ApprovalCounts {
	var c ApprovalCounts
	for _, tr := range r {
		if !tr.Enabled {
			continue
		}
		c.Enabled++
		if tr.Mode() == ApprovalAuto {
			c.Auto++
			if tr.Kind == KindWrite {
				c.AutoWrites++
			}
		} else {
			c.Ask++
		}
	}
	return c
}

// ApplyApprovals returns a copy of r with the approval modes set (the
// mode edit that needs no new snapshot) and how many tools changed. Read
// tools are left alone (they always run without approval); a tool
// already in the requested mode keeps its record. A name not in r
// returns ErrUnknownTool, a mode other than ask or auto
// ErrInvalidApproval; r is never modified.
func ApplyApprovals(r Review, modes map[string]Approval, actor string, now time.Time) (Review, int, error) {
	for name, a := range modes {
		if _, ok := r[name]; !ok {
			return nil, 0, ErrUnknownTool
		}
		if !a.Valid() {
			return nil, 0, fmt.Errorf("%w: must be ask or auto", ErrInvalidApproval)
		}
	}
	out := maps.Clone(r)
	changed := 0
	for name, a := range modes {
		tr := out[name]
		if tr.setApproval(a, actor, now) {
			out[name] = tr
			changed++
		}
	}
	return out, changed, nil
}

// DecodeReview decodes a review column (either layout, see
// decodeReviewColumn) for readers outside this package (the policy's
// store reads the approval modes of approved snapshots). The legacy
// layout yields a nil content review.
func DecodeReview(raw json.RawMessage) (Review, *ContentReview, error) {
	if normNull(raw) == nil {
		return Review{}, nil, nil
	}
	return decodeReviewColumn(raw)
}
