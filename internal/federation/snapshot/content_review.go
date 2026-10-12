package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ErrUnknownItem: a review decision names a resource, resource template
// or prompt that is not in the snapshot.
var ErrUnknownItem = errors.New("snapshot: decision for a resource, template or prompt not in the snapshot")

// ItemReview is the review state of one resource, resource template or
// prompt of an approved snapshot. ReviewedBy / ReviewedAt record who last
// set Enabled; empty for an item carried over from a snapshot approved
// before resources and prompts had review toggles.
type ItemReview struct {
	Enabled    bool       `json:"enabled"`
	ReviewedBy string     `json:"reviewedBy,omitempty"`
	ReviewedAt *time.Time `json:"reviewedAt,omitempty"`
}

// ContentReview is the review of a snapshot's resources (by URI),
// resource templates (by URI template) and prompts (by name), Brain task
// bdb5zcud. Only enabled items are listed and served on /mcp.
//
// A nil *ContentReview belongs to a snapshot approved before these
// toggles existed: everything in it counts as enabled, so servers
// approved earlier keep working without a new review. Every approval
// since stores a non-nil one, where an item without an entry is disabled.
type ContentReview struct {
	Resources         map[string]ItemReview `json:"resources"`
	ResourceTemplates map[string]ItemReview `json:"resourceTemplates"`
	Prompts           map[string]ItemReview `json:"prompts"`
}

// ResourceEnabled reports whether the resource with this URI is enabled.
func (c *ContentReview) ResourceEnabled(uri string) bool {
	return c == nil || c.Resources[uri].Enabled
}

// TemplateEnabled reports whether the resource template is enabled.
func (c *ContentReview) TemplateEnabled(uriTemplate string) bool {
	return c == nil || c.ResourceTemplates[uriTemplate].Enabled
}

// PromptEnabled reports whether the prompt is enabled.
func (c *ContentReview) PromptEnabled(name string) bool {
	return c == nil || c.Prompts[name].Enabled
}

// BuildContentReview computes the content review of next from the
// approved snapshot base and its content review baseContent, with the
// same carry-over rules as BuildReview for tools:
//
//   - an item unchanged since base keeps its review; with a nil
//     baseContent (approved before the toggles) it is enabled;
//   - a new or changed item (any listed field differs) starts disabled;
//   - items missing from next are dropped;
//   - then the decisions apply.
//
// Decisions naming an item not in next return ErrUnknownItem. The result
// is never nil.
func BuildContentReview(base *Snapshot, baseContent *ContentReview, next *Snapshot, d ReviewDecisions, actor string, now time.Time) (*ContentReview, error) {
	if next == nil {
		next = &Snapshot{}
	}
	diff := Compare(base, next)
	var baseResources, baseTemplates, basePrompts map[string]ItemReview
	if baseContent != nil {
		baseResources, baseTemplates, basePrompts = baseContent.Resources, baseContent.ResourceTemplates, baseContent.Prompts
	}
	out := &ContentReview{}
	var err error
	if out.Resources, err = buildItems(keys(next.Resources, func(r Resource) string { return r.URI }),
		baseResources, baseContent == nil, diff.Resources, d.Resources, actor, now); err != nil {
		return nil, err
	}
	if out.ResourceTemplates, err = buildItems(keys(next.ResourceTemplates, func(r ResourceTemplate) string { return r.URITemplate }),
		baseTemplates, baseContent == nil, diff.ResourceTemplates, d.ResourceTemplates, actor, now); err != nil {
		return nil, err
	}
	if out.Prompts, err = buildItems(keys(next.Prompts, func(p Prompt) string { return p.Name }),
		basePrompts, baseContent == nil, diff.Prompts, d.Prompts, actor, now); err != nil {
		return nil, err
	}
	return out, nil
}

func keys[T any](xs []T, key func(T) string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = key(x)
	}
	return out
}

// buildItems is BuildContentReview for one kind of item. legacy means the
// base had no content review: its items count as enabled.
func buildItems(next []string, base map[string]ItemReview, legacy bool, diff KeyDiff, decisions map[string]bool, actor string, now time.Time) (map[string]ItemReview, error) {
	for k := range decisions {
		if !slices.Contains(next, k) {
			return nil, ErrUnknownItem
		}
	}
	out := make(map[string]ItemReview, len(next))
	for _, k := range next {
		var ir ItemReview
		if !slices.Contains(diff.Added, k) && !slices.Contains(diff.Changed, k) {
			if legacy {
				ir.Enabled = true
			} else {
				ir = base[k]
			}
		}
		if on, ok := decisions[k]; ok {
			ir.Enabled, ir.ReviewedBy, ir.ReviewedAt = on, actor, timePtr(now)
		}
		out[k] = ir
	}
	return out, nil
}

// reviewFormat marks the review column's current layout:
//
//	{"format": 2, "tools": {<tool>: ToolReview}, "content": ContentReview}
//
// The legacy layout is the flat tool map (Review) alone; its values are
// always objects, so a number under "format" tells the two apart even when
// a tool is called "format".
const reviewFormat = 2

type reviewColumn struct {
	Format  int            `json:"format"`
	Tools   Review         `json:"tools"`
	Content *ContentReview `json:"content,omitempty"`
}

// encodeFullReview encodes the tool review and the content review for the
// review column (current layout).
func encodeFullReview(r Review, c *ContentReview) (json.RawMessage, error) {
	if r == nil {
		r = Review{}
	}
	b, err := json.Marshal(reviewColumn{Format: reviewFormat, Tools: r, Content: c})
	if err != nil {
		return nil, fmt.Errorf("snapshot: encode review: %w", err)
	}
	return b, nil
}

// decodeReviewColumn decodes either layout; the legacy one yields a nil
// content review.
func decodeReviewColumn(raw json.RawMessage) (Review, *ContentReview, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, nil, ErrCorrupt
	}
	if f, ok := top["format"]; ok && len(bytes.TrimSpace(f)) > 0 && bytes.TrimSpace(f)[0] != '{' {
		var col reviewColumn
		if err := json.Unmarshal(raw, &col); err != nil || col.Format != reviewFormat {
			return nil, nil, ErrCorrupt
		}
		if col.Tools == nil {
			col.Tools = Review{}
		}
		if col.Content == nil {
			col.Content = &ContentReview{}
		}
		return col.Tools, col.Content, nil
	}
	var r Review
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, nil, ErrCorrupt
	}
	return r, nil, nil
}
