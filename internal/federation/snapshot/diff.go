package snapshot

import (
	"encoding/json"
	"reflect"
	"slices"
)

// Tool fields a Diff reports as changed.
const (
	FieldTitle        = "title"
	FieldDescription  = "description"
	FieldInputSchema  = "inputSchema"
	FieldOutputSchema = "outputSchema"
	FieldAnnotations  = "annotations"
)

// ToolChange is one tool present in both snapshots with differing fields
// (Field* constants, in that order).
type ToolChange struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// KeyDiff lists the keys (resource URI, template, prompt name) added,
// removed or changed between two snapshots, each sorted.
type KeyDiff struct {
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Changed []string `json:"changed,omitempty"`
}

// Empty reports whether nothing changed.
func (k KeyDiff) Empty() bool { return len(k.Added)+len(k.Removed)+len(k.Changed) == 0 }

// Diff is what changed from one snapshot (the approved one) to another (a
// refresh). Tool names are sorted. FromVersion / ToVersion are set by the
// Service (0 = none).
type Diff struct {
	FromVersion       int          `json:"fromVersion"`
	ToVersion         int          `json:"toVersion"`
	Added             []string     `json:"added,omitempty"`
	Removed           []string     `json:"removed,omitempty"`
	Changed           []ToolChange `json:"changed,omitempty"`
	Resources         KeyDiff      `json:"resources"`
	ResourceTemplates KeyDiff      `json:"resourceTemplates"`
	Prompts           KeyDiff      `json:"prompts"`
}

// Empty reports whether the snapshots are equivalent.
func (d Diff) Empty() bool {
	return len(d.Added)+len(d.Removed)+len(d.Changed) == 0 &&
		d.Resources.Empty() && d.ResourceTemplates.Empty() && d.Prompts.Empty()
}

// ToolChanged reports whether tool name was added or changed.
func (d Diff) ToolChanged(name string) bool {
	if slices.Contains(d.Added, name) {
		return true
	}
	return slices.ContainsFunc(d.Changed, func(c ToolChange) bool { return c.Name == name })
}

// Compare diffs to against from (nil from = nothing approved yet, so every
// tool is added). Schemas are compared as canonical JSON, so key order and
// whitespace never count as a change.
func Compare(from, to *Snapshot) Diff {
	if from == nil {
		from = &Snapshot{}
	}
	if to == nil {
		to = &Snapshot{}
	}
	var d Diff
	old := make(map[string]Tool, len(from.Tools))
	for _, t := range from.Tools {
		old[t.Name] = t
	}
	seen := make(map[string]bool, len(to.Tools))
	for _, t := range to.Tools {
		seen[t.Name] = true
		prev, ok := old[t.Name]
		if !ok {
			d.Added = append(d.Added, t.Name)
			continue
		}
		if fields := toolFieldsChanged(prev, t); len(fields) > 0 {
			d.Changed = append(d.Changed, ToolChange{Name: t.Name, Fields: fields})
		}
	}
	for _, t := range from.Tools {
		if !seen[t.Name] {
			d.Removed = append(d.Removed, t.Name)
		}
	}
	slices.Sort(d.Added)
	slices.Sort(d.Removed)
	slices.SortFunc(d.Changed, func(a, b ToolChange) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	d.Resources = keyDiff(from.Resources, to.Resources, func(r Resource) string { return r.URI })
	d.ResourceTemplates = keyDiff(from.ResourceTemplates, to.ResourceTemplates, func(r ResourceTemplate) string { return r.URITemplate })
	d.Prompts = keyDiff(from.Prompts, to.Prompts, func(p Prompt) string { return p.Name })
	return d
}

func toolFieldsChanged(a, b Tool) []string {
	var f []string
	if a.Title != b.Title {
		f = append(f, FieldTitle)
	}
	if a.Description != b.Description {
		f = append(f, FieldDescription)
	}
	if !EqualJSON(a.InputSchema, b.InputSchema) {
		f = append(f, FieldInputSchema)
	}
	if !EqualJSON(a.OutputSchema, b.OutputSchema) {
		f = append(f, FieldOutputSchema)
	}
	if !equalAnnotations(a.Annotations, b.Annotations) {
		f = append(f, FieldAnnotations)
	}
	return f
}

// equalAnnotations treats missing annotations like empty ones (both mean
// "no hints").
func equalAnnotations(a, b *Annotations) bool {
	if a == nil {
		a = &Annotations{}
	}
	if b == nil {
		b = &Annotations{}
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func keyDiff[T any](from, to []T, key func(T) string) KeyDiff {
	var d KeyDiff
	old := make(map[string]T, len(from))
	for _, x := range from {
		old[key(x)] = x
	}
	seen := make(map[string]bool, len(to))
	for _, x := range to {
		k := key(x)
		seen[k] = true
		prev, ok := old[k]
		switch {
		case !ok:
			d.Added = append(d.Added, k)
		case !reflect.DeepEqual(prev, x):
			d.Changed = append(d.Changed, k)
		}
	}
	for _, x := range from {
		if k := key(x); !seen[k] {
			d.Removed = append(d.Removed, k)
		}
	}
	slices.Sort(d.Added)
	slices.Sort(d.Removed)
	slices.Sort(d.Changed)
	return d
}
