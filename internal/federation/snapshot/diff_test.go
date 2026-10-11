package snapshot

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestEqualJSONIgnoresKeyOrderAndWhitespace(t *testing.T) {
	a := []byte(`{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"integer","minimum":1.50}},"required":["a"]}`)
	b := []byte(` { "required" : ["a"], "properties": {"b": {"minimum": 1.50, "type": "integer"}, "a": {"type":"string"}}, "type": "object" }`)
	if !EqualJSON(a, b) {
		t.Error("EqualJSON(reordered) = false, want true")
	}
	ca, err := CanonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := CanonicalJSON(b)
	if string(ca) != string(cb) {
		t.Errorf("canonical forms differ:\n%s\n%s", ca, cb)
	}
	// Array order is significant; values matter.
	if EqualJSON([]byte(`{"required":["a","b"]}`), []byte(`{"required":["b","a"]}`)) {
		t.Error("array order ignored")
	}
	if EqualJSON([]byte(`{"type":"string"}`), []byte(`{"type":"integer"}`)) {
		t.Error("different values equal")
	}
	// Large integers are not rounded through float64.
	if EqualJSON([]byte(`{"max":9007199254740993}`), []byte(`{"max":9007199254740992}`)) {
		t.Error("large integers compared through float64")
	}
	if !EqualJSON(nil, []byte(`null`)) || EqualJSON(nil, []byte(`{}`)) {
		t.Error("nil / null handling")
	}
}

func tool(name, desc, in string, ann *Annotations) Tool {
	t := Tool{Name: name, Description: desc, Annotations: ann}
	if in != "" {
		t.InputSchema = json.RawMessage(in)
	}
	return t
}

func TestCompareTools(t *testing.T) {
	approved := &Snapshot{Tools: []Tool{
		tool("keep", "same", `{"type":"object","properties":{"q":{"type":"string"}}}`, &Annotations{ReadOnlyHint: true}),
		tool("schema", "s", `{"type":"object","properties":{"q":{"type":"string"}}}`, nil),
		tool("desc", "old", `{"type":"object"}`, nil),
		tool("ann", "a", `{"type":"object"}`, &Annotations{ReadOnlyHint: true}),
		tool("out", "o", `{"type":"object"}`, nil),
		tool("gone", "g", `{"type":"object"}`, nil),
	}}
	approved.Tools[4].OutputSchema = json.RawMessage(`{"type":"object"}`)
	pending := &Snapshot{Tools: []Tool{
		// Same tool with keys reordered (as jsonb returns it): unchanged.
		tool("keep", "same", `{"properties":{"q":{"type":"string"}},"type":"object"}`, &Annotations{ReadOnlyHint: true}),
		tool("schema", "s", `{"type":"object","properties":{"q":{"type":"string"},"x":{"type":"string"}}}`, nil),
		tool("desc", "new", `{"type":"object"}`, nil),
		tool("ann", "a", `{"type":"object"}`, &Annotations{ReadOnlyHint: true, DestructiveHint: boolPtr(true)}),
		tool("out", "o", `{"type":"object"}`, nil),
		tool("new", "n", `{"type":"object"}`, nil),
	}}
	d := Compare(approved, pending)
	if !slices.Equal(d.Added, []string{"new"}) {
		t.Errorf("added = %v", d.Added)
	}
	if !slices.Equal(d.Removed, []string{"gone"}) {
		t.Errorf("removed = %v", d.Removed)
	}
	want := map[string][]string{
		"schema": {FieldInputSchema},
		"desc":   {FieldDescription},
		"ann":    {FieldAnnotations},
		"out":    {FieldOutputSchema},
	}
	if len(d.Changed) != len(want) {
		t.Fatalf("changed = %+v, want %d entries", d.Changed, len(want))
	}
	for _, c := range d.Changed {
		if !slices.Equal(c.Fields, want[c.Name]) {
			t.Errorf("changed %s fields = %v, want %v", c.Name, c.Fields, want[c.Name])
		}
	}
	if !slices.IsSortedFunc(d.Changed, func(a, b ToolChange) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	}) {
		t.Errorf("changed not sorted: %+v", d.Changed)
	}
	if d.Empty() {
		t.Error("Empty() = true")
	}
	if !d.ToolChanged("schema") || !d.ToolChanged("new") || d.ToolChanged("keep") {
		t.Error("ToolChanged wrong")
	}
}

func TestCompareTitleAndMultipleFields(t *testing.T) {
	a := &Snapshot{Tools: []Tool{{Name: "t", Title: "A", Description: "x", InputSchema: json.RawMessage(`{"type":"object"}`)}}}
	b := &Snapshot{Tools: []Tool{{Name: "t", Title: "B", Description: "y", InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`)}}}
	d := Compare(a, b)
	if len(d.Changed) != 1 || !slices.Equal(d.Changed[0].Fields, []string{FieldTitle, FieldDescription, FieldInputSchema}) {
		t.Errorf("changed = %+v", d.Changed)
	}
}

func TestCompareAgainstNoApprovedSnapshot(t *testing.T) {
	pending := &Snapshot{Tools: []Tool{{Name: "b"}, {Name: "a"}}}
	d := Compare(nil, pending)
	if !slices.Equal(d.Added, []string{"a", "b"}) || len(d.Removed) != 0 || len(d.Changed) != 0 {
		t.Errorf("diff = %+v", d)
	}
}

func TestCompareIdenticalIsEmpty(t *testing.T) {
	s := &Snapshot{
		Tools:     []Tool{tool("a", "d", `{"type":"object"}`, nil)},
		Resources: []Resource{{URI: "u", Name: "n"}},
		Prompts:   []Prompt{{Name: "p"}},
	}
	if d := Compare(s, s); !d.Empty() {
		t.Errorf("diff of identical = %+v", d)
	}
}

func TestCompareResourcesTemplatesPrompts(t *testing.T) {
	a := &Snapshot{
		Resources:         []Resource{{URI: "r1", Name: "one"}, {URI: "r2", Name: "two"}},
		ResourceTemplates: []ResourceTemplate{{URITemplate: "t/{x}", Name: "t"}},
		Prompts:           []Prompt{{Name: "p", Description: "old"}},
	}
	b := &Snapshot{
		Resources:         []Resource{{URI: "r1", Name: "uno"}, {URI: "r3", Name: "three"}},
		ResourceTemplates: []ResourceTemplate{{URITemplate: "t/{x}", Name: "t"}},
		Prompts:           []Prompt{{Name: "p", Description: "new", Arguments: []PromptArgument{{Name: "a"}}}},
	}
	d := Compare(a, b)
	if !slices.Equal(d.Resources.Added, []string{"r3"}) || !slices.Equal(d.Resources.Removed, []string{"r2"}) ||
		!slices.Equal(d.Resources.Changed, []string{"r1"}) {
		t.Errorf("resources = %+v", d.Resources)
	}
	if !d.ResourceTemplates.Empty() {
		t.Errorf("templates = %+v", d.ResourceTemplates)
	}
	if !slices.Equal(d.Prompts.Changed, []string{"p"}) {
		t.Errorf("prompts = %+v", d.Prompts)
	}
}
