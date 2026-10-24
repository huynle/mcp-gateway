package ref

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// handles used across tests: valid, fixed-width, distinct.
var (
	h1 = Prefix + strings.Repeat("A", HandleLen)
	h2 = Prefix + strings.Repeat("b", HandleLen)
	h3 = Prefix + strings.Repeat("3", HandleLen)
)

func refObj(h string) map[string]any { return map[string]any{Key: h} }

func TestGenerateShapeAndValid(t *testing.T) {
	re := regexp.MustCompile(`^sec_[0-9A-Za-z]{43}$`)
	seen := map[string]bool{}
	for range 200 {
		h, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !re.MatchString(h) {
			t.Fatalf("Generate() = %q, want %s", h, re)
		}
		if !Valid(h) {
			t.Fatalf("Valid(%q) = false", h)
		}
		if seen[h] {
			t.Fatalf("Generate repeated %q", h)
		}
		seen[h] = true
	}
	if ScanPattern != `sec_[0-9A-Za-z]{43}` {
		t.Fatalf("ScanPattern = %q", ScanPattern)
	}
}

func TestValid(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{h1, true},
		{h2, true},
		{"", false},
		{"sec_", false},
		{"sec_abc", false},
		{h1 + "A", false},
		{h1[:len(h1)-1], false},
		{"SEC_" + strings.Repeat("A", HandleLen), false},
		{"mgw_" + strings.Repeat("A", HandleLen), false},
		{"sec_" + strings.Repeat("A", HandleLen-1) + "-", false},
		{"sec_" + strings.Repeat("A", HandleLen-1) + "_", false},
		{" " + h1, false},
		{h1 + "\n", false},
		{"sec_" + strings.Repeat("é", HandleLen/2), false},
	}
	for _, tt := range tests {
		if got := Valid(tt.in); got != tt.want {
			t.Errorf("Valid(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestIsRef(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
		ok   bool
	}{
		{"ref", refObj(h1), h1, true},
		{"extra key", map[string]any{Key: h1, "x": 1}, "", false},
		{"non-string value", map[string]any{Key: 42.0}, "", false},
		{"nested object value", map[string]any{Key: refObj(h1)}, "", false},
		{"wrong prefix", map[string]any{Key: "mgw_" + strings.Repeat("A", HandleLen)}, "", false},
		{"short handle", map[string]any{Key: "sec_abc"}, "", false},
		{"wrong key", map[string]any{"secret": h1}, "", false},
		{"bare string", h1, "", false},
		{"empty map", map[string]any{}, "", false},
		{"nil", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := IsRef(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("IsRef = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestFind(t *testing.T) {
	lookalikes := map[string]any{
		"extra":   map[string]any{Key: h3, "other": "x"},
		"number":  map[string]any{Key: 1.0},
		"prefix":  map[string]any{Key: "tok_" + strings.Repeat("A", HandleLen)},
		"bare":    h3,
		"wrongky": map[string]any{"$Secret": h3},
	}
	tests := []struct {
		name string
		in   any
		want []string
	}{
		{"nil", nil, nil},
		{"scalar", "x", nil},
		{"empty", map[string]any{}, nil},
		{"top level", map[string]any{"password": refObj(h1), "user": "bob"}, []string{h1}},
		{"nested", map[string]any{"auth": map[string]any{"inner": map[string]any{"pw": refObj(h1)}}}, []string{h1}},
		{"in array", map[string]any{"list": []any{"a", refObj(h1), []any{refObj(h2)}}}, []string{h1, h2}},
		{"dedupe", map[string]any{"a": refObj(h1), "b": refObj(h1), "c": []any{refObj(h1), refObj(h2)}}, []string{h1, h2}},
		{"lookalikes ignored", lookalikes, nil},
		{"root array", []any{refObj(h2), refObj(h1)}, []string{h2, h1}},
		{"root ref", refObj(h1), []string{h1}},
		{"raw message", json.RawMessage(`{"p":{"$secret":"` + h1 + `"},"q":[{"$secret":"` + h2 + `"}]}`), []string{h1, h2}},
		{"bytes", []byte(`{"p":{"$secret":"` + h1 + `"}}`), []string{h1}},
		{"invalid raw", json.RawMessage(`{"p":`), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Find(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Find = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindDeterministicOrder(t *testing.T) {
	args := map[string]any{"z": refObj(h1), "a": refObj(h2), "m": refObj(h3)}
	want := []string{h2, h3, h1} // sorted by key: a, m, z
	for range 20 {
		if got := Find(args); !reflect.DeepEqual(got, want) {
			t.Fatalf("Find = %v, want %v", got, want)
		}
	}
}

func TestFindRaw(t *testing.T) {
	got, err := FindRaw(json.RawMessage(`{"x":{"$secret":"` + h1 + `"}}`))
	if err != nil || !reflect.DeepEqual(got, []string{h1}) {
		t.Fatalf("FindRaw = %v, %v", got, err)
	}
	if got, err := FindRaw(nil); err != nil || got != nil {
		t.Fatalf("FindRaw(nil) = %v, %v", got, err)
	}
	if got, err := FindRaw(json.RawMessage(`null`)); err != nil || got != nil {
		t.Fatalf("FindRaw(null) = %v, %v", got, err)
	}
	if _, err := FindRaw(json.RawMessage(`{"x":`)); err == nil {
		t.Fatal("FindRaw(invalid) err = nil")
	}
}

func TestFindWithPaths(t *testing.T) {
	args := map[string]any{
		"password": refObj(h1),
		"opts":     map[string]any{"a/b": refObj(h2), "t~x": []any{"s", refObj(h3)}},
		"dup":      refObj(h1),
	}
	got := FindWithPaths(args)
	want := []Location{
		{Handle: h1, Arg: "dup", Pointer: "/dup"},
		{Handle: h2, Arg: "opts", Pointer: "/opts/a~1b"},
		{Handle: h3, Arg: "opts", Pointer: "/opts/t~0x/1"},
		{Handle: h1, Arg: "password", Pointer: "/password"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FindWithPaths =\n%#v\nwant\n%#v", got, want)
	}
	for _, l := range got {
		if top := l.TopLevel(); top != (l.Pointer == "/"+l.Arg) {
			t.Errorf("%+v TopLevel = %v", l, top)
		}
	}

	if got := FindWithPaths(refObj(h1)); !reflect.DeepEqual(got, []Location{{Handle: h1, Arg: "", Pointer: ""}}) {
		t.Fatalf("root ref = %#v", got)
	}
	if got := FindWithPaths([]any{refObj(h1)}); !reflect.DeepEqual(got, []Location{{Handle: h1, Arg: "", Pointer: "/0"}}) {
		t.Fatalf("root array = %#v", got)
	}
	raw := json.RawMessage(`{"password":{"$secret":"` + h1 + `"}}`)
	if got := FindWithPaths(raw); !reflect.DeepEqual(got, []Location{{Handle: h1, Arg: "password", Pointer: "/password"}}) {
		t.Fatalf("raw = %#v", got)
	}
}

func TestBoundTo(t *testing.T) {
	args := map[string]any{"password": refObj(h1), "nested": map[string]any{"password": refObj(h2)}}
	locs := FindWithPaths(args)
	byHandle := map[string]Location{}
	for _, l := range locs {
		byHandle[l.Handle] = l
	}
	if !byHandle[h1].BoundTo("password") {
		t.Error("h1 at /password should be bound to password")
	}
	if byHandle[h1].BoundTo("user") {
		t.Error("h1 should not be bound to user")
	}
	if byHandle[h2].BoundTo("password") || byHandle[h2].BoundTo("nested") {
		t.Error("nested ref is not at a top-level argument")
	}
	if (Location{Handle: h1}).BoundTo("") {
		t.Error("root ref must not match empty arg")
	}
}

func cloneJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReplace(t *testing.T) {
	values := map[string]string{h1: "hunter2-password", h2: "s3cr3t-token-value"}
	in := map[string]any{
		"password": refObj(h1),
		"user":     "bob",
		"n":        3.0,
		"list":     []any{refObj(h2), map[string]any{"deep": refObj(h1)}, true, nil},
		"look":     map[string]any{Key: h3, "x": 1.0},
	}
	before := cloneJSON(t, in)

	got, err := Replace(in, values)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	want := map[string]any{
		"password": "hunter2-password",
		"user":     "bob",
		"n":        3.0,
		"list":     []any{"s3cr3t-token-value", map[string]any{"deep": "hunter2-password"}, true, nil},
		"look":     map[string]any{Key: h3, "x": 1.0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Replace =\n%#v\nwant\n%#v", got, want)
	}
	if !reflect.DeepEqual(cloneJSON(t, in), before) {
		t.Fatal("Replace mutated its input")
	}
	// The copy shares no containers with the input.
	got.(map[string]any)["look"].(map[string]any)["x"] = 99.0
	got.(map[string]any)["list"].([]any)[2] = false
	if !reflect.DeepEqual(cloneJSON(t, in), before) {
		t.Fatal("Replace result aliases its input")
	}
}

func TestReplaceUnknownHandle(t *testing.T) {
	in := map[string]any{"a": refObj(h1), "b": refObj(h2)}
	_, err := Replace(in, map[string]string{h1: "value-one-long"})
	if !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("err = %v, want ErrUnknownHandle", err)
	}
	if strings.Contains(err.Error(), "value-one-long") {
		t.Fatalf("error leaks a value: %v", err)
	}
	if _, err := Replace(in, nil); !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("nil values err = %v", err)
	}
}

func TestReplaceNoRefs(t *testing.T) {
	in := map[string]any{"a": "x", "b": []any{1.0}}
	got, err := Replace(in, nil)
	if err != nil || !reflect.DeepEqual(got, in) {
		t.Fatalf("Replace = %v, %v", got, err)
	}
	if got, err := Replace(nil, nil); err != nil || got != nil {
		t.Fatalf("Replace(nil) = %v, %v", got, err)
	}
}

func TestReplaceRaw(t *testing.T) {
	in := json.RawMessage(`{"password":{"$secret":"` + h1 + `"},"n":12345678901234567890}`)
	orig := append(json.RawMessage(nil), in...)
	got, err := Replace(in, map[string]string{h1: `pa"ss\word`})
	if err != nil {
		t.Fatalf("Replace raw: %v", err)
	}
	raw, ok := got.(json.RawMessage)
	if !ok {
		t.Fatalf("Replace raw returned %T", got)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["password"] != `pa"ss\word` {
		t.Fatalf("password = %v", m["password"])
	}
	if !strings.Contains(string(raw), "12345678901234567890") {
		t.Fatalf("number precision lost: %s", raw)
	}
	if string(in) != string(orig) {
		t.Fatal("raw input mutated")
	}
	if _, err := Replace(json.RawMessage(`{`), nil); err == nil {
		t.Fatal("invalid raw: err = nil")
	}
}

func TestReplaceArgs(t *testing.T) {
	in := map[string]any{"password": refObj(h1)}
	got, err := ReplaceArgs(in, map[string]string{h1: "plain-text-value"})
	if err != nil || got["password"] != "plain-text-value" {
		t.Fatalf("ReplaceArgs = %v, %v", got, err)
	}
	if _, ok := in["password"].(map[string]any); !ok {
		t.Fatal("ReplaceArgs mutated input")
	}
	if _, err := ReplaceArgs(refObj(h1), map[string]string{h1: "plain-text-value"}); !errors.Is(err, ErrRootRef) {
		t.Fatalf("root ref err = %v", err)
	}
	if got, err := ReplaceArgs(nil, nil); err != nil || got != nil {
		t.Fatalf("ReplaceArgs(nil) = %v, %v", got, err)
	}
}

func TestReplaceWithHandle(t *testing.T) {
	in := map[string]any{
		"password": refObj(h1),
		"list":     []any{refObj(h2), map[string]any{Key: h3, "x": 1.0}},
	}
	before := cloneJSON(t, in)
	got := ReplaceWithHandle(in)
	want := map[string]any{
		"password": h1,
		"list":     []any{h2, map[string]any{Key: h3, "x": 1.0}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReplaceWithHandle = %#v", got)
	}
	if !reflect.DeepEqual(cloneJSON(t, in), before) {
		t.Fatal("ReplaceWithHandle mutated input")
	}
	gm := ReplaceArgsWithHandle(in)
	if !reflect.DeepEqual(gm, want) {
		t.Fatalf("ReplaceArgsWithHandle = %#v", gm)
	}
	if ReplaceArgsWithHandle(nil) != nil {
		t.Fatal("ReplaceArgsWithHandle(nil) != nil")
	}
}

func TestFingerprint(t *testing.T) {
	word := regexp.MustCompile(`^[a-z]+(-[a-z]+){3}$`)
	if a, b := Fingerprint(h1), Fingerprint(h1); a != b {
		t.Fatalf("not deterministic: %q vs %q", a, b)
	}
	if Fingerprint(h1) == Fingerprint(h2) {
		t.Fatal("h1 and h2 share a fingerprint")
	}
	seen := map[string]int{}
	for range 1000 {
		h, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		fp := Fingerprint(h)
		if !word.MatchString(fp) {
			t.Fatalf("Fingerprint = %q", fp)
		}
		seen[fp]++
	}
	if dup := 1000 - len(seen); dup > 2 {
		t.Fatalf("%d fingerprint collisions in 1000 handles", dup)
	}
}

func TestWordlist(t *testing.T) {
	if len(words) < 256 {
		t.Fatalf("wordlist has %d words, want >= 256", len(words))
	}
	re := regexp.MustCompile(`^[a-z]{3,7}$`)
	seen := map[string]bool{}
	for _, w := range words {
		if !re.MatchString(w) {
			t.Errorf("bad word %q", w)
		}
		if seen[w] {
			t.Errorf("duplicate word %q", w)
		}
		seen[w] = true
	}
}
