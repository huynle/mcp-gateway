package ref

import (
	"encoding/json"
	"errors"
	"testing"
)

// FuzzFindReplace feeds arbitrary bytes through every entry point: none may
// panic, and on valid JSON a full value map makes Replace succeed and leave
// no refs behind.
func FuzzFindReplace(f *testing.F) {
	for _, s := range []string{
		``, `null`, `{}`, `[]`, `"x"`, `1e400`, `{"a":`,
		`{"password":{"$secret":"` + h1 + `"}}`,
		`{"a":[{"$secret":"` + h1 + `"},{"$secret":"` + h2 + `","x":1}],"b":{"c":{"$secret":7}}}`,
		`{"$secret":"` + h1 + `"}`,
		`[{"$secret":"` + h3 + `"}] trailing`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		raw := json.RawMessage(data)
		handles := Find(raw)
		_ = FindWithPaths(raw)
		_, rawErr := FindRaw(raw)
		_ = ReplaceWithHandle(raw)

		values := map[string]string{}
		for _, h := range handles {
			values[h] = "plaintext-" + h
		}
		out, err := Replace(raw, values)
		if rawErr != nil {
			if err == nil {
				t.Fatalf("Replace accepted input FindRaw rejected: %q", data)
			}
			return
		}
		if err != nil {
			t.Fatalf("Replace with all values: %v", err)
		}
		if left := Find(out); len(left) != 0 {
			t.Fatalf("refs left after Replace: %v", left)
		}
		if len(handles) > 0 {
			if _, err := Replace(raw, nil); !errors.Is(err, ErrUnknownHandle) {
				t.Fatalf("Replace without values err = %v", err)
			}
		}
		var tree any
		if json.Unmarshal(data, &tree) == nil {
			_ = Find(tree)
			_, _ = Replace(tree, values)
			_ = ReplaceWithHandle(tree)
			if m, ok := tree.(map[string]any); ok {
				_, _ = ReplaceArgs(m, values)
				_ = ReplaceArgsWithHandle(m)
			}
		}
	})
}
