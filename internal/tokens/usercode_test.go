package tokens_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/tokens"
)

func TestUserCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c, err := tokens.NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("user code %q", c)
		}
		for _, r := range strings.ReplaceAll(c, "-", "") {
			if !strings.ContainsRune(tokens.UserCodeAlphabet, r) {
				t.Fatalf("user code %q has %q outside the alphabet", c, r)
			}
		}
		seen[c] = true
		n, ok := tokens.NormalizeUserCode(" " + strings.ToLower(c[:4]) + " " + c[5:])
		if !ok || n != strings.ReplaceAll(c, "-", "") {
			t.Fatalf("normalize(%q) = %q, %v", c, n, ok)
		}
		if tokens.FormatUserCode(n) != c {
			t.Fatalf("format(%q) = %q", n, tokens.FormatUserCode(n))
		}
	}
	if len(seen) < 190 {
		t.Fatalf("only %d distinct codes in 200", len(seen))
	}
	for _, bad := range []string{"", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ1", "BCDF GHJK X", "BCDF-GHJ0", "BCDF-GHJO", "BCDF-GHJI"} {
		if _, ok := tokens.NormalizeUserCode(bad); ok {
			t.Errorf("normalize(%q) accepted", bad)
		}
	}
	if strings.ContainsAny(tokens.UserCodeAlphabet, "AEIOUY01") || tokens.UserCodeLen != 8 {
		t.Fatalf("alphabet %q / length %d", tokens.UserCodeAlphabet, tokens.UserCodeLen)
	}
}
