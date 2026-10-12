package static_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/static"
)

// Every served asset gets a URL whose ?v= is derived from its bytes, so a
// deploy that changes a file changes its URL and browsers skip the 1-day
// cached copy.
func TestURLCarriesAContentHash(t *testing.T) {
	for _, name := range []string{"htmx.min.js", "review.js", "review.css", "portal.css", "theme.js"} {
		b, err := fs.ReadFile(static.FS, name)
		if err != nil {
			t.Fatalf("%s not embedded: %v", name, err)
		}
		sum := sha256.Sum256(b)
		want := "/static/" + name + "?v=" + hex.EncodeToString(sum[:])[:static.HashLen]
		got, err := static.URL(name)
		if err != nil || got != want {
			t.Errorf("URL(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
}

func TestURLRejectsUnknownAssets(t *testing.T) {
	for _, name := range []string{"", "nope.css", "../static.go", "static.go"} {
		if got, err := static.URL(name); err == nil {
			t.Errorf("URL(%q) = %q, want an error", name, got)
		}
	}
}

func TestURLIsStableAndShort(t *testing.T) {
	a, _ := static.URL("portal.css")
	b, _ := static.URL("portal.css")
	if a != b {
		t.Errorf("URL not stable: %q vs %q", a, b)
	}
	if !regexp.MustCompile(`^/static/portal\.css\?v=[0-9a-f]{12}$`).MatchString(a) {
		t.Errorf("URL shape = %q", a)
	}
}

// The Go sources of this package are not served.
func TestFSHoldsOnlyAssets(t *testing.T) {
	_ = fs.WalkDir(static.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(path, ".go") {
			t.Errorf("FS serves %s", path)
		}
		return nil
	})
}
