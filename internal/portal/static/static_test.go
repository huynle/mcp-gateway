package static_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/png"
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
	for _, name := range []string{"htmx.min.js", "review.js", "review.css", "portal.css", "theme.js", "copy.js", "pwa.js",
		"icons/icon-192.png", "icons/icon-512.png", "icons/icon-maskable-512.png", "icons/apple-touch-icon.png"} {
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

// portal.css loads the web fonts by relative URL (/static/fonts/…); each
// must be embedded, or the page silently falls back to system fonts.
func TestFontsReferencedByTheStylesheetAreEmbedded(t *testing.T) {
	b, err := fs.ReadFile(static.FS, "portal.css")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`url\("(fonts/[^"]+)"\)`).FindAllStringSubmatch(string(b), -1)
	if len(refs) == 0 {
		t.Fatal("portal.css references no fonts")
	}
	for _, m := range refs {
		if _, err := fs.Stat(static.FS, m[1]); err != nil {
			t.Errorf("portal.css references %s: %v", m[1], err)
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

// The installable-app icons (rendered by scripts/render-pwa-icons.py) are
// PNGs of their declared size; the iOS home-screen icon is opaque (iOS
// shows transparency as black) and so is the maskable one (full bleed).
func TestAppIcons(t *testing.T) {
	for _, c := range []struct {
		name   string
		size   int
		opaque bool
	}{
		{"icons/icon-192.png", 192, false},
		{"icons/icon-512.png", 512, false},
		{"icons/icon-maskable-512.png", 512, true},
		{"icons/apple-touch-icon.png", 180, true},
	} {
		b, err := fs.ReadFile(static.FS, c.name)
		if err != nil {
			t.Errorf("%s not embedded: %v", c.name, err)
			continue
		}
		img, err := png.Decode(bytes.NewReader(b))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if img.Bounds() != image.Rect(0, 0, c.size, c.size) {
			t.Errorf("%s: bounds %v, want %dx%d", c.name, img.Bounds(), c.size, c.size)
		}
		if c.opaque {
			if o, ok := img.(interface{ Opaque() bool }); !ok || !o.Opaque() {
				t.Errorf("%s has transparent pixels", c.name)
			}
		}
	}
}

// The service worker source is embedded for the portal's /sw.js handler
// but is not a /static/ asset (its placeholders are filled per build and
// it must be served from the root for scope "/").
func TestServiceWorkerSourceIsEmbeddedButNotServed(t *testing.T) {
	if len(static.ServiceWorker) == 0 {
		t.Fatal("ServiceWorker is empty")
	}
	if _, err := fs.Stat(static.FS, "sw.js"); err == nil {
		t.Error("sw.js is in FS (served under /static/)")
	}
	if _, err := static.URL("sw.js"); err == nil {
		t.Error("URL(sw.js) succeeded")
	}
}
