package static_test

import (
	"io/fs"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/static"
)

// The palette contract of portal.css: colours are custom properties set
// once for light (:root), once for dark (:root[data-theme="dark"]) and a
// copy of dark for the system preference unless the user picked light.
const (
	lightSel  = `:root {`
	darkSel   = `:root[data-theme="dark"] {`
	systemSel = `@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {`
)

var varRE = regexp.MustCompile(`(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;`)

func css(t *testing.T) string {
	t.Helper()
	b, err := fs.ReadFile(static.FS, "portal.css")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// block returns the custom properties of the first rule opened by sel.
func block(t *testing.T, src, sel string) map[string]string {
	t.Helper()
	_, rest, ok := strings.Cut(src, sel)
	if !ok {
		t.Fatalf("portal.css has no %q rule", sel)
	}
	body, _, _ := strings.Cut(rest, "}")
	out := map[string]string{}
	for _, m := range varRE.FindAllStringSubmatch(body, -1) {
		out[m[1]] = strings.ToLower(m[2])
	}
	if len(out) == 0 {
		t.Fatalf("%q defines no colours", sel)
	}
	return out
}

func luminance(hex string) float64 {
	ch := func(i int) float64 {
		v, _ := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(0) + 0.7152*ch(1) + 0.0722*ch(2)
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func TestPalettesDefineTheSameColours(t *testing.T) {
	src := css(t)
	light, dark, system := block(t, src, lightSel), block(t, src, darkSel), block(t, src, systemSel)
	if l, d := slices.Sorted(maps.Keys(light)), slices.Sorted(maps.Keys(dark)); !slices.Equal(l, d) {
		t.Errorf("light defines %v, dark %v", l, d)
	}
	if !maps.Equal(dark, system) {
		t.Errorf("system-dark copy drifted from the dark palette:\ndark   %v\nsystem %v", dark, system)
	}
}

// WCAG 2.1 AA: 4.5:1 for text (body, muted, links, status colours, chips,
// primary-button label), 3:1 for UI component edges (input borders, the
// focus ring), on every background text sits on (page, panels and inputs,
// sidebar / table head surface), and status text on its tinted fill.
func TestPalettesMeetContrast(t *testing.T) {
	src := css(t)
	for name, p := range map[string]map[string]string{"light": block(t, src, lightSel), "dark": block(t, src, darkSel)} {
		check := func(fg, bg string, min float64) {
			a, b := p[fg], p[bg]
			if a == "" || b == "" {
				t.Errorf("%s: %s or %s undefined", name, fg, bg)
				return
			}
			if c := contrast(a, b); c < min {
				t.Errorf("%s: %s %s on %s %s = %.2f:1, want >= %.1f", name, fg, a, bg, b, c, min)
			}
		}
		for _, bg := range []string{"--bg", "--panel", "--surface"} {
			for _, fg := range []string{"--fg", "--muted", "--accent", "--danger", "--ok", "--warn"} {
				check(fg, bg, 4.5)
			}
			check("--input-border", bg, 3)
			check("--focus", bg, 3)
		}
		check("--accent-fg", "--accent", 4.5)
		check("--danger-fg", "--danger", 4.5)
		// Status text on its own tinted fill (callouts, badges, the
		// current tab/segment).
		for _, tone := range []string{"accent", "danger", "ok", "warn"} {
			check("--"+tone, "--"+tone+"-soft", 4.5)
			check("--fg", "--"+tone+"-soft", 4.5)
		}
	}
}

// Picking light must win over a dark system preference: the system-dark
// rule excludes data-theme="light", and the explicit dark rule exists.
func TestThemeAttributeOverridesSystem(t *testing.T) {
	src := css(t)
	for _, want := range []string{systemSel, darkSel, `color-scheme: dark`, `color-scheme: light`} {
		if !strings.Contains(src, want) {
			t.Errorf("portal.css lacks %q", want)
		}
	}
}
