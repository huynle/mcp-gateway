package navtest

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/static"
)

// AssertShell fails t unless body is a full portal page built on the shared
// shell (package nav's "page.head" and nav bar): the shared stylesheet and
// the render-blocking theme script by their versioned URLs, the theme
// toggle, a <main> content column and no page-local <style> block. Every
// module's page tests call it, so a module that drifts from the shared
// look fails its own tests.
func AssertShell(t testing.TB, what, body string) {
	t.Helper()
	for _, p := range ShellProblems(body) {
		t.Errorf("%s: %s", what, p)
	}
}

// ShellProblems lists what AssertShell would report (nil when the page is
// on the shared shell).
func ShellProblems(body string) []string {
	css, err := static.URL("portal.css")
	if err != nil {
		return []string{err.Error()}
	}
	js, err := static.URL("theme.js")
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	for _, c := range []struct{ want, why string }{
		{`<html lang="en">`, "no <html lang=\"en\">"},
		{`<link rel="stylesheet" href="` + css + `">`, "does not link the shared stylesheet " + css},
		{`<script src="` + js + `"></script>`, "does not load the theme script " + js + " (render-blocking, in <head>)"},
		{`data-theme-toggle`, "has no theme toggle"},
		{`<main`, "has no <main> content column"},
	} {
		if !strings.Contains(body, c.want) {
			out = append(out, c.why)
		}
	}
	if head, _, ok := strings.Cut(body, "</head>"); !ok || !strings.Contains(head, `<script src="`+js+`"`) {
		out = append(out, "theme script is not inside <head>")
	}
	if strings.Contains(body, "<style") {
		out = append(out, "has a page-local <style> block (styles belong in static/portal.css)")
	}
	return out
}
