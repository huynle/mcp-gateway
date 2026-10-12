package portal_test

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

// The portal's own pages (and its 404) are built on the shared shell.
func TestPortalPagesUseTheSharedShell(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.session(t, adminSub, "Admin")
	for _, path := range []string{"/account", "/admin/users", "/no-such-page"} {
		body := h.do(t, request{method: http.MethodGet, path: path, cookie: admin}).Body.String()
		navtest.AssertShell(t, path, body)
	}
	navtest.AssertShell(t, "/signin", h.do(t, request{method: http.MethodGet, path: "/signin"}).Body.String())
}

// Every module's templates that open a <head> include the shared
// "page.head" and render the shared nav; none carries its own <style>.
// This walks every templates/ directory under internal/, so a new module
// that copies an old layout fails here even before it has page tests.
func TestEveryLayoutUsesTheSharedHead(t *testing.T) {
	root := filepath.Join("..")
	var layouts int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".html" || filepath.Base(filepath.Dir(path)) != "templates" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		if strings.Contains(src, "<style") {
			t.Errorf("%s has a <style> block; put rules in internal/portal/static/portal.css", path)
		}
		if strings.Contains(src, " style=") {
			t.Errorf("%s has an inline style attribute; use a class from portal.css", path)
		}
		if !strings.Contains(src, "<head>") {
			return nil
		}
		layouts++
		for _, want := range []string{`{{template "page.head"}}`, `{{template "nav" `, "<main"} {
			if !strings.Contains(src, want) {
				t.Errorf("%s opens <head> without %s", path, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if layouts < 9 {
		t.Errorf("found %d layouts, want at least 9 (one per module)", layouts)
	}
}
