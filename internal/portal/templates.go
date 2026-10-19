package portal

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"slices"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/portal/static"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Templates are embedded so the portal ships inside the single gateway
// binary (decision 7datr7x4); the static assets live in package static.
//
//go:embed templates/*.html
var templateFS embed.FS

// page is the data every template receives.
type page struct {
	Principal *identity.Principal
	Nav       nav.Data
	Data      any
}

// userRow is the data for the admin user row fragment.
type userRow struct {
	Principal *identity.Principal
	User      identity.UserSummary
	Roles     []store.Role
	Limits    bool // link the user's resource limits page
	// Deletable shows the Delete link (an account service is wired).
	Deletable bool
}

type templates struct {
	pages map[string]*template.Template
}

// parseTemplates builds one template set per page: the layout plus the
// page file, so pages can define "title" and "content" independently.
func parseTemplates() (*templates, error) {
	funcs := template.FuncMap{
		nav.AssetFuncName: static.URL,
		"hasRole":         slices.Contains[[]string, string],
		"userRow": func(p page, u identity.UserSummary) userRow {
			d, _ := p.Data.(adminUsersData) // also the invite-created page
			return userRow{Principal: p.Principal, User: u, Roles: d.Roles, Limits: d.Limits, Deletable: d.Deletable}
		},
	}
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	t := &templates{pages: map[string]*template.Template{}}
	for _, name := range names {
		base := name[len("templates/"):]
		if base == "layout.html" {
			continue
		}
		tmpl, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", name)
		if err != nil {
			return nil, fmt.Errorf("portal: parse %s: %w", name, err)
		}
		if _, err := nav.Add(tmpl); err != nil {
			return nil, fmt.Errorf("portal: parse nav: %w", err)
		}
		t.pages[base] = tmpl
	}
	return t, nil
}

// render writes a full page (layout + page) or, when fragment is set, just
// that named template. Output is buffered so a template error never
// produces a half-written page.
func (t *templates) render(w http.ResponseWriter, status int, name, fragment string, data any) error {
	tmpl, ok := t.pages[name]
	if !ok {
		return fmt.Errorf("portal: unknown template %q", name)
	}
	var buf bytes.Buffer
	var err error
	if fragment != "" {
		err = tmpl.ExecuteTemplate(&buf, fragment, data)
	} else {
		err = tmpl.Execute(&buf, data)
	}
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, err = buf.WriteTo(w)
	return err
}
