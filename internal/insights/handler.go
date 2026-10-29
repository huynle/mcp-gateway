package insights

import (
	"bytes"
	"context"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
)

//go:embed templates/_charts.html
var partial string

//go:embed templates/admin.html
var adminFS embed.FS

// Setup parses the "insights.charts" template into t (a module's set,
// already through nav.Setup, since the partial uses asset and icon) and
// returns t: template.Must(insights.Setup(nav.Setup(template.New("")))).
func Setup(t *template.Template) (*template.Template, error) {
	if _, err := t.New("insights.partial").Parse(partial); err != nil {
		return nil, err
	}
	return t, nil
}

// Loader builds a user's dashboard for a page; Source.Activity and
// Source.Operations are Loaders.
type Loader func(ctx context.Context, userID string, r Range, u *url.URL) (*Dashboard, error)

// ForUser runs load for the request: the range comes from the query
// (an invalid one is returned as the error, for a 400), and a load failure is
// logged and returned as a Dashboard with Failed set so the page still
// renders its table. A nil load returns nil (the page has no charts).
func ForUser(r *http.Request, load Loader, userID string, log *slog.Logger) (*Dashboard, error) {
	if load == nil {
		return nil, nil
	}
	rng, err := ParseRange(r.URL.Query().Get(RangeParam))
	if err != nil {
		return nil, err
	}
	d, err := load(r.Context(), userID, rng, r.URL)
	if err != nil {
		return failed(r, rng, err, log), nil
	}
	return d, nil
}

func failed(r *http.Request, rng Range, err error, log *slog.Logger) *Dashboard {
	if log == nil {
		log = slog.Default()
	}
	rid := observability.RequestIDFromContext(r.Context())
	log.ErrorContext(r.Context(), "insights failed", "event", "insights.load_failed", "path", r.URL.Path,
		"request_id", rid, "error", observability.RedactError(err))
	return &Dashboard{Title: "Insights", Range: rng, RangeLinks: RangeLinksFor(r.URL, rng), Failed: true, RequestID: rid}
}

// Identity resolves the caller of the admin page: the session user's ID
// (empty when not signed in) and whether that user is an admin.
type Identity func(r *http.Request) (userID string, isAdmin bool)

// AdminLoader builds the admin dashboard; Source.Admin is one.
type AdminLoader func(ctx context.Context, r Range, u *url.URL) (*Dashboard, error)

// AdminHandler serves GET /admin/insights: every user's activity. It is
// mounted behind the portal's admin check and checks again itself.
func AdminHandler(load AdminLoader, who Identity, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	tpl := template.Must(template.Must(Setup(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
	}))).ParseFS(adminFS, "templates/admin.html"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		userID, isAdmin := who(r)
		if userID == "" {
			http.Error(w, "sign in", http.StatusUnauthorized)
			return
		}
		if !isAdmin {
			http.Error(w, "admin only", http.StatusForbidden)
			return
		}
		rng, err := ParseRange(r.URL.Query().Get(RangeParam))
		if err != nil {
			http.Error(w, "invalid query: "+err.Error(), http.StatusBadRequest)
			return
		}
		d, err := load(r.Context(), rng, r.URL)
		if err != nil {
			d = failed(r, rng, err, log)
		}
		var buf bytes.Buffer
		if err := nav.Execute(tpl, r, &buf, "admin.html", d); err != nil {
			log.ErrorContext(r.Context(), "insights page failed", "event", "insights.render_failed", "error", observability.RedactError(err))
			http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = buf.WriteTo(w)
	})
}
