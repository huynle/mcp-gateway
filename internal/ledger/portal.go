package ledger

import (
	"bytes"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// Identity resolves the caller of a portal page: the session's user ID
// (empty when not signed in) and its CSRF token. The portal module
// supplies it so this package never touches sessions.
type Identity func(r *http.Request) (userID, csrfToken string)

//go:embed templates/*.html
var templateFS embed.FS

// HistoryLimit is how many operations the page shows.
const HistoryLimit = 50

// Portal serves GET /operations: the user's recent writes with their
// state and result identifiers, and the "verify in the app" hint for
// unresolved ones. It is mounted behind the portal's signed-in check
// (MountUser) and still refuses anonymous callers itself.
type Portal struct {
	svc *Service
	who Identity
	log *slog.Logger
	tpl *template.Template
}

// NewPortal builds the page.
func NewPortal(svc *Service, who Identity, log *slog.Logger) *Portal {
	if log == nil {
		log = slog.Default()
	}
	tpl := template.Must(template.New("").Funcs(template.FuncMap{
		"fmtTime": fmtTime,
		"shortID": func(id string) string { return id[:min(8, len(id))] },
		"isURL":   func(v string) bool { return strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://") },
	}).ParseFS(templateFS, "templates/*.html"))
	return &Portal{svc: svc, who: who, log: log, tpl: tpl}
}

// Mount registers the route through mount (portal.MountUser or a
// ServeMux's Handle).
func (p *Portal) Mount(mount func(pattern string, handler http.Handler)) {
	mount("GET /operations", http.HandlerFunc(p.list))
}

type caller struct {
	UserID    string
	CSRFToken string
}

type listData struct {
	Title      string
	Caller     caller
	Operations []Operation
	Limit      int
}

func (p *Portal) list(w http.ResponseWriter, r *http.Request) {
	userID, csrfToken := p.who(r)
	if userID == "" {
		http.Error(w, "sign in to see your operations", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ops, err := p.svc.Operations(r.Context(), userID, HistoryLimit)
	if err != nil {
		p.log.Error("operations page failed", "event", "ledger.page_failed", "path", r.URL.Path,
			"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
		http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	data := listData{Title: "Operations", Caller: caller{UserID: userID, CSRFToken: csrfToken}, Operations: ops, Limit: HistoryLimit}
	if err := p.tpl.ExecuteTemplate(&buf, "operations.html", data); err != nil {
		p.log.Error("operations page failed", "event", "ledger.page_failed", "what", "render", "error", observability.RedactError(err))
		http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}

// fmtTime formats a time.Time or *time.Time in UTC.
func fmtTime(v any) string {
	switch t := v.(type) {
	case time.Time:
		return t.UTC().Format("2006-01-02 15:04")
	case *time.Time:
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04")
	}
	return ""
}
