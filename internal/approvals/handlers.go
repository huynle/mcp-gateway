package approvals

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/portal/nav"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// Identity resolves the caller of a portal page: the session's user ID
// (empty when not signed in) and its CSRF token, which the forms echo. The
// portal module supplies it so this package never touches sessions.
type Identity func(r *http.Request) (userID, csrfToken string)

//go:embed templates/*.html
var templateFS embed.FS

// HistoryLimit is how many approvals the history page shows.
const HistoryLimit = 50

// Portal serves the self-service approval pages:
//
//	GET  /approvals               pending approvals with the decrypted
//	                              argument summary, expiry countdown and
//	                              approve/deny buttons; htmx polls it
//	                              every 5 s
//	POST /approvals/{id}/approve  approve, back to the list
//	POST /approvals/{id}/deny     deny, back to the list
//	GET  /approvals/history       last HistoryLimit approvals, no payload
//
// It is mounted behind the portal's signed-in and CSRF checks (MountUser)
// and still refuses anonymous callers itself.
type Portal struct {
	svc *Service
	who Identity
	log *slog.Logger
	tpl *template.Template
}

// NewPortal builds the pages.
func NewPortal(svc *Service, who Identity, log *slog.Logger) *Portal {
	if log == nil {
		log = slog.Default()
	}
	tpl := template.Must(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"fmtTime":   fmtTime,
		"expiresIn": expiresIn,
		"shortID":   func(id string) string { return id[:min(8, len(id))] },
	}).ParseFS(templateFS, "templates/*.html"))
	return &Portal{svc: svc, who: who, log: log, tpl: tpl}
}

// Mount registers the routes through mount (portal.MountUser or a
// ServeMux's Handle).
func (p *Portal) Mount(mount func(pattern string, handler http.Handler)) {
	mount("GET /approvals", p.withUser(p.list))
	mount("GET /approvals/history", p.withUser(p.history))
	mount("POST /approvals/{id}/approve", p.withUser(p.decide(StatusApproved)))
	mount("POST /approvals/{id}/deny", p.withUser(p.decide(StatusDenied)))
}

// caller is the signed-in user as the templates see them.
type caller struct {
	UserID    string
	CSRFToken string
}

type handler func(w http.ResponseWriter, r *http.Request, c caller)

func (p *Portal) withUser(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, csrfToken := p.who(r)
		if userID == "" {
			http.Error(w, "sign in to see your approvals", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r, caller{UserID: userID, CSRFToken: csrfToken})
	})
}

type listData struct {
	Title   string
	Caller  caller
	Pending []Pending
	Now     time.Time
	Decided string
}

func (p *Portal) list(w http.ResponseWriter, r *http.Request, c caller) {
	data, err := p.listData(r, c)
	if err != nil {
		p.fail(w, r, "list approvals", err)
		return
	}
	p.render(w, r, http.StatusOK, "list.html", "", data)
}

func (p *Portal) listData(r *http.Request, c caller) (listData, error) {
	pending, err := p.svc.Pending(r.Context(), c.UserID)
	if err != nil {
		return listData{}, err
	}
	decided := r.URL.Query().Get("decided")
	switch decided {
	case "approved", "denied", "already":
	default:
		decided = ""
	}
	return listData{Title: "Approvals", Caller: c, Pending: pending, Now: p.svc.now(), Decided: decided}, nil
}

// decide is the approve/deny handler. A plain form submission goes back
// to the list with a notice; an htmx request gets the refreshed pending
// fragment. A decision that is no longer possible (already decided, used
// or expired) is a notice, not an error; an approval the user cannot see
// is a 404.
func (p *Portal) decide(status string) handler {
	return func(w http.ResponseWriter, r *http.Request, c caller) {
		id := r.PathValue("id")
		var err error
		if status == StatusApproved {
			_, err = p.svc.Approve(r.Context(), c.UserID, id)
		} else {
			_, err = p.svc.Deny(r.Context(), c.UserID, id)
		}
		outcome := status
		switch {
		case errors.Is(err, ErrNotFound) || isBadUUID(err):
			http.Error(w, "no such approval", http.StatusNotFound)
			return
		case errors.Is(err, ErrNotPending):
			outcome = "already"
		case err != nil:
			p.fail(w, r, status+" approval", err)
			return
		}
		if r.Header.Get("HX-Request") == "true" {
			data, err := p.listData(r, c)
			if err != nil {
				p.fail(w, r, "list approvals", err)
				return
			}
			p.render(w, r, http.StatusOK, "list.html", "pending", data)
			return
		}
		http.Redirect(w, r, "/approvals?decided="+outcome, http.StatusSeeOther)
	}
}

type historyData struct {
	Title   string
	Caller  caller
	History []Approval
	Limit   int
}

func (p *Portal) history(w http.ResponseWriter, r *http.Request, c caller) {
	hist, err := p.svc.History(r.Context(), c.UserID, HistoryLimit)
	if err != nil {
		p.fail(w, r, "approval history", err)
		return
	}
	p.render(w, r, http.StatusOK, "history.html", "", historyData{Title: "Approval history", Caller: c, History: hist, Limit: HistoryLimit})
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

// expiresIn renders the time left as "14m 59s" / "32s" / "expired".
func expiresIn(at, now time.Time) string {
	d := at.Sub(now).Round(time.Second)
	if d <= 0 {
		return "expired"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
}

// isBadUUID recognises PostgreSQL's complaint about an id that is not a
// uuid (invalid_text_representation, 22P02): for the portal that is "no
// such approval", not a server error.
func isBadUUID(err error) bool {
	return err != nil && strings.Contains(err.Error(), "22P02")
}

func (p *Portal) render(w http.ResponseWriter, r *http.Request, status int, name, fragment string, data any) {
	var buf bytes.Buffer
	if fragment == "" {
		fragment = name
	}
	if err := nav.Execute(p.tpl, r, &buf, fragment, data); err != nil {
		p.fail(w, r, "render "+name, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (p *Portal) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.log.Error("approval page failed", "event", "approvals.page_failed", "what", what, "path", r.URL.Path,
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}
