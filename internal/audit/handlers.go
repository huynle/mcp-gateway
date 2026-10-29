package audit

import (
	"context"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/huynle/mcp-gateway/internal/insights"
	"github.com/huynle/mcp-gateway/internal/portal/nav"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// Identity resolves the caller of a portal page: the user ID of the session
// (empty when not signed in) and whether that user is an admin. The portal
// module supplies it so this package never touches sessions or cookies.
type Identity func(r *http.Request) (userID string, isAdmin bool)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.Must(insights.Setup(nav.Setup(template.New("")).Funcs(template.FuncMap{
	"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05Z") },
	"fmtDur":  func(d time.Duration) string { return d.String() },
}))).ParseFS(templateFS, "templates/*.html"))

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// page is the template data for both pages.
type page struct {
	Title    string
	Admin    bool
	Rows     []Record
	Filter   Filter
	PageNum  int
	PrevLink string
	NextLink string
	// Insights are the charts above the table (nil: none); Range keeps
	// the chart range across a filter submit.
	Insights *insights.Dashboard
	Range    string
}

// Option configures ActivityHandler.
type Option func(*options)

type options struct {
	insights insights.Loader
}

// WithInsights adds charts of the user's own calls above the table
// (decision 3yq9s5ev); load is normally insights.Source.Activity.
func WithInsights(load insights.Loader) Option {
	return func(o *options) { o.insights = load }
}

// ActivityHandler serves a user's own activity ("my activity"): GET only,
// query parameters tool, decision, outcome, since, until (RFC 3339 or
// YYYY-MM-DD) and page (1-based). It always lists the session user's rows,
// whatever the query says, through Reader.ListForUser. With WithInsights
// the page also charts the user's calls over the range query parameter
// (24h, 7d or 30d).
func ActivityHandler(reader Reader, who Identity, opts ...Option) http.Handler {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowGet(w, r) {
			return
		}
		userID, _ := who(r)
		if userID == "" {
			http.Error(w, "sign in to see your activity", http.StatusUnauthorized)
			return
		}
		f, p, pageNum, err := parseQuery(r.URL.Query(), false)
		if err != nil {
			http.Error(w, "invalid query: "+err.Error(), http.StatusBadRequest)
			return
		}
		dash, err := insights.ForUser(r, o.insights, userID, nil)
		if err != nil {
			http.Error(w, "invalid query: "+err.Error(), http.StatusBadRequest)
			return
		}
		rows, err := reader.ListForUser(r.Context(), userID, f, p)
		if err != nil {
			fail(w, r, "audit: activity page", err)
			return
		}
		render(w, r, "activity.html", page{Title: "My activity", Rows: rows, Filter: f, PageNum: pageNum,
			PrevLink: pageLink(r.URL, pageNum-1, len(rows), p.Limit), NextLink: pageLink(r.URL, pageNum+1, len(rows), p.Limit),
			Insights: dash, Range: r.URL.Query().Get(insights.RangeParam)})
	})
}

// AdminSearchHandler serves the admin audit search: every user's events,
// metadata only, through Reader.AdminSearch. Non-admins get 403. Accepts the
// same query parameters as ActivityHandler plus user_id (a uuid).
func AdminSearchHandler(reader Reader, who Identity) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowGet(w, r) {
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
		f, p, pageNum, err := parseQuery(r.URL.Query(), true)
		if err != nil {
			http.Error(w, "invalid query: "+err.Error(), http.StatusBadRequest)
			return
		}
		rows, err := reader.AdminSearch(r.Context(), f, p)
		if err != nil {
			fail(w, r, "audit: admin search page", err)
			return
		}
		render(w, r, "admin_search.html", page{Title: "Audit search", Admin: true, Rows: rows, Filter: f, PageNum: pageNum,
			PrevLink: pageLink(r.URL, pageNum-1, len(rows), p.Limit), NextLink: pageLink(r.URL, pageNum+1, len(rows), p.Limit)})
	})
}

func allowGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// parseQuery reads the filter and page. admin enables the user_id filter.
func parseQuery(q url.Values, admin bool) (Filter, Page, int, error) {
	var f Filter
	f.Tool = q.Get("tool")
	f.Decision = q.Get("decision")
	f.Outcome = q.Get("outcome")
	if admin {
		if u := q.Get("user_id"); u != "" {
			if !uuidRE.MatchString(u) {
				return f, Page{}, 0, errInvalid("user_id must be a uuid")
			}
			f.UserID = u
		}
	}
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		return f, Page{}, 0, errInvalid("since: " + err.Error())
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		return f, Page{}, 0, errInvalid("until: " + err.Error())
	}
	pageNum := 1
	if s := q.Get("page"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return f, Page{}, 0, errInvalid("page must be a positive integer")
		}
		pageNum = n
	}
	p := Page{Limit: DefaultPageSize, Offset: (pageNum - 1) * DefaultPageSize}
	return f, p, pageNum, nil
}

type errInvalid string

func (e errInvalid) Error() string { return string(e) }

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errInvalid("want RFC 3339 or YYYY-MM-DD")
}

// pageLink builds the link for page n keeping the active filter, or "" when
// that page cannot exist (n < 1, or a next page after a short page).
func pageLink(u *url.URL, n, got, limit int) string {
	if n < 1 {
		return ""
	}
	q := u.Query()
	current, _ := strconv.Atoi(q.Get("page"))
	if current < 1 {
		current = 1
	}
	if n > current && got < limit {
		return ""
	}
	q.Set("page", strconv.Itoa(n))
	return u.Path + "?" + q.Encode()
}

func render(w http.ResponseWriter, r *http.Request, name string, data page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := nav.Execute(templates, r, w, name, data); err != nil {
		// Headers are already out; log and stop.
		logError(r.Context(), "audit: render "+name, err)
	}
}

// fail answers 500 with a fixed message: the underlying error can carry
// connection strings or vendor text and is only logged (redacted).
func fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	logError(r.Context(), what, err)
	http.Error(w, "could not load audit events; quote request id "+observability.RequestIDFromContext(r.Context()), http.StatusInternalServerError)
}

func logError(ctx context.Context, what string, err error) {
	slog.Default().ErrorContext(ctx, what, "error", err, observability.RequestIDAttr(ctx))
}
