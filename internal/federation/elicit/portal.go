package elicit

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
)

// PortalIdentity resolves the caller of the page: the session's user id
// (empty when not signed in) and its CSRF token, which the form echoes.
type PortalIdentity func(r *http.Request) (userID, csrfToken string)

// ServerNamer resolves a server id to the name the user knows it by. An
// error or an empty name shows the id instead.
type ServerNamer interface {
	ServerName(ctx context.Context, owner, serverID string) (string, error)
}

// ServerNamerFunc adapts a function to ServerNamer.
type ServerNamerFunc func(ctx context.Context, owner, serverID string) (string, error)

// ServerName implements ServerNamer.
func (f ServerNamerFunc) ServerName(ctx context.Context, owner, serverID string) (string, error) {
	return f(ctx, owner, serverID)
}

// HarnessNamer resolves the harness id (token id or OAuth family id) to a
// display name. An error or an empty name shows the id.
type HarnessNamer interface {
	HarnessName(ctx context.Context, owner, harnessID string) (string, error)
}

// HarnessNamerFunc adapts a function to HarnessNamer.
type HarnessNamerFunc func(ctx context.Context, owner, harnessID string) (string, error)

// HarnessName implements HarnessNamer.
func (f HarnessNamerFunc) HarnessName(ctx context.Context, owner, harnessID string) (string, error) {
	return f(ctx, owner, harnessID)
}

// DomainInfo describes an elicitation URL for the page: its host, the
// registrable domain (eTLD+1) to highlight and whether the host is an
// internationalised (punycode) name that deserves a warning. The wiring
// passes the relay's URL rules (validate.go); nil uses the URL's host as
// the registrable domain and flags xn-- labels and non-ASCII hosts.
type DomainInfo func(u string) (host, registrable string, punycode bool)

// FailureLimiter bounds failed /elicit/{id} lookups per client (the 404
// answers): Allow is asked before a lookup, and when it refuses the page
// answers 429 with Retry-After wait; Fail records one 404.
// *secrets.AddressLimiter satisfies it.
type FailureLimiter interface {
	Allow(r *http.Request) (ok bool, wait time.Duration)
	Fail(r *http.Request)
}

// PortalOptions are the optional dependencies of the page.
type PortalOptions struct {
	// Log receives page failures (record ids only). Default slog.Default().
	Log *slog.Logger
	// Servers and Harnesses name the server and the harness; nil shows
	// the ids.
	Servers   ServerNamer
	Harnesses HarnessNamer
	// Domain describes the URL; nil is the local fallback (DomainInfo).
	Domain DomainInfo
	// Audit records elicit.opened and elicit.cancelled with the record id
	// and the server id only. Nil records nothing.
	Audit audit.Recorder
	// NotFound renders every "no such page" answer (the portal's 404 page,
	// so an unknown link looks like any unknown page). Nil renders a
	// generic one.
	NotFound http.Handler
	// FailureLimiter bounds failed lookups per address; nil disables it.
	FailureLimiter FailureLimiter
}

//go:embed templates/*.html
var portalTemplateFS embed.FS

// pathPrefix is the path of the interstitial: <base>/elicit/<link id>.
const pathPrefix = "/elicit/"

// maxPortalForm bounds the form body (an action and a CSRF token).
const maxPortalForm = 4 << 10

// Portal serves the interstitial of upstream URL elicitations:
//
//	GET  /elicit/{id}   the caller's live elicitation: server, harness,
//	                    full URL, highlighted registrable domain, IDN
//	                    warning, the upstream message as escaped text,
//	                    Continue and Cancel
//	POST /elicit/{id}   action=continue: 303 to the stored URL (never
//	                    anything from the request) | action=cancel
//
// It is mounted behind the portal's signed-in and CSRF checks (MountUser)
// and checks the caller and the CSRF token of POSTs again itself. Every
// response is Cache-Control: no-store, X-Frame-Options: DENY and
// Referrer-Policy: no-referrer (the upstream never learns the link). A link
// that is unknown, someone else's, cancelled or expired is the NotFound
// page; with a FailureLimiter those 404s are counted per address. The page
// never fetches the URL.
type Portal struct {
	svc       *Service
	who       PortalIdentity
	log       *slog.Logger
	servers   ServerNamer
	harnesses HarnessNamer
	domain    DomainInfo
	audit     audit.Recorder
	notFoundH http.Handler
	limiter   FailureLimiter
	tpl       *template.Template
}

// NewPortal builds the page.
func NewPortal(svc *Service, who PortalIdentity, opts PortalOptions) *Portal {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Domain == nil {
		opts.Domain = hostDomainInfo
	}
	tpl := template.Must(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	}).ParseFS(portalTemplateFS, "templates/*.html"))
	return &Portal{
		svc: svc, who: who, log: opts.Log, servers: opts.Servers, harnesses: opts.Harnesses, domain: opts.Domain,
		audit: opts.Audit, notFoundH: opts.NotFound, limiter: opts.FailureLimiter, tpl: tpl,
	}
}

// Mount registers the routes through mount (portal.MountUser or a
// ServeMux's Handle).
func (p *Portal) Mount(mount func(pattern string, handler http.Handler)) {
	mount("GET "+pathPrefix+"{id}", p.withUser(p.limited(p.show)))
	mount("POST "+pathPrefix+"{id}", p.withUser(p.limited(p.answer)))
}

type caller struct {
	UserID    string
	CSRFToken string
}

type pageHandler func(w http.ResponseWriter, r *http.Request, c caller)

func (p *Portal) withUser(h pageHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		userID, token := p.who(r)
		if userID == "" {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxPortalForm)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "the form could not be read", http.StatusBadRequest)
				return
			}
			got := r.Header.Get("X-CSRF-Token")
			if got == "" {
				got = r.PostForm.Get("_csrf")
			}
			if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "invalid or missing CSRF token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		h(w, r, caller{UserID: userID, CSRFToken: token})
	})
}

// limited refuses a request from an address whose failed lookups used up
// its budget (429, Retry-After); the 404s spend it (notFound).
func (p *Portal) limited(h pageHandler) pageHandler {
	if p.limiter == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request, c caller) {
		if ok, wait := p.limiter.Allow(r); !ok {
			secs := max(int(math.Ceil(wait.Seconds())), 1)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			http.Error(w, "too many unknown links from your address; try again later", http.StatusTooManyRequests)
			return
		}
		h(w, r, c)
	}
}

// --- page ------------------------------------------------------------------------------

type pageData struct {
	Title     string
	CSRFToken string
	LinkID    string
	Server    string
	Harness   string
	URL       string
	// HostPrefix + Registrable is the host, with the registrable domain
	// highlighted; Other is the registrable domain when it is not a
	// suffix of the host (shown separately).
	HostPrefix  string
	Registrable string
	Other       string
	Punycode    bool
	Message     string
	Expires     time.Time
}

func (p *Portal) show(w http.ResponseWriter, r *http.Request, c caller) {
	id := r.PathValue("id")
	e, err := p.svc.Lookup(r.Context(), c.UserID, id)
	if p.handled(w, r, "look up elicitation", err) {
		return
	}
	ctx := r.Context()
	d := pageData{
		Title: "Open a page of " + p.serverName(ctx, c.UserID, e.ServerID), CSRFToken: c.CSRFToken, LinkID: id,
		Server: p.serverName(ctx, c.UserID, e.ServerID), Harness: p.harnessName(ctx, c.UserID, e.HarnessID),
		URL: e.URL, Message: e.Message, Expires: e.ExpiresAt,
	}
	host, reg, puny := p.domain(e.URL)
	d.Punycode = puny
	switch {
	case reg == "" || host == reg:
		d.Registrable = host
	case strings.HasSuffix(host, "."+reg):
		d.HostPrefix, d.Registrable = strings.TrimSuffix(host, reg), reg
	default:
		d.HostPrefix, d.Other = host, reg
	}
	p.render(w, r, http.StatusOK, "interstitial.html", d)
}

type doneData struct {
	Title, Message string
}

// answer is POST /elicit/{id}: continue to the stored URL or cancel.
func (p *Portal) answer(w http.ResponseWriter, r *http.Request, c caller) {
	id := r.PathValue("id")
	switch r.PostForm.Get("action") {
	case "continue":
		e, err := p.svc.Open(r.Context(), c.UserID, id)
		if p.handled(w, r, "open elicitation", err) {
			return
		}
		p.record(r.Context(), c.UserID, "elicit.opened", e)
		// Only the stored URL, which passed the relay's URL rules when it
		// was stored; nothing of the request is used.
		w.Header().Set("Location", e.URL)
		w.WriteHeader(http.StatusSeeOther)
	case "cancel":
		e, err := p.svc.Cancel(r.Context(), c.UserID, id)
		if p.handled(w, r, "cancel elicitation", err) {
			return
		}
		p.record(r.Context(), c.UserID, "elicit.cancelled", e)
		p.render(w, r, http.StatusOK, "done.html", doneData{
			Title: "Cancelled", Message: "Cancelled. The page was not opened; return to your agent.",
		})
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// --- helpers -------------------------------------------------------------------------

// hostDomainInfo is the fallback DomainInfo: the URL's host as the
// registrable domain, punycode flagged for xn-- labels or non-ASCII.
func hostDomainInfo(raw string) (string, string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	host := strings.ToLower(u.Hostname())
	puny := false
	for _, l := range strings.Split(host, ".") {
		if strings.HasPrefix(l, "xn--") {
			puny = true
		}
	}
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			puny = true
		}
	}
	return host, host, puny
}

func (p *Portal) serverName(ctx context.Context, owner, id string) string {
	if p.servers == nil {
		return id
	}
	name, err := p.servers.ServerName(ctx, owner, id)
	if err != nil || name == "" {
		p.log.Debug("elicitation page: server name unavailable", "event", "elicit.name_failed", "server_id", id,
			"error", observability.RedactError(err))
		return id
	}
	return name
}

func (p *Portal) harnessName(ctx context.Context, owner, id string) string {
	if id == "" {
		return "unknown harness"
	}
	if p.harnesses == nil {
		return id
	}
	name, err := p.harnesses.HarnessName(ctx, owner, id)
	if err != nil || name == "" {
		p.log.Debug("elicitation page: harness name unavailable", "event", "elicit.name_failed", "harness_id", id,
			"error", observability.RedactError(err))
		return id
	}
	return name
}

// record writes an audit event with the record id and server id only
// (never the URL, the message or the link).
func (p *Portal) record(ctx context.Context, owner, action string, e Elicitation) {
	if p.audit == nil {
		return
	}
	ev := audit.Event{
		Time:             p.svc.now(),
		UserID:           owner,
		ResourceIdentity: map[string]string{"action": action, "elicitation_id": e.ID, "server_id": e.ServerID},
		Outcome:          "succeeded",
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if err := p.audit.Record(ctx, ev); err != nil {
		p.log.Error("elicitation action not audited", "event", "elicit.audit_failed", "action", action, "elicitation_id", e.ID,
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	}
}

// handled answers err: ErrNotFound is the 404 page, anything else a
// server error. It reports whether it wrote a response.
func (p *Portal) handled(w http.ResponseWriter, r *http.Request, what string, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrNotFound):
		p.notFound(w, r)
	default:
		p.fail(w, r, what, err)
	}
	return true
}

type messageData struct {
	Title, Message string
}

func (p *Portal) notFound(w http.ResponseWriter, r *http.Request) {
	if p.limiter != nil {
		p.limiter.Fail(r)
	}
	if p.notFoundH != nil {
		p.notFoundH.ServeHTTP(w, r)
		return
	}
	p.render(w, r, http.StatusNotFound, "message.html", messageData{Title: "Page not found", Message: "There is no page at this address."})
}

func (p *Portal) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := nav.Execute(p.tpl, r, &buf, name, data); err != nil {
		p.fail(w, r, "render "+name, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (p *Portal) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	// The link id opens the page, so the path stays out of the logs.
	p.log.Error("elicitation page failed", "event", "elicit.page_failed", "what", what, "path", pathPrefix+"…",
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}
