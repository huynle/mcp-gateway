package secrets

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
)

// PortalIdentity resolves the caller of a portal page: the session's user
// id (empty when not signed in) and its CSRF token, which the forms echo.
// The gateway supplies it so this package never touches sessions.
type PortalIdentity func(r *http.Request) (userID, csrfToken string)

// ServerNamer resolves a bound server id to the name the user knows it by.
// An error or an empty name shows the id instead.
type ServerNamer interface {
	ServerName(ctx context.Context, owner, serverID string) (string, error)
}

// ServerNamerFunc adapts a function to ServerNamer.
type ServerNamerFunc func(ctx context.Context, owner, serverID string) (string, error)

// ServerName implements ServerNamer.
func (f ServerNamerFunc) ServerName(ctx context.Context, owner, serverID string) (string, error) {
	return f(ctx, owner, serverID)
}

// HarnessNamer resolves the requesting harness id (token id or OAuth
// family id) to a display name. An error or an empty name shows the id.
type HarnessNamer interface {
	HarnessName(ctx context.Context, owner, harnessID string) (string, error)
}

// HarnessNamerFunc adapts a function to HarnessNamer.
type HarnessNamerFunc func(ctx context.Context, owner, harnessID string) (string, error)

// HarnessName implements HarnessNamer.
func (f HarnessNamerFunc) HarnessName(ctx context.Context, owner, harnessID string) (string, error) {
	return f(ctx, owner, harnessID)
}

// PortalOptions are the optional dependencies of the pages.
type PortalOptions struct {
	// Log receives page failures (never values). Default slog.Default().
	Log *slog.Logger
	// Servers and Harnesses name the binding's server and the requesting
	// harness; nil shows the ids.
	Servers   ServerNamer
	Harnesses HarnessNamer
	// Audit records secret.provided, secret.denied and secret.revoked
	// (record id and label only). Nil records nothing.
	Audit audit.Recorder
	// NotFound renders every "no such page" answer. Nil renders a page
	// with the portal's unknown-page title and message.
	NotFound http.Handler
}

//go:embed templates/*.html
var portalTemplateFS embed.FS

// entryPrefix is the path of the entry page: <base>/s/<request id>.
const entryPrefix = "/s/"

// maxPortalForm bounds the form bodies of the pages (a value is at most
// MaxValueLen bytes, up to three times that URL-encoded).
const maxPortalForm = 64 << 10

// Portal serves the self-service secret pages:
//
//	GET  /s/{id}               entry page of the caller's live pending
//	                           request (who asked, label, binding, TTL,
//	                           uses, fingerprint, one password field)
//	POST /s/{id}               action=save (value) | action=deny
//	GET  /secrets              the caller's pending and live secrets,
//	                           ended ones last; never values
//	POST /secrets/{id}/revoke  end a pending or live secret now
//
// It is mounted behind the portal's signed-in and CSRF checks (MountUser)
// and checks the caller and the CSRF token of POSTs again itself. Every
// response is Cache-Control: no-store and X-Frame-Options: DENY. A request
// that is unknown, someone else's, expired or already answered is the
// same 404 page as an unknown portal page. The value is read once from the
// form, wiped after Provide and never rendered, logged or audited.
type Portal struct {
	svc       *Service
	who       PortalIdentity
	log       *slog.Logger
	servers   ServerNamer
	harnesses HarnessNamer
	audit     audit.Recorder
	notFoundH http.Handler
	tpl       *template.Template
}

// NewPortal builds the pages.
func NewPortal(svc *Service, who PortalIdentity, opts PortalOptions) *Portal {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	tpl := template.Must(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"fmtTime": fmtPortalTime,
	}).ParseFS(portalTemplateFS, "templates/*.html"))
	return &Portal{
		svc: svc, who: who, log: opts.Log, servers: opts.Servers, harnesses: opts.Harnesses,
		audit: opts.Audit, notFoundH: opts.NotFound, tpl: tpl,
	}
}

// Mount registers the routes through mount (portal.MountUser or a
// ServeMux's Handle).
func (p *Portal) Mount(mount func(pattern string, handler http.Handler)) {
	mount("GET "+entryPrefix+"{id}", p.withUser(p.entry))
	mount("POST "+entryPrefix+"{id}", p.withUser(p.answer))
	mount("GET /secrets", p.withUser(p.list))
	mount("POST /secrets/{id}/revoke", p.withUser(p.revoke))
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
				dropValue(r)
				http.Error(w, "invalid or missing CSRF token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		h(w, r, caller{UserID: userID, CSRFToken: token})
	})
}

// --- entry page ------------------------------------------------------------------

type bindingView struct {
	Server, Tool, Arg string
	Machine           bool
}

type entryData struct {
	Title       string
	CSRFToken   string
	RequestID   string
	Harness     string
	Label       string
	Binding     bindingView
	TTL         string
	Uses        string
	Fingerprint string
	LinkExpires time.Time
	MinLen      int
	MaxLen      int
	Error       string
}

func (p *Portal) entry(w http.ResponseWriter, r *http.Request, c caller) {
	id := r.PathValue("id")
	sec, err := p.svc.LookupRequest(r.Context(), c.UserID, id)
	if p.handled(w, r, "look up request", err) {
		return
	}
	p.renderEntry(w, r, c, id, sec, http.StatusOK, "")
}

func (p *Portal) renderEntry(w http.ResponseWriter, r *http.Request, c caller, id string, sec Secret, status int, msg string) {
	p.render(w, r, status, "entry.html", entryData{
		Title: "Enter a secret", CSRFToken: c.CSRFToken, RequestID: id,
		Harness: p.harnessName(r.Context(), c.UserID, sec.HarnessID), Label: sec.Label,
		Binding: p.binding(r.Context(), c.UserID, sec.Binding),
		TTL:     fmtDuration(sec.TTL), Uses: fmtUses(sec.UsesTotal),
		Fingerprint: FingerprintForRequest(id), LinkExpires: sec.LinkExpiresAt,
		MinLen: MinValueLen, MaxLen: MaxValueLen, Error: msg,
	})
}

type doneData struct {
	Title, Message string
}

// answer is POST /s/{id}: save the value or deny the request.
func (p *Portal) answer(w http.ResponseWriter, r *http.Request, c caller) {
	switch r.PostForm.Get("action") {
	case "save":
		p.save(w, r, c)
	case "deny":
		dropValue(r)
		p.deny(w, r, c)
	default:
		dropValue(r)
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

func (p *Portal) save(w http.ResponseWriter, r *http.Request, c caller) {
	id := r.PathValue("id")
	value := takeValue(r)
	sec, err := p.svc.Provide(r.Context(), c.UserID, id, value)
	clear(value)
	var msg string
	switch {
	case errors.Is(err, ErrTooShort):
		msg = fmt.Sprintf("The secret must be at least %d characters. Nothing was saved.", MinValueLen)
	case errors.Is(err, ErrTooLong):
		msg = fmt.Sprintf("The secret must be at most %d bytes. Nothing was saved.", MaxValueLen)
	}
	if msg != "" {
		again, err := p.svc.LookupRequest(r.Context(), c.UserID, id)
		if p.handled(w, r, "look up request", err) {
			return
		}
		p.renderEntry(w, r, c, id, again, http.StatusUnprocessableEntity, msg)
		return
	}
	if p.handled(w, r, "provide secret", err) {
		return
	}
	p.record(r.Context(), c.UserID, "secret.provided", sec)
	p.render(w, r, http.StatusOK, "done.html", doneData{
		Title: "Secret saved", Message: "Saved. Return to your agent; it can retry now.",
	})
}

func (p *Portal) deny(w http.ResponseWriter, r *http.Request, c caller) {
	sec, err := p.svc.Deny(r.Context(), c.UserID, r.PathValue("id"))
	if p.handled(w, r, "deny secret", err) {
		return
	}
	p.record(r.Context(), c.UserID, "secret.denied", sec)
	p.render(w, r, http.StatusOK, "done.html", doneData{
		Title: "Request denied", Message: "Denied. Nothing was stored; your agent is told the request was denied.",
	})
}

// takeValue reads the value field once and removes it from the parsed
// form, so no later code path can see it. The caller wipes the bytes.
func takeValue(r *http.Request) []byte {
	v := []byte(r.PostFormValue("value"))
	dropValue(r)
	return v
}

func dropValue(r *http.Request) {
	r.PostForm.Del("value")
	r.Form.Del("value")
}

// --- /secrets ----------------------------------------------------------------------

type rowView struct {
	ID, Label, Harness, Status, Expires string
	Binding                             bindingView
	UsesLeft, UsesTotal                 int
}

type listData struct {
	Title     string
	CSRFToken string
	Active    []rowView
	Ended     []rowView
	Revoked   bool
}

func (p *Portal) list(w http.ResponseWriter, r *http.Request, c caller) {
	rows, err := p.svc.List(r.Context(), c.UserID)
	if err != nil {
		p.fail(w, r, "list secrets", err)
		return
	}
	now := p.svc.now()
	data := listData{Title: "Secrets", CSRFToken: c.CSRFToken, Revoked: r.URL.Query().Get("revoked") == "1"}
	servers, harnesses := map[string]string{}, map[string]string{}
	for _, s := range rows {
		if _, ok := servers[s.Binding.ServerID]; !ok {
			servers[s.Binding.ServerID] = p.serverName(r.Context(), c.UserID, s.Binding.ServerID)
		}
		if _, ok := harnesses[s.HarnessID]; !ok {
			harnesses[s.HarnessID] = p.harnessName(r.Context(), c.UserID, s.HarnessID)
		}
		v := rowView{
			ID: s.ID, Label: s.Label, Harness: harnesses[s.HarnessID],
			Binding:  bindingView{Server: servers[s.Binding.ServerID], Tool: s.Binding.Tool, Arg: s.Binding.Arg, Machine: s.Binding.Arg == ""},
			UsesLeft: s.UsesLeft, UsesTotal: s.UsesTotal,
		}
		v.Status, v.Expires = rowStatus(s, now)
		if s.State == StatePending || s.State == StateProvided {
			data.Active = append(data.Active, v)
		} else {
			data.Ended = append(data.Ended, v)
		}
	}
	p.render(w, r, http.StatusOK, "list.html", data)
}

// rowStatus is the state shown for s and when it ends (or ended).
func rowStatus(s Secret, now time.Time) (status, expires string) {
	switch s.State {
	case StatePending:
		if s.LinkLive(now) {
			return "waiting for you", "link " + fmtPortalTime(s.LinkExpiresAt)
		}
		return "link expired", fmtPortalTime(s.LinkExpiresAt)
	case StateProvided:
		switch {
		case s.Usable(now):
			return "live", fmtPortalTime(s.ExpiresAt)
		case s.UsesLeft <= 0:
			return "used up", fmtPortalTime(s.ExpiresAt)
		}
		return "expired", fmtPortalTime(s.ExpiresAt)
	}
	return s.State, fmtPortalTime(s.EndedAt)
}

func (p *Portal) revoke(w http.ResponseWriter, r *http.Request, c caller) {
	sec, err := p.svc.Revoke(r.Context(), c.UserID, r.PathValue("id"))
	if p.handled(w, r, "revoke secret", err) {
		return
	}
	p.record(r.Context(), c.UserID, "secret.revoked", sec)
	http.Redirect(w, r, "/secrets?revoked=1", http.StatusSeeOther)
}

// --- helpers -------------------------------------------------------------------------

func (p *Portal) binding(ctx context.Context, owner string, b Binding) bindingView {
	return bindingView{Server: p.serverName(ctx, owner, b.ServerID), Tool: b.Tool, Arg: b.Arg, Machine: b.Arg == ""}
}

func (p *Portal) serverName(ctx context.Context, owner, id string) string {
	if p.servers == nil {
		return id
	}
	name, err := p.servers.ServerName(ctx, owner, id)
	if err != nil || name == "" {
		p.log.Debug("secret page: server name unavailable", "event", "secrets.name_failed", "server_id", id,
			"error", observability.RedactError(err))
		return id
	}
	return name
}

func (p *Portal) harnessName(ctx context.Context, owner, id string) string {
	if p.harnesses == nil {
		return id
	}
	name, err := p.harnesses.HarnessName(ctx, owner, id)
	if err != nil || name == "" {
		p.log.Debug("secret page: harness name unavailable", "event", "secrets.name_failed", "harness_id", id,
			"error", observability.RedactError(err))
		return id
	}
	return name
}

// record writes an audit event with the record id and label only.
func (p *Portal) record(ctx context.Context, owner, action string, s Secret) {
	if p.audit == nil {
		return
	}
	ev := audit.Event{
		Time:             p.svc.now(),
		UserID:           owner,
		ResourceIdentity: map[string]string{"action": action, "secret_id": s.ID, "label": s.Label},
		Outcome:          "succeeded",
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if err := p.audit.Record(ctx, ev); err != nil {
		p.log.Error("secret action not audited", "event", "secrets.audit_failed", "action", action, "secret_id", s.ID,
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
	p.log.Error("secret page failed", "event", "secrets.page_failed", "what", what, "path", pagePath(r),
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}

// pagePath is the request path with the entry link's request id removed:
// the id opens the entry page, so it stays out of the logs.
func pagePath(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, entryPrefix) {
		return entryPrefix + "…"
	}
	return r.URL.Path
}

// fmtPortalTime formats a time.Time or *time.Time in UTC.
func fmtPortalTime(v any) string {
	switch t := v.(type) {
	case time.Time:
		return t.UTC().Format("2006-01-02 15:04 UTC")
	case *time.Time:
		if t != nil {
			return t.UTC().Format("2006-01-02 15:04 UTC")
		}
	}
	return ""
}

// fmtDuration renders 15m0s as "15m" and 1h0m0s as "1h".
func fmtDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func fmtUses(n int) string {
	if n == 1 {
		return "1 use"
	}
	return fmt.Sprintf("%d uses", n)
}
