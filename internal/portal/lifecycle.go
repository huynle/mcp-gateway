package portal

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/account"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Account is the account lifecycle service (*account.Service): the data
// export and account deletion behind My account and /admin/users.
type Account interface {
	Export(ctx context.Context, userID string, w io.Writer) error
	Status(ctx context.Context, userID string) (*account.Status, error)
	DeleteSelf(ctx context.Context, userID string) error
	DeleteByAdmin(ctx context.Context, actorID, userID string) error
	ReauthWindow() time.Duration
}

// SetAccount adds "Your data" (export, delete) to My account, its routes
// and the admin delete action. Call before Handler.
func (p *Portal) SetAccount(a Account) { p.lifecycle = a }

func (p *Portal) mountLifecycle(mux *http.ServeMux) {
	mux.Handle("POST /account/export", p.requireUser(p.csrf(http.HandlerFunc(p.exportMyData))))
	mux.Handle("GET /account/delete", p.requireUser(http.HandlerFunc(p.deleteMyAccountPage)))
	mux.Handle("POST /account/delete", p.requireUser(p.csrf(http.HandlerFunc(p.deleteMyAccount))))
	mux.HandleFunc("GET /account/deleted", p.accountDeleted)
	// Gating before CSRF: a non-admin's POST is the 404 of an unknown page.
	mux.Handle("GET /admin/users/{id}/delete", p.requireAdmin(http.HandlerFunc(p.adminDeletePage)))
	mux.Handle("POST /admin/users/{id}/delete", p.requireAdmin(p.csrf(http.HandlerFunc(p.adminDeleteUser))))
}

// exportMyData streams the export as a JSON download. Nothing is written
// (and no download headers set) until the service writes its first byte,
// so a refused export (rate limit, store error) is a normal error page.
func (p *Portal) exportMyData(w http.ResponseWriter, r *http.Request) {
	userID := identity.PrincipalFrom(r.Context()).UserID
	dl := &downloadWriter{w: w, filename: "mcp-gateway-export-" + time.Now().UTC().Format("2006-01-02") + ".json"}
	err := p.lifecycle.Export(r.Context(), userID, dl)
	var soon *account.ExportTooSoonError
	switch {
	case err == nil:
	case dl.started:
		// Headers are gone; the truncated JSON will not parse.
		p.log.Error("data export failed mid-stream", "event", "portal.export_failed", "error", err)
	case errors.As(err, &soon):
		secs := int(math.Ceil(soon.RetryAfter.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		mins := int(math.Ceil(soon.RetryAfter.Minutes()))
		p.errorPage(w, r, http.StatusTooManyRequests, "Export limit",
			"You can download your data once every few minutes. Try again in "+plural(mins, "minute")+".")
	default:
		p.serverError(w, r, err)
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// downloadWriter sets the download headers on the first Write.
type downloadWriter struct {
	w        http.ResponseWriter
	filename string
	started  bool
}

func (d *downloadWriter) Write(b []byte) (int, error) {
	if !d.started {
		d.started = true
		h := d.w.Header()
		h.Set("Content-Type", "application/json; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+d.filename+`"`)
		h.Set("Cache-Control", "no-store")
		d.w.WriteHeader(http.StatusOK)
	}
	return d.w.Write(b)
}

// deleteData is the confirm page (own account or, for Admin, someone
// else's).
type deleteData struct {
	Admin       bool
	Name        string
	Action      string
	Phrase      string
	Fresh       bool
	WindowMins  int
	Blockers    []string
	Error       string
	ReauthLinks []signInProvider
}

func (p *Portal) deleteMyAccountPage(w http.ResponseWriter, r *http.Request) {
	p.renderDelete(w, r, http.StatusOK, identity.PrincipalFrom(r.Context()).UserID, false, "")
}

func (p *Portal) adminDeletePage(w http.ResponseWriter, r *http.Request) {
	p.renderDelete(w, r, http.StatusOK, r.PathValue("id"), true, "")
}

func (p *Portal) renderDelete(w http.ResponseWriter, r *http.Request, status int, userID string, admin bool, msg string) {
	st, err := p.lifecycle.Status(r.Context(), userID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		p.notFound(w, r)
		return
	case err != nil:
		p.serverError(w, r, err)
		return
	}
	d := deleteData{
		Admin: admin, Name: st.DisplayName, Action: "/account/delete", Phrase: account.ConfirmPhrase,
		Fresh: st.Fresh || admin, WindowMins: int(p.lifecycle.ReauthWindow().Minutes()), Blockers: st.Blockers, Error: msg,
	}
	if admin {
		d.Action = "/admin/users/" + url.PathEscape(userID) + "/delete"
		d.Phrase = account.AdminConfirmPhrase
		if userID == identity.PrincipalFrom(r.Context()).UserID {
			d.Blockers = append(d.Blockers, "This is your own account: delete it from My account.")
		}
	}
	for _, prov := range p.svc.Providers() {
		d.ReauthLinks = append(d.ReauthLinks, signInProvider{
			DisplayName: prov.DisplayName,
			StartURL:    "/auth/" + prov.Name + "/start?return_to=" + url.QueryEscape("/account/delete"),
		})
	}
	p.render(w, r, status, "account_delete.html", d)
}

// confirmed compares the typed phrase, ignoring case and surrounding space.
func confirmed(r *http.Request, phrase string) bool {
	return strings.EqualFold(strings.Join(strings.Fields(r.PostFormValue("confirm")), " "), phrase)
}

func (p *Portal) deleteMyAccount(w http.ResponseWriter, r *http.Request) {
	userID := identity.PrincipalFrom(r.Context()).UserID
	if !confirmed(r, account.ConfirmPhrase) {
		p.renderDelete(w, r, http.StatusUnprocessableEntity, userID, false, "Type the phrase exactly to confirm.")
		return
	}
	err := p.lifecycle.DeleteSelf(r.Context(), userID)
	var blocked *account.BlockedError
	switch {
	case err == nil:
		p.svc.ClearSessionCookie(w)
		http.Redirect(w, r, "/account/deleted", http.StatusSeeOther)
	case errors.Is(err, account.ErrReauthRequired):
		p.renderDelete(w, r, http.StatusForbidden, userID, false, "Sign in again first: deleting your account needs a sign-in from the last few minutes.")
	case errors.As(err, &blocked):
		p.renderDelete(w, r, http.StatusConflict, userID, false, "Your account cannot be deleted yet.")
	default:
		p.serverError(w, r, err)
	}
}

func (p *Portal) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	actor := identity.PrincipalFrom(r.Context()).UserID
	id := r.PathValue("id")
	if !confirmed(r, account.AdminConfirmPhrase) {
		p.renderDelete(w, r, http.StatusUnprocessableEntity, id, true, "Type the phrase exactly to confirm.")
		return
	}
	err := p.lifecycle.DeleteByAdmin(r.Context(), actor, id)
	var blocked *account.BlockedError
	switch {
	case err == nil:
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	case errors.Is(err, account.ErrOwnAccount):
		p.errorPage(w, r, http.StatusBadRequest, "Not allowed", "Delete your own account from My account.")
	case errors.Is(err, store.ErrNotFound):
		p.notFound(w, r)
	case errors.As(err, &blocked):
		p.renderDelete(w, r, http.StatusConflict, id, true, "The account cannot be deleted yet.")
	default:
		p.serverError(w, r, err)
	}
}

func (p *Portal) accountDeleted(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p.render(w, r, http.StatusOK, "error.html", errorData{
		Title:   "Account deleted",
		Message: "Your account was deleted: your tokens, harness sign-ins, app connections, tunnels and private MCP servers are gone. Signing in again creates a new, empty account.",
		Back:    "/",
	})
}
