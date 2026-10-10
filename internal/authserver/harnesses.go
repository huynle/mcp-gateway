package authserver

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The connected-harnesses page (decision uamxx6ba: "connected harnesses
// list with revoke"): one row per refresh-token family of the signed-in
// user (client name, connected, last used, scope, status) with a revoke
// button that ends the family; the harness then has to sign in again.

//go:embed templates/*.html
var templateFS embed.FS

// parseTemplates builds the consent, harnesses and error pages.
func parseTemplates() (*template.Template, error) {
	return template.New("").Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
		"fmtDate": func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	}).ParseFS(templateFS, "templates/*.html")
}

// consentData is the consent page.
type consentData struct {
	Title        string
	CSRFToken    string
	ClientName   string
	ClientID     string
	RedirectHost string
	Resource     string
	Scopes       []string
	Hidden       url.Values
}

// harnessView is one row of the harnesses page.
type harnessView struct {
	store.Harness
	Status string
}

// harnessesData is the harnesses page.
type harnessesData struct {
	Title     string
	CSRFToken string
	Harnesses []harnessView
	Revoked   bool
	MCPURL    string
}

// errorData is the error page. CSRFToken is always empty: the layout
// shows the sign-out form only when it is set, and an error page carries
// no form.
type errorData struct {
	Title     string
	Message   string
	CSRFToken string
}

// ServeHarnesses is GET /harnesses.
func (s *Service) ServeHarnesses(w http.ResponseWriter, r *http.Request) {
	userID, csrfToken := s.identity(r)
	if userID == "" {
		s.redirectToSignIn(w, r)
		return
	}
	list, err := s.ListHarnesses(r.Context(), userID)
	if err != nil {
		s.log.Error("harnesses page failed", "event", "authserver.page_failed", "error", observability.RedactError(err), "request_id", observability.RequestIDFromContext(r.Context()))
		s.errorPage(w, http.StatusInternalServerError, "The request could not be completed. Try again.")
		return
	}
	now := s.now()
	data := harnessesData{Title: "Connected harnesses", CSRFToken: csrfToken, Revoked: r.URL.Query().Get("revoked") == "1", MCPURL: s.cfg.Resource()}
	for _, h := range list {
		v := harnessView{Harness: h, Status: "active"}
		v.Scope = scopeFromStore([]byte(h.Scope))
		switch {
		case h.RevokedAt != nil:
			v.Status = "revoked"
		case !now.Before(h.ExpiresAt):
			v.Status = "expired"
		}
		data.Harnesses = append(data.Harnesses, v)
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, http.StatusOK, "harnesses.html", data)
}

// ServeHarnessRevoke is POST /harnesses/{id}/revoke.
func (s *Service) ServeHarnessRevoke(w http.ResponseWriter, r *http.Request) {
	userID, csrfToken := s.identity(r)
	if userID == "" {
		s.errorPage(w, http.StatusUnauthorized, "Sign in to manage your harnesses.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("_csrf")), []byte(csrfToken)) != 1 {
		s.errorPage(w, http.StatusForbidden, "The form token is missing or expired. Reload the page and try again.")
		return
	}
	err := s.RevokeHarness(r.Context(), userID, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound) || isBadUUID(err):
		s.errorPage(w, http.StatusNotFound, "No such harness.")
		return
	case err != nil:
		s.log.Error("harness revoke failed", "event", "authserver.page_failed", "error", observability.RedactError(err), "request_id", observability.RequestIDFromContext(r.Context()))
		s.errorPage(w, http.StatusInternalServerError, "The request could not be completed. Try again.")
		return
	}
	http.Redirect(w, r, HarnessesPath+"?revoked=1", http.StatusSeeOther)
}

// ListHarnesses returns the user's connected harnesses, newest first.
func (s *Service) ListHarnesses(ctx context.Context, userID string) ([]store.Harness, error) {
	var out []store.Harness
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		var err error
		out, err = tx.ListHarnesses(ctx, userID)
		return err
	})
	return out, err
}

// RevokeHarness revokes one of userID's refresh-token families. Another
// user's family is store.ErrNotFound (row-level security hides it);
// revoking twice is not an error.
func (s *Service) RevokeHarness(ctx context.Context, userID, familyID string) error {
	now := s.now()
	var found bool
	var revoked int64
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		list, err := tx.ListHarnesses(ctx, userID)
		if err != nil {
			return err
		}
		for _, h := range list {
			if h.FamilyID == familyID {
				found = true
			}
		}
		if !found {
			return store.ErrNotFound
		}
		revoked, err = tx.RevokeRefreshFamily(ctx, familyID, now)
		return err
	})
	if err != nil {
		return err
	}
	if revoked == 0 {
		return nil
	}
	s.log.Info("harness revoked", "event", "authserver.harness_revoked", "user_id", userID, "family_id", familyID, "tokens", revoked)
	s.record(ctx, userID, familyID, "oauth_harness_revoked", nil, "allow", "succeeded")
	return nil
}

// DisableHook returns the identity.DisableHook that revokes every refresh
// token and pending code of a user being disabled, inside the disabling
// transaction when there is one (tx is nil on non-PostgreSQL stores; then
// it uses Bypass).
func (s *Service) DisableHook() identity.DisableHook {
	return func(ctx context.Context, tx store.Tx, userID string) error {
		now := s.now()
		var n int64
		var err error
		if tx != nil {
			n, err = pgTx{tx}.RevokeUserRefreshTokens(ctx, userID, now)
		} else {
			err = s.st.Bypass(ctx, func(t Tx) error {
				n, err = t.RevokeUserRefreshTokens(ctx, userID, now)
				return err
			})
		}
		if err != nil {
			return fmt.Errorf("authserver: revoke on disable: %w", err)
		}
		s.log.Info("oauth harnesses revoked on disable", "event", "authserver.revoked_on_disable", "user_id", userID, "revoked", n)
		return nil
	}
}

// --- rendering ---------------------------------------------------------------

func (s *Service) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("render failed", "event", "authserver.render_failed", "template", name, "path", r.URL.Path, "error", err)
		pageHeaders(w)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pageHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// errorPage renders a message without redirecting anywhere.
func (s *Service) errorPage(w http.ResponseWriter, status int, message string) {
	var buf bytes.Buffer
	pageHeaders(w)
	if err := s.tpl.ExecuteTemplate(&buf, "error.html", errorData{Title: "Request refused", Message: message}); err != nil {
		http.Error(w, message, status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// pageHeaders hardens every page the authorization server renders: the
// consent page must not be framed (clickjacking, RFC 9700 section 4.16),
// nothing on it may be cached, and the URL (which carries the client's
// state) must not leak through the Referer header. A Content-Security-
// Policy already set by an outer layer (the portal's baseline, which
// includes frame-ancestors 'none') is kept rather than narrowed to the
// framing directive alone.
func pageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	if h.Get("Content-Security-Policy") == "" {
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	}
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
}

// isBadUUID recognises PostgreSQL's complaint about an id that is not a
// uuid (22P02): for the portal that is "no such harness".
func isBadUUID(err error) bool {
	return err != nil && strings.Contains(err.Error(), "22P02")
}
