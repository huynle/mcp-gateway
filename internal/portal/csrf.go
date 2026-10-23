package portal

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/huynle/mcp-gateway/internal/identity"
)

// CSRF protection for every state-changing request (anything but GET,
// HEAD, OPTIONS, TRACE):
//
//  1. the request must belong to a session (anonymous writes are refused);
//  2. the token in the "_csrf" form field or the X-CSRF-Token header must
//     equal the session's token (identity derives it from the session
//     secret, so no extra server state: synchronizer token pattern);
//  3. a browser that labels the request cross-site (Sec-Fetch-Site) is
//     refused regardless, as defence in depth.
//
// Failures are 403 and never reach the handler.

const (
	csrfField  = "_csrf"
	csrfHeader = "X-CSRF-Token"
	// maxFormBytes bounds form bodies parsed for the token check.
	maxFormBytes = 1 << 20
)

func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

func (p *Portal) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		principal := identity.PrincipalFrom(r.Context())
		expected, userID := "", ""
		switch pending := identity.PendingFrom(r.Context()); {
		case principal != nil:
			expected, userID = principal.CSRFToken, principal.UserID
		case pending != nil && r.URL.Path == "/auth/signout":
			// A pending account may only sign out.
			expected, userID = pending.CSRFToken, pending.UserID
		default:
			p.forbidden(w, r, "Sign in before submitting this form.")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
			p.forbidden(w, r, "Cross-site form submissions are not accepted.")
			return
		}
		token := r.Header.Get(csrfHeader)
		if token == "" {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			if err := r.ParseForm(); err != nil {
				p.forbidden(w, r, "The form could not be read.")
				return
			}
			token = r.PostForm.Get(csrfField)
		}
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			p.log.Warn("request rejected", "event", "portal.csrf_rejected", "user_id", userID, "path", logPath(r))
			p.forbidden(w, r, "The form token is missing or expired. Reload the page and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// logPath is the request path as logged: the id of a secret entry link
// (/s/<id>, internal/secrets) opens that page, so it stays out of logs.
func logPath(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/s/") {
		return "/s/…"
	}
	return r.URL.Path
}

func (p *Portal) forbidden(w http.ResponseWriter, r *http.Request, message string) {
	p.errorPage(w, r, http.StatusForbidden, "Request refused", message)
}
