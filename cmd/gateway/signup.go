package main

import (
	"log/slog"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/identity"
)

// withSignupAudit records the identity service's sign-up and admin user
// events (user.signed_up, user.approved, user.rejected,
// signup_invite.created / revoked, signup.rate_limited) through rec.
func withSignupAudit(rec audit.Recorder) portalExtra {
	return func(idSvc *identity.Service, _ func(string, http.Handler), _ func(*http.Request) (string, string), _ *slog.Logger) {
		if rec != nil {
			idSvc.SetAudit(rec)
		}
	}
}
