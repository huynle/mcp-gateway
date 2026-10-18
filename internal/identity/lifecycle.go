package identity

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Account lifecycle helpers for internal/account (data export, account
// deletion), which runs its own transaction around the disable hooks.

// RunDisableHooks runs the registered OnDisable hooks, in registration
// order, inside the caller's transaction tx: account deletion reuses the
// revocations of a disable (tokens, OAuth harness grants, app
// connections revoked at the vendor). The first error stops the run.
func (s *Service) RunDisableHooks(ctx context.Context, tx store.Tx, userID string) error {
	s.mu.RLock()
	hooks := slices.Clone(s.hooks)
	s.mu.RUnlock()
	for _, h := range hooks {
		if err := h(ctx, tx, userID); err != nil {
			return fmt.Errorf("identity: disable hook: %w", err)
		}
	}
	return nil
}

// IsBootstrapAdmin reports whether issuer+subject is listed in
// GATEWAY_BOOTSTRAP_ADMINS (granted admin on every sign-in, so deleting
// that account would not stick).
func (s *Service) IsBootstrapAdmin(issuer, subject string) bool {
	return s.admins[adminKey(issuer, subject)]
}

// ClearSessionCookie expires the browser's session cookie (the session row
// itself is revoked or deleted by the caller).
func (s *Service) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
