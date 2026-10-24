package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/pushnotify"
	"github.com/huynle/mcp-gateway/internal/store"
)

// pushRoutes are the portal routes the feature mounts (portal/push.go).
var pushRoutes = []string{
	"GET /account/push/key", "POST /account/push/subscribe", "POST /account/push/unsubscribe", "POST /account/push/test",
}

// newPush builds Web Push approval notifications (decision 0pzhidap,
// docs/push-notifications.md) when GATEWAY_WEBPUSH_ENABLED is true. Only
// an unparsable flag fails startup. Without a key provider (the VAPID
// private key and the subscriptions could not be encrypted) or without a
// VAPID subject (the base URL is not https and GATEWAY_LEGAL_CONTACT_EMAIL
// is unset) it stays off (nil, nil) with a warning, as secrets do without
// a key provider. The VAPID key itself is created on first use, not here,
// so a database hiccup at startup does not take the feature down.
func newPush(cfg config.Config, st *store.Store, keys crypto.KeyProvider, rec audit.Recorder, getenv func(string) string, log *slog.Logger) (*pushnotify.Service, error) {
	pcfg, err := pushnotify.ConfigFromEnv(getenv)
	if err != nil {
		return nil, fmt.Errorf("web push: %w", err)
	}
	if !pcfg.Enabled {
		return nil, nil
	}
	if keys == nil {
		log.Warn(pushnotify.EnvEnabled + " is set but there is no key provider: web push stays off (keys and subscriptions cannot be encrypted)")
		return nil, nil
	}
	subject, err := pushnotify.Subject(cfg.BaseURL, getenv(portal.EnvLegalContactEmail))
	if err != nil {
		log.Warn(pushnotify.EnvEnabled+" is set but there is no VAPID subject: web push stays off (use an https base URL or set "+
			portal.EnvLegalContactEmail+")", "base_url", cfg.BaseURL, "error", err)
		return nil, nil
	}
	svc, err := pushnotify.New(pushnotify.NewPostgresStore(st), keys, pushnotify.Options{Subject: subject, Audit: rec, Log: log})
	if err != nil {
		return nil, fmt.Errorf("web push: %w", err)
	}
	log.Info("web push ready", "subject", subject, "routes", pushRoutes,
		"max_devices_per_user", pushnotify.MaxSubscriptionsPerUser, "timeout", pushnotify.DefaultNotifyTimeout)
	return svc, nil
}

// withPushDisableHook deletes a disabled user's push subscriptions inside
// the disabling transaction (the routes and the My account panel come
// through portalSettings.Push).
func withPushDisableHook(svc *pushnotify.Service) portalExtra {
	return func(idSvc *identity.Service, _ func(string, http.Handler), _ func(*http.Request) (string, string), _ *slog.Logger, _ http.Handler) {
		if svc == nil {
			return
		}
		idSvc.OnDisable(svc.OnDisableUser)
	}
}
