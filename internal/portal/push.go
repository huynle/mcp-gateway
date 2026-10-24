package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/pushnotify"
)

// Push is the Web Push service behind My account's "Notifications" panel
// (*pushnotify.Service; decision 0pzhidap, docs/push-notifications.md).
type Push interface {
	PublicKey(ctx context.Context) (string, error)
	Subscribe(ctx context.Context, userID string, raw []byte, label string) (*pushnotify.Device, error)
	Unsubscribe(ctx context.Context, userID, endpoint string) error
	RemoveDevice(ctx context.Context, userID, id string) error
	Devices(ctx context.Context, userID string) ([]pushnotify.Device, error)
	SendTest(ctx context.Context, userID string) (int, error)
}

// SetPush adds the "Notifications" panel to My account and its routes
// (GATEWAY_WEBPUSH_ENABLED). Call before Handler; without it neither
// exists.
func (p *Portal) SetPush(push Push) { p.push = push }

// pushView is the panel's data: the user's devices (never an endpoint).
type pushView struct {
	Devices []pushnotify.Device
}

// mountPush registers the push routes. All are behind the sign-in check;
// the POSTs behind the CSRF check too (pwa.js sends the token in the
// X-CSRF-Token header it reads from <body hx-headers>; the device
// table's Remove buttons are plain forms with _csrf).
func (p *Portal) mountPush(mux *http.ServeMux) {
	mux.Handle("GET /account/push/key", p.requireUser(http.HandlerFunc(p.pushKey)))
	mux.Handle("POST /account/push/subscribe", p.requireUser(p.csrf(http.HandlerFunc(p.pushSubscribe))))
	mux.Handle("POST /account/push/unsubscribe", p.requireUser(p.csrf(http.HandlerFunc(p.pushUnsubscribe))))
	mux.Handle("POST /account/push/test", p.requireUser(p.csrf(http.HandlerFunc(p.pushTest))))
}

// pushKey answers {"publicKey": "<base64url applicationServerKey>"}.
func (p *Portal) pushKey(w http.ResponseWriter, r *http.Request) {
	key, err := p.push.PublicKey(r.Context())
	if err != nil {
		p.log.Error("web push key unavailable", "event", "portal.push_key_failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Notifications are not available right now."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"publicKey": key})
}

// pushSubscribe stores the browser's PushSubscription.toJSON() (plus an
// optional "label"; without one the device is named from the
// User-Agent). 204, 400 for anything malformed or not on a known push
// service (one generic message: the reason is the service's business),
// 409 at the device cap, 413 over MaxRequestBytes.
func (p *Portal) pushSubscribe(w http.ResponseWriter, r *http.Request) {
	raw, ok := p.readPushJSON(w, r)
	if !ok {
		return
	}
	var body struct {
		Label string `json:"label"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The request is not a JSON object."})
		return
	}
	label := body.Label
	if label == "" {
		label = pushnotify.DeviceLabel(r.UserAgent())
	}
	userID := identity.PrincipalFrom(r.Context()).UserID
	_, err := p.push.Subscribe(r.Context(), userID, raw, label)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, pushnotify.ErrInvalidSubscription):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "This browser's push subscription was refused."})
	case errors.Is(err, pushnotify.ErrLimit):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "You already have " + strconv.Itoa(pushnotify.MaxSubscriptionsPerUser) +
			" devices with notifications. Remove one under My account → Notifications first."})
	default:
		p.log.Error("push subscribe failed", "event", "portal.push_subscribe_failed", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "The subscription could not be saved."})
	}
}

// pushUnsubscribe turns notifications off: JSON {"endpoint"} from the
// browser's current subscription (204), or the device table's form with
// the device id (303 back to the panel; 404 for an unknown device).
func (p *Portal) pushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	userID := identity.PrincipalFrom(r.Context()).UserID
	if isJSON(r) {
		raw, ok := p.readPushJSON(w, r)
		if !ok {
			return
		}
		var body struct {
			Endpoint string `json:"endpoint"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The request is not a JSON object."})
			return
		}
		if err := p.push.Unsubscribe(r.Context(), userID, body.Endpoint); err != nil {
			p.log.Error("push unsubscribe failed", "event", "portal.push_unsubscribe_failed", "user_id", userID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Notifications could not be turned off."})
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	err := p.push.RemoveDevice(r.Context(), userID, r.PostFormValue("id"))
	switch {
	case errors.Is(err, pushnotify.ErrNotFound):
		p.notFound(w, r)
	case err != nil:
		p.serverError(w, r, err)
	default:
		http.Redirect(w, r, "/account#notifications", http.StatusSeeOther)
	}
}

// pushTest sends the test notification: {"sent": n}; 429 with
// Retry-After within pushnotify.TestInterval of the last one.
func (p *Portal) pushTest(w http.ResponseWriter, r *http.Request) {
	userID := identity.PrincipalFrom(r.Context()).UserID
	n, err := p.push.SendTest(r.Context(), userID)
	var soon *pushnotify.TestTooSoonError
	switch {
	case errors.As(err, &soon):
		secs := int(math.Ceil(soon.RetryAfter.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "You can send a test notification every " +
			strconv.Itoa(int(pushnotify.TestInterval.Seconds())) + " seconds. Try again in " + plural(secs, "second") + "."})
		return
	case err != nil:
		// Some or all devices failed; the count says how many got it.
		p.log.Warn("push test partly failed", "event", "portal.push_test_failed", "user_id", userID, "sent", n, "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]int{"sent": n})
}

// readPushJSON reads a JSON body of at most MaxRequestBytes. It answers
// 413 (too large) or 400 (unreadable) itself and reports false then.
func (p *Portal) readPushJSON(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, pushnotify.MaxRequestBytes))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "The request is too large."})
		return nil, false
	case err != nil:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The request could not be read."})
		return nil, false
	}
	// An object, not an array or a scalar: both bodies are objects.
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '{' {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The request is not a JSON object."})
		return nil, false
	}
	return raw, true
}

func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// writeJSON answers v as JSON, never cached (the requireUser wrapper sets
// no-store already; set again for clarity on error paths).
func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
