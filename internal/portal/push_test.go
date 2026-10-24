package portal_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/pushnotify"
	"github.com/huynle/mcp-gateway/internal/webpush"
)

// The "Notifications" panel on My account and its routes (Web Push,
// decision 0pzhidap).

// fakePush is an in-memory portal.Push.
type fakePush struct {
	mu           sync.Mutex
	devices      map[string][]pushnotify.Device
	subscribed   []string // raw bodies
	labels       []string
	unsubscribed []string
	removed      []string
	tests        []string
	subscribeErr error
	testErr      error
}

func newFakePush() *fakePush { return &fakePush{devices: map[string][]pushnotify.Device{}} }

func (f *fakePush) PublicKey(context.Context) (string, error) { return "BPublicKeyBase64url", nil }

func (f *fakePush) Subscribe(_ context.Context, userID string, raw []byte, label string) (*pushnotify.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.subscribeErr != nil {
		return nil, f.subscribeErr
	}
	f.subscribed = append(f.subscribed, string(raw))
	f.labels = append(f.labels, label)
	d := pushnotify.Device{ID: "dev-1", Label: label, Host: "fcm.googleapis.com", CreatedAt: time.Now()}
	f.devices[userID] = append(f.devices[userID], d)
	return &d, nil
}

func (f *fakePush) Unsubscribe(_ context.Context, userID, endpoint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unsubscribed = append(f.unsubscribed, userID+" "+endpoint)
	return nil
}

func (f *fakePush) RemoveDevice(_ context.Context, userID, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, d := range f.devices[userID] {
		if d.ID == id {
			f.devices[userID] = append(f.devices[userID][:i], f.devices[userID][i+1:]...)
			f.removed = append(f.removed, id)
			return nil
		}
	}
	return pushnotify.ErrNotFound
}

func (f *fakePush) Devices(_ context.Context, userID string) ([]pushnotify.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]pushnotify.Device(nil), f.devices[userID]...), nil
}

func (f *fakePush) SendTest(_ context.Context, userID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.testErr != nil {
		return 0, f.testErr
	}
	f.tests = append(f.tests, userID)
	return len(f.devices[userID]), nil
}

func newHarnessWithPush(t *testing.T) (*harness, *fakePush) {
	t.Helper()
	h := newHarness(t)
	fp := newFakePush()
	p, err := portal.New(h.svc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p.SetPush(fp)
	h.portal, h.h = p, p.Handler()
	return h, fp
}

// jsonPost posts body as JSON with the CSRF header (what pwa.js sends).
func (h *harness) jsonPost(t *testing.T, path string, cookie *http.Cookie, csrf, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

const subJSON = `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc","expirationTime":null,"keys":{"p256dh":"x","auth":"y"},"label":"Work phone"}`

func TestPushPanelHiddenWhenFeatureOff(t *testing.T) {
	h := newHarness(t)
	ck, _ := h.session(t, memberSub, "Member")
	body := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck}).Body.String()
	if strings.Contains(body, "data-push-control") || strings.Contains(body, `id="notifications"`) {
		t.Error("notifications panel shown with the feature off")
	}
	if rec := h.do(t, request{method: http.MethodGet, path: "/account/push/key", cookie: ck}); rec.Code != http.StatusNotFound {
		t.Errorf("GET /account/push/key with the feature off = %d, want 404", rec.Code)
	}
}

func TestPushPanelOnMyAccount(t *testing.T) {
	h, fp := newHarnessWithPush(t)
	ck, p := h.session(t, memberSub, "Member")
	ok := time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)
	fp.devices[p.UserID] = []pushnotify.Device{
		{ID: "11111111-1111-4111-8111-111111111111", Label: "Android <Chrome>", Host: "fcm.googleapis.com", CreatedAt: ok.Add(-time.Hour), LastSuccessAt: &ok},
		{ID: "22222222-2222-4222-8222-222222222222", Label: "iPhone Safari", Host: "web.push.apple.com", CreatedAt: ok},
	}
	rec := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck})
	body := rec.Body.String()
	for _, want := range []string{
		`id="notifications"`, "Notifications",
		"Get a notification on this device when an approval is waiting.",
		"On iPhone, add the app to your Home Screen first (Share → Add to Home Screen).",
		`data-push-control`, `data-push-state`, `data-push-toggle`, `data-push-test`,
		"Turn on for this device", "Send test notification",
		"Android &lt;Chrome&gt;", "fcm.googleapis.com", "iPhone Safari", "web.push.apple.com", "2026-10-20 09:30",
		`action="/account/push/unsubscribe"`, `name="id" value="11111111-1111-4111-8111-111111111111"`,
		`name="_csrf" value="` + p.CSRFToken + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("account page lacks %q", want)
		}
	}
	// The JS-only control is hidden until pwa.js reveals it.
	if ctl := regexp.MustCompile(`<[^>]*data-push-control[^>]*>`).FindString(body); !strings.Contains(ctl, "hidden") {
		t.Errorf("push control %q is not rendered hidden", ctl)
	}
	if strings.Contains(body, "/fcm/send/") {
		t.Error("account page shows an endpoint")
	}
	if strings.Contains(body, "onclick") {
		t.Error("inline handler in the push panel")
	}
}

func TestPushKeyRoute(t *testing.T) {
	h, _ := newHarnessWithPush(t)
	ck, _ := h.session(t, memberSub, "Member")
	rec := h.do(t, request{method: http.MethodGet, path: "/account/push/key", cookie: ck})
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET key = %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Cache-Control"))
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got["publicKey"] != "BPublicKeyBase64url" || len(got) != 1 {
		t.Errorf("body = %s", rec.Body)
	}
	// Signed out: the sign-in redirect, never the key.
	if rec := h.do(t, request{method: http.MethodGet, path: "/account/push/key"}); rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous GET key = %d", rec.Code)
	}
}

func TestPushSubscribeRoute(t *testing.T) {
	h, fp := newHarnessWithPush(t)
	ck, p := h.session(t, memberSub, "Member")

	// Auth and CSRF first.
	if rec := h.jsonPost(t, "/account/push/subscribe", nil, "", subJSON); rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous subscribe = %d, want the sign-in redirect", rec.Code)
	}
	if rec := h.jsonPost(t, "/account/push/subscribe", ck, "", subJSON); rec.Code != http.StatusForbidden {
		t.Errorf("subscribe without CSRF token = %d, want 403", rec.Code)
	}
	if rec := h.jsonPost(t, "/account/push/subscribe", ck, "wrong", subJSON); rec.Code != http.StatusForbidden {
		t.Errorf("subscribe with a wrong CSRF token = %d, want 403", rec.Code)
	}
	if len(fp.subscribed) != 0 {
		t.Fatal("subscription stored without CSRF")
	}

	rec := h.jsonPost(t, "/account/push/subscribe", ck, p.CSRFToken, subJSON)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("subscribe = %d: %s", rec.Code, rec.Body)
	}
	if len(fp.subscribed) != 1 || fp.subscribed[0] != subJSON || fp.labels[0] != "Work phone" {
		t.Errorf("service got %v / %v", fp.subscribed, fp.labels)
	}
	// Without a label the device is named from the User-Agent.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/account/push/subscribe",
		strings.NewReader(`{"endpoint":"https://fcm.googleapis.com/fcm/send/def","keys":{"p256dh":"x","auth":"y"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", p.CSRFToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36")
	req.AddCookie(ck)
	rr := httptest.NewRecorder()
	h.h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || fp.labels[1] != "Android Chrome" {
		t.Errorf("subscribe without label = %d, label %q", rr.Code, fp.labels[len(fp.labels)-1])
	}

	for name, c := range map[string]struct {
		body string
		err  error
		want int
	}{
		"bad JSON":             {body: `{`, want: http.StatusBadRequest},
		"not an object":        {body: `[1]`, want: http.StatusBadRequest},
		"endpoint not allowed": {body: subJSON, err: errors.Join(pushnotify.ErrInvalidSubscription, webpush.ErrEndpointNotAllowed), want: http.StatusBadRequest},
		"cap":                  {body: subJSON, err: pushnotify.ErrLimit, want: http.StatusConflict},
		"too large":            {body: `{"endpoint":"` + strings.Repeat("a", pushnotify.MaxRequestBytes) + `"}`, want: http.StatusRequestEntityTooLarge},
	} {
		fp.subscribeErr = c.err
		rec := h.jsonPost(t, "/account/push/subscribe", ck, p.CSRFToken, c.body)
		if rec.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", name, rec.Code, c.want, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "webpush:") || strings.Contains(rec.Body.String(), "fcm.googleapis.com") {
			t.Errorf("%s: error body leaks internals: %s", name, rec.Body)
		}
	}
}

func TestPushUnsubscribeRoute(t *testing.T) {
	h, fp := newHarnessWithPush(t)
	ck, p := h.session(t, memberSub, "Member")
	fp.devices[p.UserID] = []pushnotify.Device{{ID: "11111111-1111-4111-8111-111111111111", Label: "x", Host: "fcm.googleapis.com"}}

	// JSON from the browser's own subscription.
	rec := h.jsonPost(t, "/account/push/unsubscribe", ck, p.CSRFToken, `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc"}`)
	if rec.Code != http.StatusNoContent || len(fp.unsubscribed) != 1 || fp.unsubscribed[0] != p.UserID+" https://fcm.googleapis.com/fcm/send/abc" {
		t.Fatalf("JSON unsubscribe = %d, %v", rec.Code, fp.unsubscribed)
	}
	if rec := h.jsonPost(t, "/account/push/unsubscribe", ck, p.CSRFToken, `{`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d", rec.Code)
	}
	// The device table's plain form.
	rec = h.do(t, request{method: http.MethodPost, path: "/account/push/unsubscribe", cookie: ck,
		form: url.Values{"_csrf": {p.CSRFToken}, "id": {"11111111-1111-4111-8111-111111111111"}}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account#notifications" || len(fp.removed) != 1 {
		t.Fatalf("form remove = %d %q, removed %v", rec.Code, rec.Header().Get("Location"), fp.removed)
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/account/push/unsubscribe", cookie: ck,
		form: url.Values{"_csrf": {p.CSRFToken}, "id": {"11111111-1111-4111-8111-111111111111"}}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("removing an unknown device = %d, want 404", rec.Code)
	}
	if rec := h.do(t, request{method: http.MethodPost, path: "/account/push/unsubscribe", cookie: ck,
		form: url.Values{"id": {"x"}}}); rec.Code != http.StatusForbidden {
		t.Errorf("form without CSRF = %d, want 403", rec.Code)
	}
}

func TestPushTestRoute(t *testing.T) {
	h, fp := newHarnessWithPush(t)
	ck, p := h.session(t, memberSub, "Member")
	fp.devices[p.UserID] = []pushnotify.Device{{ID: "a"}, {ID: "b"}}
	if rec := h.jsonPost(t, "/account/push/test", ck, "", `{}`); rec.Code != http.StatusForbidden {
		t.Errorf("test without CSRF = %d", rec.Code)
	}
	rec := h.jsonPost(t, "/account/push/test", ck, p.CSRFToken, `{}`)
	var got map[string]int
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got["sent"] != 2 {
		t.Fatalf("test = %d %s", rec.Code, rec.Body)
	}
	fp.testErr = &pushnotify.TestTooSoonError{RetryAfter: 12500 * time.Millisecond}
	rec = h.jsonPost(t, "/account/push/test", ck, p.CSRFToken, `{}`)
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "13" || !strings.Contains(string(body), "13 seconds") {
		t.Errorf("rate-limited test = %d Retry-After %q: %s", rec.Code, rec.Header().Get("Retry-After"), body)
	}
}
