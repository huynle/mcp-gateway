package portal_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

// The "Gateway management tools" setting on My account (Brain task
// ds5tjou2, decision bnneszc1).

// fakeGatewayTools is an in-memory portal.GatewayTools.
type fakeGatewayTools struct {
	mu        sync.Mutex
	permitted map[string]bool
	enabled   map[string]bool
	sets      []string
}

func (f *fakeGatewayTools) CanAddServers(_ context.Context, userID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.permitted[userID]
}

func (f *fakeGatewayTools) GatewayToolsEnabled(_ context.Context, userID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled[userID], nil
}

func (f *fakeGatewayTools) SetGatewayToolsEnabled(_ context.Context, userID string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if on && !f.permitted[userID] {
		return permissions.ErrNotPermitted
	}
	f.enabled[userID] = on
	f.sets = append(f.sets, userID)
	return nil
}

func newHarnessWithGatewayTools(t *testing.T) (*harness, *fakeGatewayTools) {
	t.Helper()
	h := newHarness(t)
	gt := &fakeGatewayTools{permitted: map[string]bool{}, enabled: map[string]bool{}}
	p, err := portal.New(h.svc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p.SetGatewayTools(gt)
	h.portal, h.h = p, p.Handler()
	return h, gt
}

var switchRE = regexp.MustCompile(`<input[^>]*name="enabled"[^>]*>`)

func TestAccountGatewayToolsNotPermitted(t *testing.T) {
	h, gt := newHarnessWithGatewayTools(t)
	ck, p := h.session(t, memberSub, "Member")
	rec := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck})
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /account = %d", rec.Code)
	}
	for _, want := range []string{"Gateway management tools", "Ask an admin for a role that may add MCP servers", "gateway.*", "OpenCode"} {
		if !strings.Contains(body, want) {
			t.Errorf("account page lacks %q:\n%s", want, body)
		}
	}
	sw := switchRE.FindString(body)
	if sw == "" || !strings.Contains(sw, "disabled") || strings.Contains(sw, "checked") || !strings.Contains(sw, `role="switch"`) {
		t.Errorf("switch = %q, want a disabled, unchecked switch", sw)
	}
	navtest.AssertShell(t, "/account", body)

	// Posting anyway is refused and changes nothing.
	rec = h.do(t, request{method: http.MethodPost, path: "/account/gateway-tools", cookie: ck,
		form: url.Values{"_csrf": {p.CSRFToken}, "enabled": {"on"}}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Ask an admin for a role that may add MCP servers") {
		t.Errorf("POST on without permission = %d:\n%s", rec.Code, rec.Body)
	}
	if gt.enabled[p.UserID] {
		t.Error("toggle stored without permission")
	}
}

func TestAccountGatewayToolsPermittedToggle(t *testing.T) {
	h, gt := newHarnessWithGatewayTools(t)
	ck, p := h.session(t, memberSub, "Member")
	gt.permitted[p.UserID] = true

	body := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck}).Body.String()
	sw := switchRE.FindString(body)
	if sw == "" || strings.Contains(sw, "disabled") || strings.Contains(sw, "checked") {
		t.Errorf("switch = %q, want an enabled, unchecked switch", sw)
	}
	if strings.Contains(body, "Ask an admin for a role that may add MCP servers") {
		t.Error("permitted user told to ask an admin")
	}
	if !strings.Contains(body, `action="/account/gateway-tools"`) || !strings.Contains(body, `name="_csrf" value="`+p.CSRFToken+`"`) {
		t.Errorf("toggle form lacks action or CSRF token:\n%s", body)
	}

	// On.
	rec := h.do(t, request{method: http.MethodPost, path: "/account/gateway-tools", cookie: ck,
		form: url.Values{"_csrf": {p.CSRFToken}, "enabled": {"on"}}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account#gateway-tools" {
		t.Fatalf("POST on = %d %q:\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if !gt.enabled[p.UserID] {
		t.Fatal("toggle not stored")
	}
	body = h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck}).Body.String()
	if sw := switchRE.FindString(body); !strings.Contains(sw, "checked") {
		t.Errorf("switch after on = %q, want checked", sw)
	}
	// Off: an unchecked box posts no "enabled" field.
	rec = h.do(t, request{method: http.MethodPost, path: "/account/gateway-tools", cookie: ck,
		form: url.Values{"_csrf": {p.CSRFToken}}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST off = %d", rec.Code)
	}
	if gt.enabled[p.UserID] {
		t.Error("toggle still on")
	}
}

// Losing the permission shows the stored "on" as off and disabled, and
// still lets the user turn it off.
func TestAccountGatewayToolsPermissionTakenAway(t *testing.T) {
	h, gt := newHarnessWithGatewayTools(t)
	ck, p := h.session(t, memberSub, "Member")
	gt.enabled[p.UserID] = true
	body := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck}).Body.String()
	if sw := switchRE.FindString(body); !strings.Contains(sw, "disabled") || strings.Contains(sw, "checked") {
		t.Errorf("switch = %q, want disabled and unchecked", sw)
	}
	rec := h.do(t, request{method: http.MethodPost, path: "/account/gateway-tools", cookie: ck,
		form: url.Values{"_csrf": {p.CSRFToken}}})
	if rec.Code != http.StatusSeeOther || gt.enabled[p.UserID] {
		t.Errorf("turning off without permission = %d, enabled %v", rec.Code, gt.enabled[p.UserID])
	}
}

func TestAccountGatewayToolsCSRF(t *testing.T) {
	h, gt := newHarnessWithGatewayTools(t)
	ck, p := h.session(t, memberSub, "Member")
	gt.permitted[p.UserID] = true
	rec := h.do(t, request{method: http.MethodPost, path: "/account/gateway-tools", cookie: ck,
		form: url.Values{"_csrf": {"forged"}, "enabled": {"on"}}})
	if rec.Code != http.StatusForbidden || gt.enabled[p.UserID] {
		t.Errorf("forged POST = %d, enabled %v", rec.Code, gt.enabled[p.UserID])
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/account/gateway-tools", form: url.Values{"enabled": {"on"}}})
	if rec.Code == http.StatusSeeOther && rec.Header().Get("Location") == "/account#gateway-tools" {
		t.Error("anonymous POST accepted")
	}
}

// Without the setting wired (no database) the section is absent and the
// route does not exist.
func TestAccountWithoutGatewayTools(t *testing.T) {
	h := newHarness(t)
	ck, p := h.session(t, memberSub, "Member")
	body := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck}).Body.String()
	if strings.Contains(body, "Gateway management tools") {
		t.Error("section shown without the setting")
	}
	rec := h.do(t, request{method: http.MethodPost, path: "/account/gateway-tools", cookie: ck,
		form: url.Values{"_csrf": {p.CSRFToken}, "enabled": {"on"}}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST without the setting = %d, want 404", rec.Code)
	}
}

// A store failure is a server error, not a silent success.
func TestAccountGatewayToolsStoreFailure(t *testing.T) {
	h := newHarness(t)
	p, err := portal.New(h.svc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p.SetGatewayTools(failingGatewayTools{})
	h.h = p.Handler()
	ck, pr := h.session(t, memberSub, "Member")
	rec := h.do(t, request{method: http.MethodPost, path: "/account/gateway-tools", cookie: ck,
		form: url.Values{"_csrf": {pr.CSRFToken}, "enabled": {"on"}}})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("POST with a failing store = %d, want 500", rec.Code)
	}
}

type failingGatewayTools struct{}

func (failingGatewayTools) CanAddServers(context.Context, string) bool { return true }
func (failingGatewayTools) GatewayToolsEnabled(context.Context, string) (bool, error) {
	return false, errors.New("db down")
}
func (failingGatewayTools) SetGatewayToolsEnabled(context.Context, string, bool) error {
	return errors.New("db down")
}
