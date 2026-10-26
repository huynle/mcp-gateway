package machines

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
)

// /activate serves harness device grants (RFC 8628, internal/authserver)
// next to machine device requests: one code box, the code decides which
// kind of request it confirms.

// fakeHarness is the authorization server's side of /activate.
type fakeHarness struct {
	mu      sync.Mutex
	grants  map[string]*authserver.DeviceGrantView // by normalized user code
	decided map[string]string                      // grant id -> "approved:<user>" | "denied:<user>"
}

func newFakeHarness() *fakeHarness {
	return &fakeHarness{grants: map[string]*authserver.DeviceGrantView{}, decided: map[string]string{}}
}

// add registers the grant harnessGrantID under userCode.
func (f *fakeHarness) add(userCode string) {
	n, _ := NormalizeUserCode(userCode)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[n] = &authserver.DeviceGrantView{
		ID: harnessGrantID, ClientName: "Remote <Claude>", ClientID: "gwc_remote", Scope: "mcp:read",
		Scopes: []string{"Read-only access to the tools your role allows (mcp:read)"}, Resource: "https://gw.example.com/mcp",
		RequestIP: "203.0.113.77", UserAgent: "remote-harness/1.4 (linux; ssh)", CreatedAt: time.Unix(1_800_000_000, 0), ExpiresAt: time.Unix(1_800_000_600, 0),
	}
}

func (f *fakeHarness) LookupDeviceGrant(_ context.Context, userCode string) (*authserver.DeviceGrantView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := NormalizeUserCode(userCode)
	g := f.grants[n]
	if !ok || g == nil || f.decided[g.ID] != "" {
		return nil, authserver.ErrDeviceGrantGone
	}
	cp := *g
	cp.UserCode = FormatUserCode(n)
	return &cp, nil
}

func (f *fakeHarness) decide(userID, id, how string) (*authserver.DeviceGrantView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, g := range f.grants {
		if g.ID == id && f.decided[id] == "" {
			f.decided[id] = how + ":" + userID
			cp := *g
			return &cp, nil
		}
	}
	return nil, authserver.ErrDeviceGrantGone
}

func (f *fakeHarness) ApproveDeviceGrant(_ context.Context, userID, id string) (*authserver.DeviceGrantView, error) {
	return f.decide(userID, id, "approved")
}

func (f *fakeHarness) DenyDeviceGrant(_ context.Context, userID, id string) error {
	_, err := f.decide(userID, id, "denied")
	return err
}

func (f *fakeHarness) decision() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decided[harnessGrantID]
}

// activateServer serves a portal (svc may be nil: harness grants only)
// with harness grants attached.
func activateServer(t *testing.T, svc *Service, h HarnessGrants) *httptest.Server {
	t.Helper()
	p := NewPortal(svc, func(r *http.Request) (string, string, bool) {
		return r.Header.Get("X-Test-User"), csrf, false
	}, slog.New(slog.DiscardHandler))
	p.SetHarnessGrants(h)
	mux := http.NewServeMux()
	p.Mount(func(pattern string, h http.Handler) { mux.Handle(pattern, h) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.Header.Get("X-Test-User"); u != "" {
			r = r.WithContext(nav.WithData(r.Context(), nav.Data{SignedIn: true, CSRFToken: csrf}))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

const harnessGrantID = "00000000-0000-4000-8000-0000000000aa"

func TestActivateHarnessGrantNeedsExplicitAllow(t *testing.T) {
	e := newEnv(t)
	h := newFakeHarness()
	h.add("BCDF-GHJK")
	srv := activateServer(t, e.svc, h)

	// A prefilled code only shows the request: nothing is decided.
	code, html, hdr := page(t, srv, http.MethodGet, "/activate?code=bcdfghjk", alice, false, nil)
	if code != http.StatusOK {
		t.Fatalf("confirm = %d\n%s", code, html)
	}
	for _, want := range []string{"BCDF-GHJK", "Remote &lt;Claude&gt;", "gwc_remote", "Read-only access", "203.0.113.77", "remote-harness/1.4 (linux; ssh)",
		"Allow", "Deny", `value="` + csrf + `"`, `value="` + harnessGrantID + `"`} {
		if !strings.Contains(html, want) {
			t.Errorf("harness confirm page lacks %q", want)
		}
	}
	if strings.Contains(html, "Key fingerprint") {
		t.Errorf("harness confirm page shows machine fields")
	}
	if hdr.Get("X-Frame-Options") != "DENY" || !strings.Contains(hdr.Get("Content-Security-Policy"), "frame-ancestors 'none'") || hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", hdr)
	}
	if d := h.decision(); d != "" {
		t.Fatalf("GET decided the grant: %s", d)
	}
	// Approval needs the CSRF token ...
	if code, _, _ := page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"action": {"approve"}, "request_id": {harnessGrantID}, "code": {"BCDF-GHJK"}}); code != http.StatusForbidden {
		t.Fatalf("approve without CSRF = %d", code)
	}
	// ... and the request id must belong to the code.
	page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"_csrf": {csrf}, "action": {"approve"}, "request_id": {"00000000-0000-4000-8000-0000000000bb"}, "code": {"BCDF-GHJK"}})
	if d := h.decision(); d != "" {
		t.Fatalf("approved with a mismatched request id: %s", d)
	}
	code, html, _ = page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"_csrf": {csrf}, "action": {"approve"}, "request_id": {harnessGrantID}, "code": {"BCDF-GHJK"}})
	if code != http.StatusOK || !strings.Contains(html, "Harness connected") || !strings.Contains(html, "/harnesses") {
		t.Fatalf("approve = %d\n%s", code, html)
	}
	if d := h.decision(); d != "approved:"+alice {
		t.Fatalf("decision = %q", d)
	}
	// The code is spent.
	if _, html, _ := page(t, srv, http.MethodGet, "/activate?code=BCDF-GHJK", alice, false, nil); !strings.Contains(html, "No pending request") {
		t.Fatalf("spent code:\n%s", html)
	}
}

func TestActivateHarnessGrantDeny(t *testing.T) {
	e := newEnv(t)
	h := newFakeHarness()
	h.add("BCDF-GHJK")
	srv := activateServer(t, e.svc, h)
	code, html, _ := page(t, srv, http.MethodPost, "/activate", bob, false, url.Values{"_csrf": {csrf}, "action": {"deny"}, "request_id": {harnessGrantID}, "code": {"BCDF-GHJK"}})
	if code != http.StatusOK || !strings.Contains(html, "denied") {
		t.Fatalf("deny = %d\n%s", code, html)
	}
	if d := h.decision(); d != "denied:"+bob {
		t.Fatalf("decision = %q", d)
	}
}

func TestActivateStillServesMachineRequestsWithHarnessGrants(t *testing.T) {
	e := newEnv(t)
	h := newFakeHarness()
	srv := activateServer(t, e.svc, h)
	body, _ := e.requestDevice("huy-macbook")
	uc := body["user_code"].(string)
	_, html, _ := page(t, srv, http.MethodGet, "/activate?code="+url.QueryEscape(uc), alice, false, nil)
	if !strings.Contains(html, "huy-macbook") || !strings.Contains(html, "Key fingerprint") {
		t.Fatalf("machine confirm page:\n%s", html)
	}
}

// A code both kinds claim is never confirmed: neither request can be
// approved through it (the store prevents this; the page fails safe).
func TestActivateRefusesACodeBothKindsHold(t *testing.T) {
	e := newEnv(t)
	h := newFakeHarness()
	srv := activateServer(t, e.svc, h)
	body, _ := e.requestDevice("laptop")
	uc := body["user_code"].(string)
	h.add(uc)
	code, html, _ := page(t, srv, http.MethodGet, "/activate?code="+url.QueryEscape(uc), alice, false, nil)
	if code != http.StatusOK || !strings.Contains(html, "No pending request") || strings.Contains(html, "laptop") {
		t.Fatalf("ambiguous code = %d\n%s", code, html)
	}
	page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"_csrf": {csrf}, "action": {"approve"}, "request_id": {harnessGrantID}, "code": {uc}})
	if d := h.decision(); d != "" {
		t.Fatalf("ambiguous code approved: %s", d)
	}
}

func TestActivateWithoutMachines(t *testing.T) {
	h := newFakeHarness()
	h.add("BCDF-GHJK")
	srv := activateServer(t, nil, h)
	code, html, _ := page(t, srv, http.MethodGet, "/activate?code=BCDF-GHJK", alice, false, nil)
	if code != http.StatusOK || !strings.Contains(html, "Remote &lt;Claude&gt;") {
		t.Fatalf("harness-only /activate = %d\n%s", code, html)
	}
	if code, _, _ := page(t, srv, http.MethodGet, "/machines", alice, false, nil); code != http.StatusNotFound {
		t.Fatalf("/machines without machines = %d", code)
	}
	code, html, _ = page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"_csrf": {csrf}, "action": {"approve"}, "request_id": {harnessGrantID}, "code": {"BCDF-GHJK"}})
	if code != http.StatusOK || h.decision() != "approved:"+alice {
		t.Fatalf("approve = %d %q\n%s", code, h.decision(), html)
	}
}

// Wrong codes are limited per user and per address, whichever kind the
// code was meant for.
func TestActivateLimitsWrongCodesPerUserAndAddress(t *testing.T) {
	h := newFakeHarness()
	h.add("BCDF-GHJK")
	srv := activateServer(t, nil, h)
	limited := 0
	for i := range 12 {
		code, html, _ := page(t, srv, http.MethodGet, "/activate?code=ZZZZ-ZZZZ", alice, false, nil)
		if code == http.StatusTooManyRequests && strings.Contains(html, "Too many wrong codes") {
			limited = i
			break
		}
	}
	if limited == 0 || limited > 10 {
		t.Fatalf("per-user limit hit after %d wrong codes", limited)
	}
	// Once limited, even the right code is refused (no oracle).
	if code, _, _ := page(t, srv, http.MethodGet, "/activate?code=BCDF-GHJK", alice, false, nil); code != http.StatusTooManyRequests {
		t.Fatalf("right code while limited = %d", code)
	}
	if code, _, _ := page(t, srv, http.MethodPost, "/activate", alice, false, url.Values{"_csrf": {csrf}, "action": {"lookup"}, "code": {"BCDF-GHJK"}}); code != http.StatusTooManyRequests {
		t.Fatalf("POST lookup while limited = %d", code)
	}
	// Many users behind one address share the address budget.
	ipLimited := false
	for i := range 60 {
		user := "00000000-0000-4000-8000-1" + strings.Repeat("0", 9) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if code, _, _ := page(t, srv, http.MethodGet, "/activate?code=ZZZZ-ZZZZ", user, false, nil); code == http.StatusTooManyRequests {
			ipLimited = true
			break
		}
	}
	if !ipLimited {
		t.Fatal("60 wrong codes from one address across users were never limited")
	}
}
