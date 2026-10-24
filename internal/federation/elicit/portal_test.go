package elicit_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/federation/elicit"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/secrets"
)

// The secrets page limiter fits the interstitial.
var _ elicit.FailureLimiter = (*secrets.AddressLimiter)(nil)

const (
	pageCSRF    = "csrf-token-value"
	serverName  = "notes-prod"
	harnessName = "Claude Code on laptop"
)

type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *fakeAudit) Record(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *fakeAudit) all() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...)
}

// countingLimiter is a FailureLimiter that counts failures and refuses
// once budget failures were recorded.
type countingLimiter struct {
	mu     sync.Mutex
	fails  int
	budget int
}

func (l *countingLimiter) Allow(*http.Request) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fails < l.budget, 1500 * time.Millisecond
}

func (l *countingLimiter) Fail(*http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails++
}

type pages struct {
	*fixture
	mux   *http.ServeMux
	user  string
	audit *fakeAudit
	lim   *countingLimiter
}

func newPages(t *testing.T, opts elicit.PortalOptions) *pages {
	t.Helper()
	p := &pages{fixture: newFixture(t), mux: http.NewServeMux(), user: alice, audit: &fakeAudit{}, lim: &countingLimiter{budget: 1000}}
	who := func(*http.Request) (string, string) {
		if p.user == "" {
			return "", ""
		}
		return p.user, pageCSRF
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	opts.Audit = p.audit
	if opts.FailureLimiter == nil {
		opts.FailureLimiter = p.lim
	}
	elicit.NewPortal(p.svc, who, opts).Mount(p.mux.Handle)
	return p
}

func named() elicit.PortalOptions {
	return elicit.PortalOptions{
		Servers: elicit.ServerNamerFunc(func(_ context.Context, owner, id string) (string, error) {
			if owner == alice && id == server {
				return serverName, nil
			}
			return "", errors.New("no such server")
		}),
		Harnesses: elicit.HarnessNamerFunc(func(_ context.Context, owner, id string) (string, error) {
			if owner == alice && id == harness {
				return harnessName, nil
			}
			return "", errors.New("no such harness")
		}),
	}
}

func (p *pages) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	p.mux.ServeHTTP(rec, req)
	return rec
}

func (p *pages) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return p.serve(httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
}

func (p *pages) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return p.serve(req)
}

func (p *pages) createWith(t *testing.T, owner, rawURL, msg string) string {
	t.Helper()
	link, _, err := p.svc.Create(context.Background(), owner, harness, server, rawURL, upID, msg)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return link
}

func action(a string) url.Values { return url.Values{"_csrf": {pageCSRF}, "action": {a}} }

func assertHeaders(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	for k, want := range map[string]string{"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s: %s = %q, want %q", what, k, got, want)
		}
	}
}

func TestInterstitialShowsTheElicitation(t *testing.T) {
	p := newPages(t, named())
	full := "https://login.connect.example.co.uk/oauth/start?client=notes&state=s1"
	link := p.createWith(t, alice, full, "Sign in to <b>Notes</b>\n<script>alert(1)</script>")
	rec := p.get(t, "/elicit/"+link)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d:\n%s", rec.Code, body)
	}
	assertHeaders(t, "GET", rec)
	for _, want := range []string{
		serverName, harnessName,
		// The full URL, HTML-escaped, in a monospace block.
		`<pre class="elicit-url"><code>https://login.connect.example.co.uk/oauth/start?client=notes&amp;state=s1</code></pre>`,
		// The registrable domain highlighted (fallback: the whole host).
		`<mark>login.connect.example.co.uk</mark>`,
		"Message from " + serverName + " (not verified)",
		"Sign in to &lt;b&gt;Notes&lt;/b&gt;", "&lt;script&gt;alert(1)&lt;/script&gt;",
		`action="/elicit/` + link + `"`, `name="action" value="continue"`, `name="action" value="cancel"`,
		`name="_csrf" value="` + pageCSRF + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	for _, bad := range []string{"<script>alert(1)", "<b>Notes", `href="https://login.connect`, "IDN"} {
		if strings.Contains(body, bad) {
			t.Errorf("page contains %q:\n%s", bad, body)
		}
	}
	navtest.AssertShell(t, "/elicit/{id}", body)
}

func TestInterstitialUsesDomainInfo(t *testing.T) {
	opts := named()
	var asked string
	opts.Domain = func(u string) (string, string, bool) {
		asked = u
		return "login.xn--exmple-cua.com", "xn--exmple-cua.com", true
	}
	p := newPages(t, opts)
	full := "https://login.xn--exmple-cua.com/start"
	link := p.createWith(t, alice, full, "")
	body := p.get(t, "/elicit/"+link).Body.String()
	if asked != full {
		t.Errorf("DomainInfo asked %q, want the stored URL", asked)
	}
	for _, want := range []string{`login.<mark>xn--exmple-cua.com</mark>`, `class="error"`, "international"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	// No message: no message block.
	if strings.Contains(body, "not verified") {
		t.Errorf("empty message rendered:\n%s", body)
	}
}

func TestInterstitialFallbackFlagsPunycodeAndShowsIDs(t *testing.T) {
	p := newPages(t, elicit.PortalOptions{})
	link := p.createWith(t, alice, "https://xn--pple-43d.com/connect", "hi")
	body := p.get(t, "/elicit/"+link).Body.String()
	for _, want := range []string{"international", server, harness, "Message from " + server + " (not verified)"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
}

func TestInterstitialNotFoundIsIdentical(t *testing.T) {
	notFound := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "the portal's own 404", http.StatusNotFound)
	})
	p := newPages(t, elicit.PortalOptions{NotFound: notFound})
	bobs := p.createWith(t, bob, upURL, "")
	cancelled := p.createWith(t, alice, upURL, "")
	if rec := p.post(t, "/elicit/"+cancelled, action("cancel")); rec.Code != http.StatusOK {
		t.Fatalf("cancel = %d", rec.Code)
	}
	expired := p.createWith(t, alice, upURL, "")
	var first string
	check := func(name, id string) {
		t.Helper()
		for _, rec := range []*httptest.ResponseRecorder{p.get(t, "/elicit/"+url.PathEscape(id)), p.post(t, "/elicit/"+url.PathEscape(id), action("continue"))} {
			if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "the portal's own 404") {
				t.Errorf("%s = %d:\n%s", name, rec.Code, rec.Body)
			}
			if first == "" {
				first = rec.Body.String()
			} else if rec.Body.String() != first {
				t.Errorf("%s body differs:\n%s\nvs\n%s", name, rec.Body, first)
			}
			assertHeaders(t, name, rec)
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("%s: Location %q", name, loc)
			}
		}
	}
	cases := map[string]string{
		"other user's (live)": bobs, "cancelled": cancelled,
		"unknown": strings.Repeat("Z", 43), "malformed": "not-base62!", "short": "abc",
	}
	for name, id := range cases {
		check(name, id)
	}
	p.clk.Add(elicit.LinkTTL)
	check("expired", expired)
	if want := 2 * (len(cases) + 1); p.lim.fails != want {
		t.Errorf("limiter failures = %d, want %d", p.lim.fails, want)
	}
}

func TestInterstitialDefaultNotFoundPage(t *testing.T) {
	p := newPages(t, elicit.PortalOptions{})
	rec := p.get(t, "/elicit/"+strings.Repeat("Z", 43))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Page not found") {
		t.Errorf("404 = %d:\n%s", rec.Code, rec.Body)
	}
}

func TestInterstitialLimiterAnswers429(t *testing.T) {
	p := newPages(t, elicit.PortalOptions{})
	p.lim.budget = 1
	if rec := p.get(t, "/elicit/"+strings.Repeat("Z", 43)); rec.Code != http.StatusNotFound {
		t.Fatalf("first = %d", rec.Code)
	}
	link := p.createWith(t, alice, upURL, "")
	rec := p.get(t, "/elicit/"+link)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Errorf("past the budget = %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	assertHeaders(t, "429", rec)
}

func TestInterstitialSignedOutIsRefused(t *testing.T) {
	p := newPages(t, elicit.PortalOptions{})
	link := p.createWith(t, alice, upURL, "")
	p.user = ""
	for _, rec := range []*httptest.ResponseRecorder{p.get(t, "/elicit/"+link), p.post(t, "/elicit/"+link, action("continue"))} {
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("Location") != "" {
			t.Errorf("signed out = %d %q", rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestContinueRedirectsToTheStoredURLOnly(t *testing.T) {
	p := newPages(t, named())
	link := p.createWith(t, alice, upURL, "")
	form := action("continue")
	// Nothing from the request decides the target.
	form.Set("url", "https://evil.example/")
	form.Set("next", "https://evil.example/")
	rec := p.post(t, "/elicit/"+link+"?url=https://evil.example/&return_to=https://evil.example/", form)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != upURL {
		t.Fatalf("continue = %d %q, want 303 to %q", rec.Code, rec.Header().Get("Location"), upURL)
	}
	assertHeaders(t, "continue", rec)
	// Continue may be pressed again within the TTL.
	if rec := p.post(t, "/elicit/"+link, action("continue")); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != upURL {
		t.Errorf("second continue = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	evs := p.audit.all()
	if len(evs) != 2 {
		t.Fatalf("audit = %+v", evs)
	}
	recs := p.mem.all()
	ri := evs[0].ResourceIdentity
	if ri["action"] != "elicit.opened" || ri["server_id"] != server || ri["elicitation_id"] != recs[0].ID || len(ri) != 3 ||
		evs[0].UserID != alice || evs[0].Outcome != "succeeded" {
		t.Errorf("audit event = %+v", evs[0])
	}
	for _, ev := range evs {
		for _, v := range ev.ResourceIdentity {
			if strings.Contains(v, "connect.example.com") || strings.Contains(v, link) {
				t.Errorf("audit carries the URL or link: %+v", ev)
			}
		}
	}
	// After expiry: 404, no redirect.
	p.clk.Add(elicit.LinkTTL)
	if rec := p.post(t, "/elicit/"+link, action("continue")); rec.Code != http.StatusNotFound || rec.Header().Get("Location") != "" {
		t.Errorf("continue after expiry = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestCancelEndsTheElicitation(t *testing.T) {
	p := newPages(t, named())
	link := p.createWith(t, alice, upURL, "")
	rec := p.post(t, "/elicit/"+link, action("cancel"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Cancelled") {
		t.Fatalf("cancel = %d:\n%s", rec.Code, rec.Body)
	}
	assertHeaders(t, "cancel", rec)
	if strings.Contains(rec.Body.String(), upURL) {
		t.Error("done page shows the URL")
	}
	if rec := p.post(t, "/elicit/"+link, action("continue")); rec.Code != http.StatusNotFound {
		t.Errorf("continue after cancel = %d", rec.Code)
	}
	if rec := p.get(t, "/elicit/"+link); rec.Code != http.StatusNotFound {
		t.Errorf("GET after cancel = %d", rec.Code)
	}
	evs := p.audit.all()
	if len(evs) != 1 || evs[0].ResourceIdentity["action"] != "elicit.cancelled" || evs[0].ResourceIdentity["server_id"] != server {
		t.Errorf("audit = %+v", evs)
	}
}

func TestPostNeedsCSRFAndAKnownAction(t *testing.T) {
	p := newPages(t, elicit.PortalOptions{})
	link := p.createWith(t, alice, upURL, "")
	for name, form := range map[string]url.Values{
		"no token":    {"action": {"continue"}},
		"wrong token": {"_csrf": {"nope"}, "action": {"continue"}},
	} {
		rec := p.post(t, "/elicit/"+link, form)
		if rec.Code != http.StatusForbidden || rec.Header().Get("Location") != "" {
			t.Errorf("%s = %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
		assertHeaders(t, name, rec)
	}
	if rec := p.post(t, "/elicit/"+link, action("open")); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown action = %d", rec.Code)
	}
	// Nothing was opened or cancelled.
	if r := p.mem.all()[0]; r.OpenedAt != nil || r.CancelledAt != nil {
		t.Errorf("row changed: %+v", r)
	}
	// The header token works too.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/elicit/"+link, strings.NewReader("action=continue"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", pageCSRF)
	if rec := p.serve(req); rec.Code != http.StatusSeeOther {
		t.Errorf("header token = %d", rec.Code)
	}
}

func TestOtherUserCannotContinueOrCancel(t *testing.T) {
	p := newPages(t, elicit.PortalOptions{})
	link := p.createWith(t, alice, upURL, "")
	p.user = bob
	for _, a := range []string{"continue", "cancel"} {
		if rec := p.post(t, "/elicit/"+link, action(a)); rec.Code != http.StatusNotFound || rec.Header().Get("Location") != "" {
			t.Errorf("bob %s = %d %q", a, rec.Code, rec.Header().Get("Location"))
		}
	}
	p.user = alice
	if rec := p.get(t, "/elicit/"+link); rec.Code != http.StatusOK {
		t.Errorf("alice after bob's attempts = %d", rec.Code)
	}
	if n := len(p.audit.all()); n != 0 {
		t.Errorf("%d audit events", n)
	}
}

// Mounted through the real portal: anonymous users are sent to sign in,
// the portal's CSRF check and security headers apply.
func TestInterstitialThroughThePortal(t *testing.T) {
	const issuer = "http://localhost:15556/dex"
	ist := identitytest.NewMemStore()
	idsvc, err := identity.New(identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "Local dex", Issuer: issuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, ist, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := portal.New(idsvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	who := func(r *http.Request) (string, string) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", ""
		}
		return pr.UserID, pr.CSRFToken
	}
	elicit.NewPortal(f.svc, who, elicit.PortalOptions{Log: slog.New(slog.DiscardHandler)}).Mount(pt.MountUser)
	h := pt.Handler()
	res, err := idsvc.SignIn(context.Background(), "dex", identity.Claims{
		Issuer: issuer, Subject: "member", Name: "Member", Email: "member@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, form url.Values, cookie bool) *httptest.ResponseRecorder {
		body := strings.NewReader("")
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req := httptest.NewRequestWithContext(context.Background(), method, path, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cookie {
			req.AddCookie(res.Cookie)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	link, _, err := f.svc.Create(context.Background(), res.Principal.UserID, harness, server, upURL, upID, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := do(http.MethodGet, "/elicit/"+link, nil, false)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin?return_to=") {
		t.Errorf("anonymous GET = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = do(http.MethodGet, "/elicit/"+link, nil, true)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("page = %d %v", rec.Code, rec.Header())
	}
	if rec := do(http.MethodPost, "/elicit/"+link, url.Values{"action": {"continue"}}, true); rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", rec.Code)
	}
	rec = do(http.MethodPost, "/elicit/"+link, url.Values{"_csrf": {res.Principal.CSRFToken}, "action": {"continue"}}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != upURL {
		t.Errorf("continue through the portal = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
