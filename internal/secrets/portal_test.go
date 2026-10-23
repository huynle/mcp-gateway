package secrets_test

import (
	"bytes"
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
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/secrets/ref"
	"github.com/huynle/mcp-gateway/internal/secrets/secretstest"
)

const (
	pageCSRF    = "csrf-token-value"
	serverName  = "vault-prod"
	harnessName = "Claude Code on laptop"
)

// syncBuffer is a log sink the race detector accepts.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeAudit collects the recorded events.
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

// pages mounts the secret pages on a plain mux through the same Mount
// callback the portal supplies; who returns the configured user.
type pages struct {
	svc    *secrets.Service
	mem    *secretstest.MemStore
	clk    *clock
	mux    *http.ServeMux
	user   string
	logs   *syncBuffer
	audit  *fakeAudit
	bodies []string // every response body, for the never-echoed checks
}

func newPages(t *testing.T, named bool) *pages {
	t.Helper()
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mem := secretstest.NewMemStore()
	svc, err := secrets.New(mem, keys, secrets.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	svc.SetClock(clk.Now)
	p := &pages{svc: svc, mem: mem, clk: clk, mux: http.NewServeMux(), user: alice, logs: logs, audit: &fakeAudit{}}
	who := func(*http.Request) (string, string) {
		if p.user == "" {
			return "", ""
		}
		return p.user, pageCSRF
	}
	opts := secrets.PortalOptions{Log: log, Audit: p.audit}
	if named {
		opts.Servers = secrets.ServerNamerFunc(func(_ context.Context, owner, id string) (string, error) {
			if owner == alice && id == server {
				return serverName, nil
			}
			return "", errors.New("no such server")
		})
		opts.Harnesses = secrets.HarnessNamerFunc(func(_ context.Context, owner, id string) (string, error) {
			if owner == alice && id == harness {
				return harnessName, nil
			}
			return "", errors.New("no such harness")
		})
	}
	secrets.NewPortal(svc, who, opts).Mount(p.mux.Handle)
	return p
}

func (p *pages) serve(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	p.mux.ServeHTTP(rec, req)
	p.bodies = append(p.bodies, rec.Body.String())
	return rec
}

func (p *pages) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return p.serve(t, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
}

func (p *pages) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return p.serve(t, req)
}

func (p *pages) request(t *testing.T, owner, label string, b secrets.Binding, uses int) secrets.Requested {
	t.Helper()
	r, err := p.svc.Request(context.Background(), owner, harness, label, b, 0, uses)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return r
}

func save(v string) url.Values {
	return url.Values{"_csrf": {pageCSRF}, "action": {"save"}, "value": {v}}
}

func deny() url.Values { return url.Values{"_csrf": {pageCSRF}, "action": {"deny"}} }

// assertNoValue fails when v appears in any response body or the logs.
func (p *pages) assertNoValue(t *testing.T, v string) {
	t.Helper()
	for i, b := range p.bodies {
		if strings.Contains(b, v) || strings.Contains(b, url.QueryEscape(v)) {
			t.Errorf("response %d echoes the value:\n%s", i, b)
		}
	}
	if logs := p.logs.String(); strings.Contains(logs, v) {
		t.Errorf("logs contain the value:\n%s", logs)
	}
}

func TestFingerprintMatchesOnBothSides(t *testing.T) {
	p := newPages(t, false)
	r := p.request(t, alice, "vault password", binding, 1)
	got := secrets.FingerprintForRequest(r.RequestID)
	if got != secrets.FingerprintForHandle(r.Handle) {
		t.Errorf("FingerprintForRequest = %q, FingerprintForHandle = %q", got, secrets.FingerprintForHandle(r.Handle))
	}
	if got != ref.Fingerprint(secrets.RequestIDForHandle(r.Handle)) || len(strings.Split(got, "-")) != ref.FingerprintWords {
		t.Errorf("fingerprint %q is not the 4 words of the request id", got)
	}
}

func TestEntryPageShowsTheRequest(t *testing.T) {
	p := newPages(t, true)
	r := p.request(t, alice, "vault <password>", binding, 3)
	rec := p.get(t, "/s/"+r.RequestID)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET entry = %d:\n%s", rec.Code, body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if xfo := rec.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("X-Frame-Options = %q", xfo)
	}
	for _, want := range []string{
		harnessName, "vault &lt;password&gt;", serverName, "vault.login", "password",
		"15m", "3 uses", secrets.FingerprintForRequest(r.RequestID), "Check that your agent shows the same words",
		`<input type="password" name="value" autocomplete="off" required minlength="8" maxlength="4096">`,
		`action="/s/` + r.RequestID + `"`, `name="action" value="save"`, `name="action" value="deny"`,
		`name="_csrf" value="` + pageCSRF + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("entry page lacks %q:\n%s", want, body)
		}
	}
	navtest.AssertShell(t, "/s/{id}", body)
}

func TestEntryPageFallsBackToIDsAndShowsMachineActions(t *testing.T) {
	p := newPages(t, false)
	r := p.request(t, alice, "sudo on box", secrets.Binding{ServerID: server, Tool: "box-actions.restart"}, 1)
	body := p.get(t, "/s/"+r.RequestID).Body.String()
	for _, want := range []string{harness, server, "machine action <code>box-actions.restart</code>", "1 use"} {
		if !strings.Contains(body, want) {
			t.Errorf("entry page lacks %q:\n%s", want, body)
		}
	}
}

func TestEntryPageNotFoundIsUniform(t *testing.T) {
	p := newPages(t, true)
	unknown := p.get(t, "/s/"+strings.Repeat("Z", 43))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown id = %d", unknown.Code)
	}
	want := unknown.Body.String()
	if !strings.Contains(want, "Page not found") || !strings.Contains(want, "There is no page at this address.") {
		t.Errorf("404 is not the portal's unknown page:\n%s", want)
	}
	if cc := unknown.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("404 Cache-Control = %q", cc)
	}

	mine := p.request(t, alice, "vault password", binding, 1)
	expired := p.request(t, alice, "old one", binding, 1)
	saved := p.request(t, alice, "saved one", binding, 1)
	denied := p.request(t, alice, "denied one", binding, 1)
	if rec := p.post(t, "/s/"+saved.RequestID, save(value)); rec.Code != http.StatusOK {
		t.Fatalf("save = %d", rec.Code)
	}
	if rec := p.post(t, "/s/"+denied.RequestID, deny()); rec.Code != http.StatusOK {
		t.Fatalf("deny = %d", rec.Code)
	}

	check := func(what string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusNotFound || rec.Body.String() != want {
			t.Errorf("%s = %d, want the unknown-page 404:\n%s", what, rec.Code, rec.Body)
		}
	}
	check("malformed id", p.get(t, "/s/not-a-request"))
	check("already saved", p.get(t, "/s/"+saved.RequestID))
	check("second save", p.post(t, "/s/"+saved.RequestID, save(value)))
	check("denied", p.get(t, "/s/"+denied.RequestID))
	check("second deny", p.post(t, "/s/"+denied.RequestID, deny()))

	p.user = bob
	check("other user GET", p.get(t, "/s/"+mine.RequestID))
	check("other user save", p.post(t, "/s/"+mine.RequestID, save(value)))
	check("other user deny", p.post(t, "/s/"+mine.RequestID, deny()))
	if got := p.mem.Record(mine.Secret.ID); got.State != secrets.StatePending || got.Value != nil {
		t.Errorf("bob changed alice's request: %+v", got)
	}

	p.user = alice
	p.clk.Advance(secrets.LinkTTL + time.Second)
	check("expired link GET", p.get(t, "/s/"+expired.RequestID))
	check("expired link save", p.post(t, "/s/"+expired.RequestID, save(value)))
	p.assertNoValue(t, value)
}

func TestSaveStoresTheValueWithoutEchoingIt(t *testing.T) {
	p := newPages(t, true)
	r := p.request(t, alice, "vault password", binding, 1)
	const v = "s3cr3t-Value-Never-Echoed"
	rec := p.post(t, "/s/"+r.RequestID, save(v))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Saved. Return to your agent; it can retry now.") {
		t.Fatalf("save = %d:\n%s", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("done page Cache-Control = %q", cc)
	}
	got := p.mem.Record(r.Secret.ID)
	if got.State != secrets.StateProvided || got.Value == nil {
		t.Fatalf("after save: %+v", got)
	}
	c, err := p.svc.Consume(context.Background(), alice, harness, r.Handle, binding)
	if err != nil || string(c.Value) != v {
		t.Fatalf("consume after save = %q, %v", c.Value, err)
	}
	evs := p.audit.all()
	if len(evs) != 1 || evs[0].ResourceIdentity["action"] != "secret.provided" ||
		evs[0].ResourceIdentity["secret_id"] != r.Secret.ID || evs[0].ResourceIdentity["label"] != "vault password" ||
		evs[0].UserID != alice {
		t.Errorf("audit = %+v", evs)
	}
	p.get(t, "/secrets")
	p.assertNoValue(t, v)
}

func TestDenyThroughThePage(t *testing.T) {
	p := newPages(t, true)
	r := p.request(t, alice, "vault password", binding, 1)
	rec := p.post(t, "/s/"+r.RequestID, deny())
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Denied") {
		t.Fatalf("deny = %d:\n%s", rec.Code, rec.Body)
	}
	if got := p.mem.Record(r.Secret.ID); got.State != secrets.StateDenied {
		t.Errorf("after deny: %+v", got)
	}
	if evs := p.audit.all(); len(evs) != 1 || evs[0].ResourceIdentity["action"] != "secret.denied" || evs[0].ResourceIdentity["secret_id"] != r.Secret.ID {
		t.Errorf("audit = %+v", evs)
	}
}

func TestInvalidValuesRerenderWithoutTheValue(t *testing.T) {
	p := newPages(t, true)
	r := p.request(t, alice, "vault password", binding, 1)
	const short = "Qz7#xY1"
	rec := p.post(t, "/s/"+r.RequestID, save(short))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "at least 8") ||
		!strings.Contains(rec.Body.String(), `name="value"`) {
		t.Errorf("too short = %d:\n%s", rec.Code, rec.Body)
	}
	long := strings.Repeat("Lq", 2049)
	rec = p.post(t, "/s/"+r.RequestID, save(long))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "at most 4096") {
		t.Errorf("too long = %d:\n%s", rec.Code, rec.Body)
	}
	if got := p.mem.Record(r.Secret.ID); got.State != secrets.StatePending || got.Value != nil {
		t.Errorf("invalid value changed the request: %+v", got)
	}
	if evs := p.audit.all(); len(evs) != 0 {
		t.Errorf("invalid value audited: %+v", evs)
	}
	p.assertNoValue(t, short)
	p.assertNoValue(t, long[:64])
	// The request still accepts a good value.
	if rec := p.post(t, "/s/"+r.RequestID, save(value)); rec.Code != http.StatusOK {
		t.Errorf("save after invalid = %d", rec.Code)
	}
}

func TestEntryPostsNeedCSRFAndAKnownAction(t *testing.T) {
	p := newPages(t, true)
	r := p.request(t, alice, "vault password", binding, 1)
	for name, form := range map[string]url.Values{
		"missing": {"action": {"save"}, "value": {value}},
		"wrong":   {"_csrf": {"nope"}, "action": {"deny"}},
	} {
		if rec := p.post(t, "/s/"+r.RequestID, form); rec.Code != http.StatusForbidden {
			t.Errorf("CSRF %s = %d, want 403", name, rec.Code)
		}
	}
	if rec := p.post(t, "/s/"+r.RequestID, url.Values{"_csrf": {pageCSRF}, "action": {"approve"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown action = %d, want 400", rec.Code)
	}
	if got := p.mem.Record(r.Secret.ID); got.State != secrets.StatePending {
		t.Errorf("refused posts changed the request: %+v", got)
	}
	p.assertNoValue(t, value)
}

func TestPagesRefuseAnonymousCallers(t *testing.T) {
	p := newPages(t, true)
	r := p.request(t, alice, "vault password", binding, 1)
	p.user = ""
	for _, rec := range []*httptest.ResponseRecorder{
		p.get(t, "/s/"+r.RequestID),
		p.post(t, "/s/"+r.RequestID, save(value)),
		p.get(t, "/secrets"),
		p.post(t, "/secrets/"+r.Secret.ID+"/revoke", deny()),
	} {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("anonymous = %d, want 401", rec.Code)
		}
	}
	if got := p.mem.Record(r.Secret.ID); got.State != secrets.StatePending {
		t.Errorf("anonymous changed the request: %+v", got)
	}
}

func TestSecretsListShowsOwnRowsWithoutValues(t *testing.T) {
	p := newPages(t, true)
	pending := p.request(t, alice, "pending label", binding, 2)
	live := p.request(t, alice, "live label", binding, 3)
	if _, err := p.svc.Provide(context.Background(), alice, live.RequestID, []byte(value)); err != nil {
		t.Fatal(err)
	}
	ended := p.request(t, alice, "ended label", binding, 1)
	if _, err := p.svc.Deny(context.Background(), alice, ended.RequestID); err != nil {
		t.Fatal(err)
	}
	theirs := p.request(t, bob, "bob label", binding, 1)

	rec := p.get(t, "/secrets")
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /secrets = %d:\n%s", rec.Code, body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	for _, want := range []string{
		"pending label", "live label", "ended label", serverName, "vault.login", "password", "3 / 3", "2 / 2",
		`action="/secrets/` + pending.Secret.ID + `/revoke"`, `action="/secrets/` + live.Secret.ID + `/revoke"`,
		`name="_csrf" value="` + pageCSRF + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `/secrets/`+ended.Secret.ID+`/revoke`) {
		t.Error("ended row has a revoke button")
	}
	if strings.Contains(body, "bob label") || strings.Contains(body, theirs.Secret.ID) {
		t.Error("alice sees bob's secret")
	}
	if i, j := strings.Index(body, "live label"), strings.Index(body, "ended label"); i < 0 || j < i {
		t.Error("ended rows are not listed last")
	}
	navtest.AssertShell(t, "/secrets", body)
	p.assertNoValue(t, value)
}

func TestRevokeOnlyOwnLiveRows(t *testing.T) {
	p := newPages(t, true)
	live := p.request(t, alice, "live label", binding, 1)
	if _, err := p.svc.Provide(context.Background(), alice, live.RequestID, []byte(value)); err != nil {
		t.Fatal(err)
	}
	theirs := p.request(t, bob, "bob label", binding, 1)

	rec := p.post(t, "/secrets/"+theirs.Secret.ID+"/revoke", deny())
	if rec.Code != http.StatusNotFound {
		t.Errorf("revoke bob's = %d, want 404", rec.Code)
	}
	if got := p.mem.Record(theirs.Secret.ID); got.State != secrets.StatePending {
		t.Errorf("alice revoked bob's request: %+v", got)
	}
	if rec := p.post(t, "/secrets/"+live.Secret.ID+"/revoke", url.Values{}); rec.Code != http.StatusForbidden {
		t.Errorf("revoke without CSRF = %d, want 403", rec.Code)
	}
	rec = p.post(t, "/secrets/"+live.Secret.ID+"/revoke", url.Values{"_csrf": {pageCSRF}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/secrets?revoked=1" {
		t.Fatalf("revoke = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := p.mem.Record(live.Secret.ID); got.State != secrets.StateRevoked || got.Value != nil {
		t.Errorf("after revoke: %+v", got)
	}
	if evs := p.audit.all(); len(evs) != 1 || evs[0].ResourceIdentity["action"] != "secret.revoked" ||
		evs[0].ResourceIdentity["secret_id"] != live.Secret.ID || evs[0].ResourceIdentity["label"] != "live label" {
		t.Errorf("audit = %+v", evs)
	}
	if !strings.Contains(p.get(t, "/secrets?revoked=1").Body.String(), "Revoked") {
		t.Error("revoke notice missing")
	}
	for _, id := range []string{live.Secret.ID, "not-a-uuid"} {
		if rec := p.post(t, "/secrets/"+id+"/revoke", url.Values{"_csrf": {pageCSRF}}); rec.Code != http.StatusNotFound {
			t.Errorf("revoke %s again = %d, want 404", id, rec.Code)
		}
	}
}

// The pages mounted through the real portal: anonymous users are sent to
// sign in, the portal's CSRF check and security headers apply.
func TestSecretPagesThroughThePortal(t *testing.T) {
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
	secrets.NewPortal(f.svc, who, secrets.PortalOptions{Log: slog.New(slog.DiscardHandler)}).Mount(pt.MountUser)
	h := pt.Handler()
	res, err := idsvc.SignIn(context.Background(), "dex", identity.Claims{
		Issuer: issuer, Subject: "member", Name: "Member", Email: "member@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, form url.Values, cookie bool) *httptest.ResponseRecorder {
		var body *strings.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		} else {
			body = strings.NewReader("")
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
	r := f.request(t, res.Principal.UserID, 0, 1)

	rec := do(http.MethodGet, "/s/"+r.RequestID, nil, false)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin?return_to=") {
		t.Errorf("anonymous GET = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = do(http.MethodGet, "/s/"+r.RequestID, nil, true)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Frame-Options") != "DENY" ||
		rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("entry = %d %v", rec.Code, rec.Header())
	}
	if !strings.Contains(rec.Body.String(), `href="/secrets"`) {
		t.Errorf("signed-in nav lacks /secrets:\n%s", rec.Body)
	}
	if rec := do(http.MethodPost, "/s/"+r.RequestID, url.Values{"action": {"save"}, "value": {value}}, true); rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", rec.Code)
	}
	if rec := do(http.MethodPost, "/s/"+r.RequestID, url.Values{"_csrf": {res.Principal.CSRFToken}, "action": {"save"}, "value": {value}}, true); rec.Code != http.StatusOK {
		t.Errorf("save through the portal = %d:\n%s", rec.Code, rec.Body)
	}
	if rec := do(http.MethodGet, "/s/"+r.RequestID, nil, true); rec.Code != http.StatusNotFound {
		t.Errorf("used link = %d, want 404", rec.Code)
	}
	if rec := do(http.MethodGet, "/secrets", nil, true); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "vault password") ||
		strings.Contains(rec.Body.String(), value) {
		t.Errorf("/secrets = %d:\n%s", rec.Code, rec.Body)
	}
}

func TestNotFoundHandlerOverridesTheDefaultPage(t *testing.T) {
	f := newFixture(t)
	mux := http.NewServeMux()
	notFound := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "the portal's own 404", http.StatusNotFound)
	})
	who := func(*http.Request) (string, string) { return alice, pageCSRF }
	secrets.NewPortal(f.svc, who, secrets.PortalOptions{NotFound: notFound}).Mount(mux.Handle)
	for _, req := range []*http.Request{
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/s/"+strings.Repeat("Z", 43), nil),
		httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/secrets/00000000-0000-4000-8000-000000000999/revoke",
			strings.NewReader(url.Values{"_csrf": {pageCSRF}}.Encode())),
	} {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "the portal's own 404") {
			t.Errorf("%s %s = %d:\n%s", req.Method, req.URL.Path, rec.Code, rec.Body)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q", req.URL.Path, rec.Header().Get("Cache-Control"))
		}
	}
}
