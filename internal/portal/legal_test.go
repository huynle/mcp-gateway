package portal_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// Unset, the legal settings are safe placeholders and the draft marker is
// on: a fresh deployment never shows texts that look reviewed.
func TestLegalFromEnvDefaults(t *testing.T) {
	l, err := portal.LegalFromEnv(envMap(nil))
	if err != nil {
		t.Fatalf("LegalFromEnv: %v", err)
	}
	if !l.Draft {
		t.Error("Draft = false by default, want true")
	}
	want := []string{"GATEWAY_LEGAL_OPERATOR_NAME", "GATEWAY_LEGAL_CONTACT_EMAIL", "GATEWAY_LEGAL_JURISDICTION", "GATEWAY_LEGAL_EFFECTIVE_DATE"}
	if got := l.Placeholders(); !slices.Equal(got, want) {
		t.Errorf("Placeholders = %v, want %v", got, want)
	}
	for _, s := range []string{l.OperatorDisplay(), l.JurisdictionDisplay(), l.EffectiveDisplay(), l.ContactDisplay()} {
		if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
			t.Errorf("placeholder %q is not bracketed", s)
		}
	}
	if l.ContactMailto() != "" {
		t.Errorf("ContactMailto = %q without an address, want empty", l.ContactMailto())
	}
}

func TestLegalFromEnvValues(t *testing.T) {
	l, err := portal.LegalFromEnv(envMap(map[string]string{
		"GATEWAY_LEGAL_OPERATOR_NAME":  "  Example Labs LLC ",
		"GATEWAY_LEGAL_CONTACT_EMAIL":  "privacy@example.com",
		"GATEWAY_LEGAL_JURISDICTION":   "the State of Washington, USA",
		"GATEWAY_LEGAL_EFFECTIVE_DATE": "2026-10-18",
		"GATEWAY_LEGAL_DRAFT":          "false",
	}))
	if err != nil {
		t.Fatalf("LegalFromEnv: %v", err)
	}
	if l.Draft || l.OperatorName != "Example Labs LLC" || l.ContactEmail != "privacy@example.com" ||
		l.Jurisdiction != "the State of Washington, USA" || !l.EffectiveDate.Equal(time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Legal = %+v", l)
	}
	if got := l.Placeholders(); len(got) != 0 {
		t.Errorf("Placeholders = %v, want none", got)
	}
	if l.EffectiveDisplay() != "18 October 2026" || l.ContactMailto() != "mailto:privacy@example.com" {
		t.Errorf("EffectiveDisplay %q, ContactMailto %q", l.EffectiveDisplay(), l.ContactMailto())
	}
}

// Bad values fail startup with the variable's name.
func TestLegalFromEnvRejectsBadValues(t *testing.T) {
	for name, val := range map[string]string{
		"GATEWAY_LEGAL_DRAFT":          "maybe",
		"GATEWAY_LEGAL_CONTACT_EMAIL":  "not-an-email",
		"GATEWAY_LEGAL_EFFECTIVE_DATE": "18/10/2026",
		"GATEWAY_LEGAL_OPERATOR_NAME":  "Example\nLabs",
		"GATEWAY_LEGAL_JURISDICTION":   strings.Repeat("x", 201),
	} {
		_, err := portal.LegalFromEnv(envMap(map[string]string{name: val}))
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s=%q: err = %v, want an error naming the variable", name, val, err)
		}
	}
	// A display-name form is not a bare address (it would render oddly in
	// the mailto link).
	if _, err := portal.LegalFromEnv(envMap(map[string]string{"GATEWAY_LEGAL_CONTACT_EMAIL": "Ada <ada@example.com>"})); err == nil {
		t.Error("display-name address accepted")
	}
}

func legalHarness(t *testing.T, l portal.Legal) *harness {
	t.Helper()
	h := newHarness(t)
	h.portal.SetLegal(l)
	h.h = h.portal.Handler()
	return h
}

var configured = portal.Legal{
	OperatorName:  "Ada & Co <Labs>",
	ContactEmail:  "privacy@example.com",
	Jurisdiction:  "England and Wales",
	EffectiveDate: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC),
	Draft:         false,
}

// The public pages answer anonymous visitors with 200 (Google, Slack and
// GitHub reviewers must reach them without signing in), on the shared
// shell, with the hardening headers, and they link each other.
func TestPublicPagesAreServedAnonymously(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/", "/privacy", "/terms", "/support"} {
		rec := h.do(t, request{method: http.MethodGet, path: path})
		if rec.Code != http.StatusOK {
			t.Errorf("anonymous GET %s = %d %q, want 200", path, rec.Code, rec.Header().Get("Location"))
			continue
		}
		hd := rec.Header()
		if !strings.HasPrefix(hd.Get("Content-Type"), "text/html") || hd.Get("Content-Security-Policy") != portal.CSP ||
			hd.Get("X-Frame-Options") != "DENY" || hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s headers = %v", path, hd)
		}
		if !strings.Contains(hd.Get("Vary"), "Cookie") {
			t.Errorf("GET %s: Vary = %q, want Cookie (signed-in responses differ)", path, hd.Get("Vary"))
		}
		body := rec.Body.String()
		navtest.AssertShell(t, path, body)
		for _, want := range []string{`href="/privacy"`, `href="/terms"`, `href="/support"`, `<footer class="site-footer"`} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s lacks %s", path, want)
			}
		}
	}
	home := h.do(t, request{method: http.MethodGet, path: "/"}).Body.String()
	for _, want := range []string{"<h1>", `href="/signin"`, "Model Context Protocol", "Local dex", "Google Workspace"} {
		if !strings.Contains(home, want) {
			t.Errorf("home page lacks %q", want)
		}
	}
}

// Signed in, / keeps going to My account; the legal pages render with the
// user's nav and are never cached (the nav carries the CSRF token).
func TestPublicPagesSignedIn(t *testing.T) {
	h := newHarness(t)
	ck, _ := h.session(t, memberSub, "Member")
	rec := h.do(t, request{method: http.MethodGet, path: "/", cookie: ck})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
		t.Errorf("signed-in GET / = %d %q, want 303 /account", rec.Code, rec.Header().Get("Location"))
	}
	for _, path := range []string{"/privacy", "/terms", "/support"} {
		rec := h.do(t, request{method: http.MethodGet, path: path, cookie: ck})
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("signed-in GET %s = %d, Cache-Control %q", path, rec.Code, rec.Header().Get("Cache-Control"))
		}
		if !strings.Contains(rec.Body.String(), `action="/auth/signout"`) {
			t.Errorf("signed-in GET %s lacks the user's nav", path)
		}
	}
	anon := h.do(t, request{method: http.MethodGet, path: "/privacy"})
	if cc := anon.Header().Get("Cache-Control"); cc == "no-store" || !strings.Contains(cc, "max-age=") {
		t.Errorf("anonymous /privacy Cache-Control = %q, want a short public max-age", cc)
	}
}

// The texts carry the operator's values (escaped) and the disclosures the
// app listings need.
func TestLegalPagesRenderConfiguredValues(t *testing.T) {
	h := legalHarness(t, configured)
	privacy := h.do(t, request{method: http.MethodGet, path: "/privacy"}).Body.String()
	terms := h.do(t, request{method: http.MethodGet, path: "/terms"}).Body.String()
	support := h.do(t, request{method: http.MethodGet, path: "/support"}).Body.String()
	home := h.do(t, request{method: http.MethodGet, path: "/"}).Body.String()
	for what, body := range map[string]string{"privacy": privacy, "terms": terms, "support": support, "home": home} {
		if !strings.Contains(body, "Ada &amp; Co &lt;Labs&gt;") || strings.Contains(body, "<Labs>") {
			t.Errorf("%s: operator name missing or unescaped", what)
		}
		if !strings.Contains(body, `href="mailto:privacy@example.com"`) {
			t.Errorf("%s: no mailto link to the contact address", what)
		}
		if strings.Contains(body, "[operator name]") || strings.Contains(body, "[contact email]") {
			t.Errorf("%s: placeholder shown although configured", what)
		}
	}
	for _, want := range []string{
		"18 October 2026",
		// Google API Services User Data Policy, Limited Use disclosure.
		"Google API Services User Data Policy",
		"Limited Use requirements",
		"https://developers.google.com/terms/api-services-user-data-policy",
		"do not sell",
		"OpenBao",
		"My account",
	} {
		if !strings.Contains(privacy, want) {
			t.Errorf("privacy policy lacks %q", want)
		}
	}
	for _, want := range []string{"18 October 2026", "England and Wales", `href="/privacy"`} {
		if !strings.Contains(terms, want) {
			t.Errorf("terms lack %q", want)
		}
	}
}

func TestLegalPagesShowPlaceholdersWhenUnset(t *testing.T) {
	h := newHarness(t)
	privacy := h.do(t, request{method: http.MethodGet, path: "/privacy"}).Body.String()
	for _, want := range []string{"[operator name]", "[contact email]", "[effective date]"} {
		if !strings.Contains(privacy, want) {
			t.Errorf("privacy lacks placeholder %q", want)
		}
	}
	if strings.Contains(privacy, "mailto:") {
		t.Error("mailto link rendered without an address")
	}
}

// GATEWAY_LEGAL_DRAFT controls a visible marker on the legal texts.
func TestDraftMarkerFollowsConfig(t *testing.T) {
	const marker = "Draft – pending review"
	on := configured
	on.Draft = true
	for _, tc := range []struct {
		legal portal.Legal
		want  bool
	}{{on, true}, {configured, false}} {
		h := legalHarness(t, tc.legal)
		for _, path := range []string{"/privacy", "/terms"} {
			body := h.do(t, request{method: http.MethodGet, path: path}).Body.String()
			if got := strings.Contains(body, marker) && strings.Contains(body, `data-legal-draft`); got != tc.want {
				t.Errorf("Draft=%v GET %s: marker shown = %v", tc.legal.Draft, path, got)
			}
		}
	}
}

// The sign-in page and every portal page link the legal texts.
func TestSignInAndPortalFooterLinkLegalPages(t *testing.T) {
	h := newHarness(t)
	ck, _ := h.session(t, memberSub, "Member")
	signin := h.do(t, request{method: http.MethodGet, path: "/signin"}).Body.String()
	account := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck}).Body.String()
	for what, body := range map[string]string{"signin": signin, "account": account} {
		for _, want := range []string{`href="/privacy"`, `href="/terms"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %s", what, want)
			}
		}
	}
	if !strings.Contains(signin, "Terms of Service") || !strings.Contains(signin, "Privacy Policy") {
		t.Error("sign-in page does not name the terms and privacy policy")
	}
}
