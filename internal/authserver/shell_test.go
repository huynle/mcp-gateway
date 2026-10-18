package authserver_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

// /harnesses, the OAuth consent page and the authorize error page are
// built on the shared shell.
func TestAuthserverPagesUseTheSharedShell(t *testing.T) {
	f := newFlow(t)
	navtest.AssertShell(t, "/harnesses", f.harnesses().Body.String())
	navtest.AssertShell(t, "consent", f.authorize(f.authorizeParams()).Body.String())
	q := f.authorizeParams()
	q.Set("redirect_uri", "https://evil.test/cb")
	navtest.AssertShell(t, "authorize error", f.authorize(q).Body.String())
}

// The consent page and the other authserver pages carry the shared footer
// with the legal links, and consent names the terms and privacy policy
// next to the Allow button (public gateway: Google / Slack / GitHub app
// listings expect the policy one click away from every consent).
func TestAuthserverPagesLinkTheLegalPages(t *testing.T) {
	f := newFlow(t)
	consent := f.authorize(f.authorizeParams()).Body.String()
	for what, body := range map[string]string{"consent": consent, "/harnesses": f.harnesses().Body.String()} {
		for _, want := range []string{`<footer class="site-footer"`, `href="/privacy"`, `href="/terms"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %s", what, want)
			}
		}
	}
	if !strings.Contains(consent, "Terms of Service</a> and the <a href=\"/privacy\">Privacy Policy") {
		t.Error("consent does not reference the terms and privacy policy near the decision")
	}
}
