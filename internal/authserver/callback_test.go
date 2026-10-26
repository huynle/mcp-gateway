package authserver_test

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/authserver/authservertest"
)

// The post-Allow page for loopback redirect URIs: a harness on a remote
// host (SSH) listens on that host's loopback, not on the laptop running
// the browser, so the bare redirect fails there. The page still sends the
// browser on (meta refresh + a Continue link) and shows the callback as a
// curl command to run where the harness runs.

var (
	callbackCurlRE = regexp.MustCompile(`(?s)<pre id="callback-curl">(.*?)</pre>`)
	metaRefreshRE  = regexp.MustCompile(`<meta http-equiv="refresh" content="([^"]*)">`)
)

// interstitial asserts the post-Allow page and returns the callback URL
// it links to, the curl command it shows and its meta refresh (empty when
// there is none).
func interstitial(t *testing.T, rec *httptest.ResponseRecorder) (link *url.URL, curl, refresh string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 interstitial; Location %q; body: %.300s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("interstitial carries Location %q", loc)
	}
	h := rec.Header()
	for name, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Content-Type":           "text/html; charset=utf-8",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q, want frame-ancestors 'none'", h.Get("Content-Security-Policy"))
	}
	body := rec.Body.String()
	link, err := authservertest.CallbackURL(rec.Code, h, rec.Body.Bytes())
	if err != nil {
		t.Fatalf("%v in %s", err, body)
	}
	c := callbackCurlRE.FindStringSubmatch(body)
	if c == nil {
		t.Fatalf("no curl command in %s", body)
	}
	if r := metaRefreshRE.FindStringSubmatch(body); r != nil {
		refresh = html.UnescapeString(r[1])
	}
	for _, want := range []string{"another machine", "mcp-gateway proxy", "10 minutes", "once"} {
		if !strings.Contains(body, want) {
			t.Errorf("interstitial lacks %q", want)
		}
	}
	// Nothing from another origin: every script, stylesheet and image is
	// same-origin (a relative path); the Continue link is not an asset.
	for _, m := range regexp.MustCompile(`(?:src="|<link [^>]*href=")(https?:)?//`).FindAllString(body, -1) {
		t.Errorf("third-party asset reference %q", m)
	}
	return link, html.UnescapeString(c[1]), refresh
}

func TestConsentApproveLoopbackRendersInterstitial(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "[::1]", "localhost"} {
		t.Run(host, func(t *testing.T) {
			f := newFlow(t)
			uri := "http://" + host + ":45678/callback"
			_, out := f.register(t, map[string]any{"client_name": "Claude Code", "redirect_uris": []string{uri}})
			q := f.authorizeParams()
			q.Set("client_id", out["client_id"].(string))
			q.Set("redirect_uri", uri)
			link, curl, refresh := interstitial(t, f.consent(q, "approve", csrf))
			if link.Scheme != "http" || link.Host != host+":45678" || link.Path != "/callback" {
				t.Errorf("link = %s", link)
			}
			lq := link.Query()
			if lq.Get("code") == "" || lq.Get("state") != "xyz" || lq.Get("iss") != strings.TrimSuffix(f.cfg.Issuer, "/") {
				t.Errorf("link query = %v", lq)
			}
			if want := "curl -g '" + link.String() + "'"; curl != want {
				t.Errorf("curl = %q, want %q", curl, want)
			}
			if want := "1;url=" + link.String(); refresh != want {
				t.Errorf("meta refresh = %q, want %q", refresh, want)
			}
			// The code works once, exactly as with a redirect.
			f.clientID = out["client_id"].(string)
			status, tok := f.token(url.Values{
				"grant_type": {"authorization_code"}, "code": {lq.Get("code")}, "redirect_uri": {uri},
				"client_id": {f.clientID}, "code_verifier": {verifier}, "resource": {f.cfg.Resource()},
			})
			if status != http.StatusOK || tok["access_token"] == nil {
				t.Errorf("exchange: %d %v", status, tok)
			}
		})
	}
}

// A single quote in the callback URL (a registered path may carry one)
// is closed, escaped and reopened, so the command stays one argument.
func TestConsentInterstitialShellQuotes(t *testing.T) {
	f := newFlow(t)
	uri := "http://127.0.0.1:4000/it's/cb"
	code, out := f.register(t, map[string]any{"client_name": "Claude Code", "redirect_uris": []string{uri}})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, out)
	}
	q := f.authorizeParams()
	q.Set("client_id", out["client_id"].(string))
	q.Set("redirect_uri", uri)
	_, curl, _ := interstitial(t, f.consent(q, "approve", csrf))
	if !strings.HasPrefix(curl, `curl -g 'http://127.0.0.1:4000/it'\''s/cb?code=`) || !strings.HasSuffix(curl, "'") {
		t.Errorf("curl = %q", curl)
	}
}

// curl expands [] and {} in URLs (globbing): an IPv6 loopback host
// ([::1]) must reach curl verbatim, so the command turns globbing off.
func TestConsentInterstitialCurlDoesNotGlob(t *testing.T) {
	f := newFlow(t)
	uri := "http://[::1]:4000/cb"
	code, out := f.register(t, map[string]any{"client_name": "Claude Code", "redirect_uris": []string{uri}})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, out)
	}
	q := f.authorizeParams()
	q.Set("client_id", out["client_id"].(string))
	q.Set("redirect_uri", uri)
	_, curl, _ := interstitial(t, f.consent(q, "approve", csrf))
	if !strings.HasPrefix(curl, "curl -g 'http://[::1]:4000/cb?code=") {
		t.Errorf("curl = %q", curl)
	}
}

// Values from the client never reach the page unescaped.
func TestConsentInterstitialEscapes(t *testing.T) {
	f := newFlow(t)
	_, out := f.register(t, map[string]any{"client_name": `<img src=x onerror=alert(1)>`, "redirect_uris": []string{redirectURI}})
	q := f.authorizeParams()
	q.Set("client_id", out["client_id"].(string))
	q.Set("state", `"><script>alert(1)</script>`)
	rec := f.consent(q, "approve", csrf)
	link, _, _ := interstitial(t, rec)
	if b := rec.Body.String(); strings.Contains(b, "<img") || strings.Contains(b, "<script>alert") {
		t.Errorf("unescaped client value in %s", b)
	}
	if link.Query().Get("state") != `"><script>alert(1)</script>` {
		t.Errorf("state = %q", link.Query().Get("state"))
	}
}

// "The harness runs on another machine" on the consent page: the
// interstitial does not navigate away, so the command stays on screen.
func TestConsentInterstitialRemoteStays(t *testing.T) {
	f := newFlow(t)
	if b := f.authorize(f.authorizeParams()).Body.String(); !strings.Contains(b, `name="remote"`) {
		t.Errorf("consent page for a loopback redirect lacks the remote option")
	}
	q := f.authorizeParams()
	q.Set("remote", "1")
	// The option is the form's own checkbox, never a hidden copy of the
	// authorization request's query.
	if b := f.authorize(q).Body.String(); strings.Contains(b, `type="hidden" name="remote"`) {
		t.Errorf("remote echoed as a hidden field")
	}
	link, _, refresh := interstitial(t, f.consent(q, "approve", csrf))
	if refresh != "" {
		t.Errorf("remote interstitial refreshes to %q", refresh)
	}
	if link.Query().Get("code") == "" {
		t.Errorf("link = %s", link)
	}
}

// Non-loopback redirect URIs keep the plain 303, and so does every error.
func TestConsentNonLoopbackStillRedirects(t *testing.T) {
	f := newFlow(t)
	for _, uri := range []string{"https://app.example.com/cb"} {
		q := f.authorizeParams()
		q.Set("redirect_uri", uri)
		loc := redirect(t, f.consent(q, "approve", csrf))
		if loc.Host != "app.example.com" || loc.Query().Get("code") == "" {
			t.Errorf("approve redirect = %s", loc)
		}
	}
	// https on the loopback host is not the native-app loopback redirect.
	_, out := f.register(t, map[string]any{"client_name": "x", "redirect_uris": []string{"https://localhost:4443/cb"}})
	q := f.authorizeParams()
	q.Set("client_id", out["client_id"].(string))
	q.Set("redirect_uri", "https://localhost:4443/cb")
	if loc := redirect(t, f.consent(q, "approve", csrf)); loc.Query().Get("code") == "" {
		t.Errorf("https loopback redirect = %s", loc)
	}
	if loc := redirect(t, f.consent(f.authorizeParams(), "deny", csrf)); loc.Query().Get("error") != "access_denied" {
		t.Errorf("deny redirect = %s", loc)
	}
	q = f.authorizeParams()
	q.Set("remote", "1")
	if loc := redirect(t, f.consent(q, "deny", csrf)); loc.Query().Get("error") != "access_denied" || loc.Host != "localhost:45678" {
		t.Errorf("deny (remote) redirect = %s", loc)
	}
}
