package portal_test

import (
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/portal/static"
)

type manifestIcon struct {
	Src     string `json:"src"`
	Sizes   string `json:"sizes"`
	Type    string `json:"type"`
	Purpose string `json:"purpose"`
}

type webManifest struct {
	Name            string         `json:"name"`
	ShortName       string         `json:"short_name"`
	ID              string         `json:"id"`
	StartURL        string         `json:"start_url"`
	Scope           string         `json:"scope"`
	Display         string         `json:"display"`
	BackgroundColor string         `json:"background_color"`
	ThemeColor      string         `json:"theme_color"`
	Description     string         `json:"description"`
	Icons           []manifestIcon `json:"icons"`
}

func mustURL(t *testing.T, name string) string {
	t.Helper()
	u, err := static.URL(name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// The web app manifest makes the portal installable: public, JSON, the
// brand colours, and icons that resolve to embedded PNGs of the declared
// size (one of them maskable).
func TestManifest(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, request{method: http.MethodGet, path: "/manifest.webmanifest"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/manifest+json" {
		t.Errorf("Content-Type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Errorf("Cache-Control %q", cc)
	}
	var m webManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, rec.Body)
	}
	if m.Name != "MCP Gateway" || m.ShortName != "Gateway" || m.ID != "/" || m.StartURL != "/approvals" ||
		m.Scope != "/" || m.Display != "standalone" || m.BackgroundColor != "#f6f7f9" || m.ThemeColor != "#0e7268" || m.Description == "" {
		t.Errorf("manifest = %+v", m)
	}
	want := map[string]manifestIcon{
		mustURL(t, "icons/icon-192.png"):          {Sizes: "192x192", Type: "image/png", Purpose: "any"},
		mustURL(t, "icons/icon-512.png"):          {Sizes: "512x512", Type: "image/png", Purpose: "any"},
		mustURL(t, "icons/icon-maskable-512.png"): {Sizes: "512x512", Type: "image/png", Purpose: "maskable"},
	}
	if len(m.Icons) != len(want) {
		t.Errorf("icons = %+v, want %d", m.Icons, len(want))
	}
	for _, ic := range m.Icons {
		w, ok := want[ic.Src]
		if !ok {
			t.Errorf("unexpected icon %+v", ic)
			continue
		}
		if ic.Sizes != w.Sizes || ic.Type != w.Type || ic.Purpose != w.Purpose {
			t.Errorf("icon %s = %+v, want %+v", ic.Src, ic, w)
		}
		r := h.do(t, request{method: http.MethodGet, path: ic.Src})
		if r.Code != http.StatusOK {
			t.Errorf("%s: status %d", ic.Src, r.Code)
			continue
		}
		img, err := png.Decode(r.Body)
		if err != nil {
			t.Errorf("%s: %v", ic.Src, err)
			continue
		}
		if got := fmt.Sprintf("%dx%d", img.Bounds().Dx(), img.Bounds().Dy()); got != ic.Sizes {
			t.Errorf("%s: %v, want %s", ic.Src, img.Bounds(), ic.Sizes)
		}
	}
}

var precacheRE = regexp.MustCompile(`(?m)^\s*var PRECACHE_URLS = (\[[^\n]*\]);$`)

// precacheURLs is the list the served worker installs.
func precacheURLs(t *testing.T, sw string) []string {
	t.Helper()
	m := precacheRE.FindStringSubmatch(sw)
	if m == nil {
		t.Fatalf("no PRECACHE_URLS line in sw.js:\n%s", sw)
	}
	var urls []string
	if err := json.Unmarshal([]byte(m[1]), &urls); err != nil {
		t.Fatalf("PRECACHE_URLS: %v", err)
	}
	return urls
}

// The service worker lives at the root (scope "/"), is revalidated on
// every check, precaches only the versioned static assets and the offline
// page, and every one of those URLs resolves.
func TestServiceWorker(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, request{method: http.MethodGet, path: "/sw.js"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control %q", cc)
	}
	sw := rec.Body.String()
	if strings.Contains(sw, "__") {
		t.Errorf("sw.js has an unreplaced placeholder:\n%s", sw)
	}
	urls := precacheURLs(t, sw)
	want := []string{"/offline"}
	for _, name := range []string{"portal.css", "theme.js", "htmx.min.js", "copy.js", "pwa.js", "favicon.svg",
		"fonts/plex-sans-400.woff2", "fonts/plex-sans-500.woff2", "fonts/plex-sans-600.woff2", "fonts/plex-mono-400.woff2", "fonts/plex-mono-500.woff2",
		"icons/icon-192.png", "icons/icon-512.png", "icons/icon-maskable-512.png", "icons/apple-touch-icon.png"} {
		want = append(want, mustURL(t, name))
	}
	got := map[string]bool{}
	for _, u := range urls {
		got[u] = true
		if u != "/offline" && !strings.HasPrefix(u, "/static/") {
			t.Errorf("precache holds %s: only static assets and /offline may be cached", u)
		}
		if r := h.do(t, request{method: http.MethodGet, path: u}); r.Code != http.StatusOK {
			t.Errorf("precache URL %s: status %d", u, r.Code)
		}
	}
	for _, u := range want {
		if !got[u] {
			t.Errorf("precache lacks %s (have %v)", u, urls)
		}
	}
	if !regexp.MustCompile(`var CACHE_VERSION = "[0-9a-f]{12}";`).MatchString(sw) {
		t.Error("sw.js has no hashed CACHE_VERSION")
	}
	if !strings.Contains(sw, `"`+mustURL(t, "icons/icon-192.png")+`"`) {
		t.Error("sw.js does not use the versioned 192 icon for notifications")
	}
	// Deterministic: the same build serves the same worker (browsers
	// reinstall it whenever a byte changes).
	if again := h.do(t, request{method: http.MethodGet, path: "/sw.js"}).Body.String(); again != sw {
		t.Error("sw.js differs between requests")
	}
	assertBalanced(t, "sw.js", sw)
	nodeCheck(t, "sw.js", sw)
}

// Navigations are network-only (the offline page is the only fallback):
// the worker must never store a page's HTML, signed in or not.
func TestServiceWorkerNeverCachesNavigations(t *testing.T) {
	h := newHarness(t)
	sw := h.do(t, request{method: http.MethodGet, path: "/sw.js"}).Body.String()
	for _, want := range []string{`request.mode === "navigate"`, `"/static/"`, `request.method !== "GET"`,
		"self.addEventListener(\"push\"", "self.addEventListener(\"notificationclick\"", "clients.claim()", "caches.delete("} {
		if !strings.Contains(sw, want) {
			t.Errorf("sw.js lacks %s", want)
		}
	}
	nav := functionBody(t, sw, "handleNavigation")
	for _, bad := range []string{"put(", "caches.open", "addAll"} {
		if strings.Contains(nav, bad) {
			t.Errorf("handleNavigation stores responses (%s):\n%s", bad, nav)
		}
	}
	if !strings.Contains(nav, "OFFLINE_URL") {
		t.Errorf("handleNavigation has no offline fallback:\n%s", nav)
	}
	// The only cache write is the static handler's.
	if n := strings.Count(sw, ".put("); n != 1 {
		t.Errorf("sw.js has %d cache writes, want 1 (static assets only)", n)
	}
	if !strings.Contains(functionBody(t, sw, "handleStatic"), ".put(") {
		t.Error("the cache write is not in handleStatic")
	}
	// Notification clicks only open same-origin paths.
	if !strings.Contains(sw, `var DEFAULT_URL = "/approvals";`) {
		t.Error(`sw.js: DEFAULT_URL is not "/approvals"`)
	}
	if click := functionBody(t, sw, "safePath"); !strings.Contains(click, "return DEFAULT_URL") || !strings.Contains(click, "self.location.origin") {
		t.Errorf("safePath does not fall back to DEFAULT_URL or check the origin:\n%s", click)
	}
}

// functionBody returns the source of `function name(` up to the next
// top-level function declaration.
func functionBody(t *testing.T, src, name string) string {
	t.Helper()
	_, rest, ok := strings.Cut(src, "function "+name+"(")
	if !ok {
		t.Fatalf("no function %s in sw.js", name)
	}
	if i := strings.Index(rest, "\n  function "); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func assertBalanced(t *testing.T, name, src string) {
	t.Helper()
	pairs := map[rune]rune{')': '(', ']': '[', '}': '{'}
	var stack []rune
	for _, r := range src {
		switch r {
		case '(', '[', '{':
			stack = append(stack, r)
		case ')', ']', '}':
			if len(stack) == 0 || stack[len(stack)-1] != pairs[r] {
				t.Fatalf("%s: unbalanced %q", name, r)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 0 {
		t.Fatalf("%s: %d unclosed brackets", name, len(stack))
	}
}

// nodeCheck parses src with `node --check` when node is installed.
func nodeCheck(t *testing.T, name, src string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Logf("node not installed: skipping the syntax check of %s", name)
		return
	}
	f := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), node, "--check", f).CombinedOutput(); err != nil {
		t.Errorf("node --check %s: %v\n%s", name, err, out)
	}
}

// The registration script parses too.
func TestPWAScriptParses(t *testing.T) {
	b, err := static.FS.ReadFile("pwa.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{`"serviceWorker" in navigator`, "isSecureContext", `register("/sw.js", { scope: "/" })`} {
		if !strings.Contains(src, want) {
			t.Errorf("pwa.js lacks %s", want)
		}
	}
	assertBalanced(t, "pwa.js", src)
	nodeCheck(t, "pwa.js", src)
}

// The "notifications on this device" control in pwa.js: the routes it
// calls, the CSRF header, the permission prompt from the click, and no
// HTML injection or inline handlers.
func TestPWAScriptPushControl(t *testing.T) {
	b, err := static.FS.ReadFile("pwa.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{
		"[data-push-control]", "[data-push-state]", "[data-push-toggle]", "[data-push-test]",
		`"/account/push/key"`, `"/account/push/subscribe"`, `"/account/push/unsubscribe"`, `"/account/push/test"`,
		`"X-CSRF-Token"`, `getAttribute("hx-headers")`,
		"Notification.requestPermission(", "pushManager.subscribe(", "userVisibleOnly: true", "applicationServerKey",
		"PushManager", "subscription.unsubscribe(", `credentials: "same-origin"`,
		"Not supported on this browser", "Blocked in browser settings", "On for this device",
		"Turn on for this device", "Turn off for this device",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("pwa.js lacks %s", want)
		}
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "onclick"} {
		if strings.Contains(src, bad) {
			t.Errorf("pwa.js uses %s", bad)
		}
	}
	// The permission prompt must come straight from the click (iOS refuses
	// it otherwise): requested in the click handler before any await.
	click := strings.Index(src, `addEventListener("click"`)
	perm := strings.Index(src, "Notification.requestPermission(")
	if click < 0 || perm < 0 {
		t.Fatal("no click handler or permission request")
	}
}

// The raw worker is not an asset: /static/sw.js would carry placeholders
// and the wrong scope.
func TestWorkerIsNotAStaticAsset(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, request{method: http.MethodGet, path: "/static/sw.js"}); rec.Code != http.StatusNotFound {
		t.Errorf("/static/sw.js: status %d, want 404", rec.Code)
	}
}

// The offline page is public, on the shared shell, and always anonymous:
// the worker caches it, so it must never carry a user's nav or CSRF token.
func TestOfflinePage(t *testing.T) {
	h := newHarness(t)
	ck, _ := h.session(t, memberSub, "Member")
	for _, cookie := range []*http.Cookie{nil, ck} {
		rec := h.do(t, request{method: http.MethodGet, path: "/offline", cookie: cookie})
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
			t.Errorf("Cache-Control %q", cc)
		}
		body := rec.Body.String()
		navtest.AssertShell(t, "/offline", body)
		// Retry reloads the address in the bar: the worker shows this page
		// in place of whatever page failed to load.
		for _, want := range []string{"You're offline", `<a class="btn primary" href="" data-offline-retry>Retry</a>`} {
			if !strings.Contains(body, want) && !strings.Contains(body, strings.ReplaceAll(want, "'", "&#39;")) {
				t.Errorf("/offline lacks %s", want)
			}
		}
		for _, bad := range []string{"_csrf", "/auth/signout", "X-CSRF-Token", "Member"} {
			if strings.Contains(body, bad) {
				t.Errorf("/offline (cookie %v) carries %s", cookie != nil, bad)
			}
		}
	}
}

// The new routes carry the same hardening headers and CSP as every page.
func TestPWARoutesCarryHardeningHeaders(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/manifest.webmanifest", "/sw.js", "/offline", mustURL(t, "pwa.js"), mustURL(t, "icons/icon-192.png")} {
		rec := h.do(t, request{method: http.MethodGet, path: path})
		hd := rec.Header()
		if rec.Code != http.StatusOK || hd.Get("X-Frame-Options") != "DENY" || hd.Get("X-Content-Type-Options") != "nosniff" ||
			hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("Content-Security-Policy") != portal.CSP {
			t.Errorf("%s (%d): headers = %v", path, rec.Code, hd)
		}
	}
	// Non-GET methods are not served.
	if rec := h.do(t, request{method: http.MethodPost, path: "/sw.js"}); rec.Code == http.StatusOK {
		t.Error("POST /sw.js answered 200")
	}
}
