package portal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/portal/static"
)

// The installable app (PWA, decision 0pzhidap): a web app manifest, a
// service worker at the root and an offline page. All three are public:
// browsers fetch the manifest and the worker without credentials, and the
// worker caches the offline page.
const (
	manifestPath = "/manifest.webmanifest"
	workerPath   = "/sw.js"
	offlinePath  = "/offline"
)

// precacheAssets are the static files the worker installs (by their
// versioned URLs), plus every embedded font and icon (precacheGlobs).
var (
	precacheAssets = []string{"portal.css", "theme.js", "htmx.min.js", "copy.js", "pwa.js", "favicon.svg"}
	precacheGlobs  = []string{"fonts/*.woff2", "icons/*.png"}
)

// pwa holds the manifest and the worker, rendered once at start-up: both
// depend only on the embedded assets, so they are the same for every
// request of a build.
type pwa struct {
	manifest []byte
	worker   []byte
}

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

func buildPWA() (*pwa, error) {
	manifest, err := buildManifest()
	if err != nil {
		return nil, err
	}
	worker, err := buildWorker()
	if err != nil {
		return nil, err
	}
	return &pwa{manifest: manifest, worker: worker}, nil
}

func buildManifest() ([]byte, error) {
	m := webManifest{
		Name:            "MCP Gateway",
		ShortName:       "Gateway",
		ID:              "/",
		StartURL:        "/approvals",
		Scope:           "/",
		Display:         "standalone",
		BackgroundColor: "#f6f7f9", // portal.css --bg (light)
		ThemeColor:      "#0e7268", // the brand teal
		Description:     "Approve your agents' tool calls and manage their access to your apps.",
	}
	for _, ic := range []struct{ file, sizes, purpose string }{
		{"icons/icon-192.png", "192x192", "any"},
		{"icons/icon-512.png", "512x512", "any"},
		{"icons/icon-maskable-512.png", "512x512", "maskable"},
	} {
		src, err := static.URL(ic.file)
		if err != nil {
			return nil, err
		}
		m.Icons = append(m.Icons, manifestIcon{Src: src, Sizes: ic.sizes, Type: "image/png", Purpose: ic.purpose})
	}
	return json.Marshal(m)
}

// buildWorker fills the placeholders of static.ServiceWorker: the precache
// list (versioned asset URLs and the offline page), a cache version (a
// hash of that list, the worker source and the offline page's templates,
// so any change installs a fresh cache) and the notification icon.
func buildWorker() ([]byte, error) {
	names := append([]string(nil), precacheAssets...)
	for _, g := range precacheGlobs {
		m, err := fs.Glob(static.FS, g)
		if err != nil {
			return nil, err
		}
		names = append(names, m...)
	}
	urls := []string{offlinePath}
	for _, n := range names {
		u, err := static.URL(n)
		if err != nil {
			return nil, err
		}
		urls = append(urls, u)
	}
	list, err := json.Marshal(urls)
	if err != nil {
		return nil, err
	}
	sum := sha256.New()
	sum.Write([]byte(static.ServiceWorker))
	sum.Write(list)
	sum.Write([]byte(nav.Partial))
	for _, t := range []string{"templates/layout.html", "templates/offline.html"} {
		b, err := fs.ReadFile(templateFS, t)
		if err != nil {
			return nil, err
		}
		sum.Write(b)
	}
	version := hex.EncodeToString(sum.Sum(nil))[:static.HashLen]
	icon, err := static.URL("icons/icon-192.png")
	if err != nil {
		return nil, err
	}
	src := []byte(static.ServiceWorker)
	for _, r := range []struct {
		placeholder string
		value       any
	}{
		{`"__CACHE_VERSION__"`, version},
		{`["__PRECACHE_URLS__"]`, urls},
		{`"__ICON_URL__"`, icon},
	} {
		if n := bytes.Count(src, []byte(r.placeholder)); n != 1 {
			return nil, fmt.Errorf("portal: sw.js has %d %s placeholders, want 1", n, r.placeholder)
		}
		v, err := json.Marshal(r.value)
		if err != nil {
			return nil, err
		}
		src = bytes.Replace(src, []byte(r.placeholder), v, 1)
	}
	return src, nil
}

// manifestHandler serves the web app manifest.
func (p *Portal) manifestHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(p.pwa.manifest)
}

// workerHandler serves the service worker from the root, so its scope is
// the whole portal. no-cache: the browser revalidates it on every update
// check and picks up a deploy at once.
func (p *Portal) workerHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(p.pwa.worker)
}

// offline is the page the worker shows when a navigation fails. The worker
// caches it, so it is always the anonymous page (no user nav, no CSRF
// token), even for a signed-in request.
func (p *Portal) offline(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := p.tpl.render(w, http.StatusOK, "offline.html", "", page{Nav: nav.Data{Active: offlinePath}}); err != nil {
		p.log.Error("render failed", "event", "portal.render_failed", "template", "offline.html", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
