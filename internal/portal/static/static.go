// Package static holds the portal's browser assets: the shared stylesheet
// (portal.css), the theme script (theme.js), htmx and the review page's
// script and styles, the IBM Plex web fonts portal.css loads from fonts/
// (SIL OFL 1.1, licence texts next to them), and the installable-app
// script and icons (pwa.js; icons/*.png, rendered by
// scripts/render-pwa-icons.py), and the insights charts: the vendored
// Chart.js (chart.umd.min.js, MIT, licence in chart.LICENSE) and its
// glue (charts.js). They are embedded so the portal ships
// inside the single gateway binary (decision 7datr7x4) and served by the
// portal under /static/. The service worker source (sw.js) is embedded
// too, as ServiceWorker, but served by the portal at /sw.js.
//
// Templates link assets through URL, which appends a hash of the file's
// bytes (?v=…): the handler sends a 1-day Cache-Control, and a deploy that
// changes a file changes its URL, so browsers fetch the new copy at once.
// The package imports nothing of the gateway, so package nav (and through
// it every module's templates) can use it.
package static

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
)

// Go's built-in MIME table has no web-font types, and the distroless image
// has no /etc/mime.types: register the one portal.css uses.
func init() {
	if err := mime.AddExtensionType(".woff2", "font/woff2"); err != nil {
		panic(err)
	}
}

// FS is the embedded asset tree served under /static/.
//
//go:embed htmx.min.js chart.umd.min.js charts.js review.js review.css portal.css theme.js copy.js pwa.js favicon.svg fonts/*.woff2 icons/*.png
var FS embed.FS

// ServiceWorker is the source of the portal's service worker. It is not in
// FS: the portal serves it at /sw.js (a worker's scope is its directory, so
// it must sit at the root for scope "/") after filling its placeholders
// with the versioned asset URLs (package portal, pwa.go).
//
//go:embed sw.js
var ServiceWorker string

// HashLen is the number of hex digits of the content hash in a URL.
const HashLen = 12

// versions maps each embedded file name to its content hash, computed
// once at start-up.
var versions = func() map[string]string {
	out := map[string]string{}
	err := fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(FS, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[path] = hex.EncodeToString(sum[:])[:HashLen]
		return nil
	})
	if err != nil {
		panic(err)
	}
	return out
}()

// URL returns the path of an embedded asset with its content-hash query,
// e.g. /static/portal.css?v=0123456789ab. Unknown names are an error, so
// a template that links a missing file fails to render instead of
// producing a dead link.
func URL(name string) (string, error) {
	v, ok := versions[name]
	if !ok {
		return "", fmt.Errorf("static: no asset %q", name)
	}
	return "/static/" + name + "?v=" + v, nil
}
