package authservertest

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
)

// callbackLinkRE finds the Continue link of the page the consent endpoint
// renders after Allow for a loopback redirect URI.
var callbackLinkRE = regexp.MustCompile(`<a [^>]*id="callback-link"[^>]*href="([^"]*)"`)

// CallbackURL is where an approved consent sends the browser: the
// Location of a 303 (a non-loopback redirect URI, or any error), or the
// Continue link of the 200 interstitial a loopback redirect URI gets. Any
// other answer is an error, so a test that expects a code cannot be
// satisfied by an error page.
func CallbackURL(status int, header http.Header, body []byte) (*url.URL, error) {
	switch status {
	case http.StatusSeeOther, http.StatusFound:
		return url.Parse(header.Get("Location"))
	case http.StatusOK:
		m := callbackLinkRE.FindSubmatch(body)
		if m == nil {
			return nil, errors.New("200 without a callback link")
		}
		return url.Parse(html.UnescapeString(string(m[1])))
	default:
		return nil, fmt.Errorf("status %d is neither a redirect nor the callback page", status)
	}
}
