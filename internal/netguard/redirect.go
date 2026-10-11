package netguard

import (
	"net/http"
	"strings"
)

// MaxRedirects is the most redirects Client follows for one request.
const MaxRedirects = 5

// Redirect reasons.
const (
	ReasonTooManyRedirects  Reason = "too_many_redirects"
	ReasonRedirectDowngrade Reason = "redirect_downgrade" // https → http, never allowed
)

// checkRedirect is Client's CheckRedirect. It caps the chain, forbids an
// https→http downgrade anywhere in it (even for allow-listed hosts or with
// AllowHTTP), and re-validates the next URL. The dial of the next hop is
// checked again by the transport.
func (g *Guard) checkRedirect(req *http.Request, via []*http.Request) error {
	host := req.URL.Hostname()
	if len(via) > MaxRedirects {
		return g.block(host, ReasonTooManyRedirects)
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		for _, prev := range via {
			if strings.EqualFold(prev.URL.Scheme, "https") {
				return g.block(host, ReasonRedirectDowngrade)
			}
		}
	}
	return g.CheckURL(req.Context(), req.URL)
}
