package portal

import (
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Elicitation origins (migration 00032,
// docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md,
// plan 2): exact https://host[:port] origins, besides the server's own
// registrable domain, that the server's URL elicitations may send users
// to. Tunnel and machine servers have no domain of their own and need the
// list. The owner edits it on the edit form (one origin per line); on a
// published server it is locked like the address (locked.go).

// maxOrigins mirrors the column check of migration 00032.
const maxOrigins = 20

// OriginValidator checks one origin line and returns its normalised form
// (https://host[:port]). The wiring passes the relay's rule
// (elicit.ValidateOrigin); nil uses NormalizeOrigin.
type OriginValidator func(origin string) (string, error)

var errBadOrigin = errors.New("not an https://host[:port] origin")

// NormalizeOrigin is the strict default OriginValidator: https only, an
// ASCII DNS host name with at least one dot (no IP literal, no userinfo),
// an optional port 1–65535 (443 is dropped), no path, query or fragment;
// the result is lowercase.
func NormalizeOrigin(raw string) (string, error) {
	if len(raw) > 300 || hasCTL(raw) {
		return "", errBadOrigin
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", errBadOrigin
	}
	host := strings.ToLower(u.Hostname())
	if !validDNSName(host) || net.ParseIP(host) != nil {
		return "", errBadOrigin
	}
	out := "https://" + host
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", errBadOrigin
		}
		if n != 443 {
			out += ":" + strconv.Itoa(n)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", errBadOrigin
	}
	return out, nil
}

// validDNSName accepts lowercase ASCII labels of letters, digits and
// hyphens (not at either end), at least two labels, at most 253 bytes.
func validDNSName(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// parseOrigins reads the textarea: one origin per line, blank lines
// ignored, each checked and normalised by valid, duplicates dropped.
func parseOrigins(s string, valid OriginValidator) ([]string, error) {
	ls := lines(s)
	if len(ls) > maxOrigins {
		return nil, bad("Up to %d origins.", maxOrigins)
	}
	out := []string{}
	for _, l := range ls {
		o, err := valid(l)
		if err != nil || o == "" {
			return nil, bad("%q is not an allowed origin: use https://host or https://host:port, without a path.", l)
		}
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out, nil
}
