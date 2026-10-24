package elicit

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// MaxURLBytes is the longest elicitation URL accepted.
const MaxURLBytes = 2048

// Errors of Check and ValidateOrigin. Their messages never echo the input,
// so they are safe to show to the owner (and to log).
var (
	ErrInvalid    = errors.New("elicitation URL is malformed or its host is not a public domain name")
	ErrNotHTTPS   = errors.New("elicitation URL is not an absolute https URL")
	ErrUserinfo   = errors.New("elicitation URL contains a user name or password")
	ErrTooLong    = errors.New("elicitation URL is too long")
	ErrIPHost     = errors.New("elicitation URL host is an IP address")
	ErrNotAllowed = errors.New("elicitation URL is outside the server's domain and its allowed origins")
)

// Rules decide which URLs an upstream server may send a user to (URL-mode
// elicitation, relayed through the /elicit interstitial).
type Rules struct {
	// ServerURL is the upstream server's URL. An https URL with a DNS
	// host gives the registrable domain (eTLD+1) its elicitation URLs may
	// use; any other (tunnel://..., http, an IP host, empty) gives none.
	ServerURL string
	// AllowedOrigins are owner-managed exact origins
	// (https://host[:port], see ValidateOrigin). Entries that do not
	// normalise are ignored.
	AllowedOrigins []string
}

// Checked is a URL that passed Check.
type Checked struct {
	// URL is the normalised URL: host lowercased and in ASCII (punycode),
	// everything else as given. Redirect to URL.String() (= Display).
	URL *url.URL
	// Display is the full URL to show the user before they continue.
	Display string
	// Host is the ASCII host, without port.
	Host string
	// RegistrableDomain is Host's eTLD+1 (private suffixes such as
	// github.io count as suffixes), empty when Host is itself a public
	// suffix. Highlight it on the interstitial.
	RegistrableDomain string
	// Punycode is true when any label of Host is an IDN A-label (xn--):
	// warn about lookalikes.
	Punycode bool
	// Origin is https://Host[:port], the default port omitted.
	Origin string
}

// Check validates raw against the rules: an absolute https URL of at most
// MaxURLBytes, with no control characters, whitespace, format characters
// or backslashes, no userinfo, a DNS host (not an IP literal in any form,
// not localhost, at least two labels), whose registrable domain equals
// the server's or whose origin is exactly one of AllowedOrigins.
func (r Rules) Check(raw string) (Checked, error) {
	if len(raw) > MaxURLBytes {
		return Checked{}, ErrTooLong
	}
	if !cleanText(raw) {
		return Checked{}, ErrInvalid
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Checked{}, ErrInvalid
	}
	host, port, err := checkAuthority(u)
	if err != nil {
		return Checked{}, err
	}
	reg, _ := publicsuffix.EffectiveTLDPlusOne(host)
	origin := makeOrigin(host, port)
	sameDomain := reg != "" && reg == r.serverDomain()
	if !sameDomain && !r.listed(origin) {
		return Checked{}, ErrNotAllowed
	}
	u.Host = host
	if port != "" {
		u.Host += ":" + port
	}
	return Checked{
		URL:               u,
		Display:           u.String(),
		Host:              host,
		RegistrableDomain: reg,
		Punycode:          punycode(host),
		Origin:            origin,
	}, nil
}

// ValidateOrigin normalises an owner-entered origin for
// Rules.AllowedOrigins: https only, no userinfo, path, query or fragment,
// a DNS host as for Check (lowercased, IDNs as punycode), the default port
// omitted. Surrounding spaces are trimmed.
func ValidateOrigin(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxURLBytes {
		return "", ErrTooLong
	}
	if !cleanText(s) {
		return "", ErrInvalid
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", ErrInvalid
	}
	host, port, err := checkAuthority(u)
	if err != nil {
		return "", err
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || strings.Contains(s, "#") {
		return "", ErrInvalid
	}
	return makeOrigin(host, port), nil
}

// checkAuthority checks scheme, userinfo, host and port of a parsed URL
// and returns the ASCII host and the port ("" when absent).
func checkAuthority(u *url.URL) (host, port string, err error) {
	if u.Scheme != "https" {
		return "", "", ErrNotHTTPS
	}
	if u.Opaque != "" {
		return "", "", ErrInvalid
	}
	if u.User != nil {
		return "", "", ErrUserinfo
	}
	if strings.HasPrefix(u.Host, "[") {
		return "", "", ErrIPHost
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", "", ErrInvalid
	}
	if port = u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", "", ErrInvalid
		}
	}
	host, err = dnsHost(u.Hostname())
	return host, port, err
}

// dnsHost returns the lowercase ASCII form of a URL host, refusing IP
// literals (canonical or legacy IPv4 forms: 2130706433, 0x7f.1, 127.1),
// localhost, single labels and anything IDNA rejects.
func dnsHost(h string) (string, error) {
	if h == "" {
		return "", ErrInvalid
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", ErrIPHost
	}
	a, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", ErrInvalid
	}
	a = strings.ToLower(a)
	if len(a) > 253 {
		return "", ErrInvalid
	}
	labels := strings.Split(a, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", ErrInvalid // also a trailing dot
		}
		if strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return "", ErrInvalid
		}
	}
	if _, err := netip.ParseAddr(a); err == nil || endsInNumber(labels[len(labels)-1]) {
		return "", ErrIPHost
	}
	if len(labels) < 2 || a == "localhost" || strings.HasSuffix(a, ".localhost") {
		return "", ErrInvalid
	}
	return a, nil
}

// serverDomain is the registrable domain of an https ServerURL with a
// DNS host, "" otherwise (tunnel://, http, IP hosts).
func (r Rules) serverDomain() string {
	u, err := url.Parse(strings.TrimSpace(r.ServerURL))
	if err != nil || u.Scheme != "https" {
		return ""
	}
	h, err := dnsHost(u.Hostname())
	if err != nil {
		return ""
	}
	reg, _ := publicsuffix.EffectiveTLDPlusOne(h)
	return reg
}

func (r Rules) listed(origin string) bool {
	for _, o := range r.AllowedOrigins {
		if n, err := ValidateOrigin(o); err == nil && n == origin {
			return true
		}
	}
	return false
}

func makeOrigin(host, port string) string {
	if port == "" || port == "443" {
		return "https://" + host
	}
	return "https://" + host + ":" + port
}

func punycode(host string) bool {
	for _, l := range strings.Split(host, ".") {
		if strings.HasPrefix(l, "xn--") {
			return true
		}
	}
	return false
}

// cleanText reports whether s is valid UTF-8 without control, whitespace
// or format characters (bidi overrides, zero-width joiners) and without
// backslashes (browsers read \ as / in https URLs; Go does not).
func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c == '\\' || unicode.IsControl(c) || unicode.IsSpace(c) || unicode.Is(unicode.Cf, c) {
			return false
		}
	}
	return true
}

// endsInNumber is the WHATWG URL "ends in a number" check on the last
// label: all digits or a valid IPv4 number (0x..., octal), which browsers
// parse as an IPv4 address (copied from netguard's host rules).
func endsInNumber(last string) bool {
	if last == "" {
		return false
	}
	if strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := parseIPv4Number(last)
	return ok
}

// parseIPv4Number parses one WHATWG IPv4 part: 0x/0X prefix is hex, a
// leading 0 is octal, anything else decimal.
func parseIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		base, s = 16, s[2:]
	case len(s) >= 2 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, base, 64)
	return n, err == nil
}
