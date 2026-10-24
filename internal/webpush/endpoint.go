package webpush

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// MaxEndpointLength bounds an endpoint URL.
const MaxEndpointLength = 1024

// ErrEndpointNotAllowed is returned (wrapped, with a reason) for an
// endpoint that is not an https URL on a known push service.
var ErrEndpointNotAllowed = errors.New("webpush: endpoint not allowed")

// Push-service hosts, matched exactly, and domains whose proper
// subdomains are accepted. Unexported so no caller can widen them.
var (
	allowedHosts = []string{
		"fcm.googleapis.com",                // Chrome, Edge, Android
		"updates.push.services.mozilla.com", // Firefox
		"web.push.apple.com",                // Safari
	}
	allowedSuffixes = []string{
		"push.apple.com",     // Apple push hosts
		"notify.windows.com", // Windows Push Notification Services
	}
)

// DefaultAllowedHosts returns a copy of the push-service hosts
// ValidateEndpoint accepts exactly.
func DefaultAllowedHosts() []string { return append([]string(nil), allowedHosts...) }

// DefaultAllowedSuffixes returns a copy of the domains whose subdomains
// ValidateEndpoint accepts (the bare domain itself is not accepted).
func DefaultAllowedSuffixes() []string { return append([]string(nil), allowedSuffixes...) }

// ValidateEndpoint reports whether raw is an acceptable push endpoint: an
// https URL of at most MaxEndpointLength bytes, printable ASCII only, with
// no userinfo or fragment, port empty or 443, a non-root path, and a host
// (case-insensitive, no trailing dot) that is in DefaultAllowedHosts or a
// subdomain of DefaultAllowedSuffixes. IP literals never match. Failures
// wrap ErrEndpointNotAllowed; the message never contains the URL's path or
// query.
func ValidateEndpoint(raw string) error {
	if raw == "" {
		return notAllowed("empty")
	}
	if len(raw) > MaxEndpointLength {
		return notAllowed("longer than %d bytes", MaxEndpointLength)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return notAllowed("non-printable or non-ASCII character")
		}
	}
	const prefix = "https://"
	if len(raw) < len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return notAllowed("scheme is not https")
	}
	rest := raw[len(prefix):]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	host, port, hasPort := strings.Cut(authority, ":")
	if hasPort && port != "443" {
		return notAllowed("port is not 443")
	}
	host = strings.ToLower(host)
	if err := checkHostName(host); err != nil {
		return err
	}
	if !hostAllowed(host) {
		return notAllowed("host %q is not a known push service", host)
	}
	if !strings.HasPrefix(tail, "/") || strings.HasPrefix(tail, "/?") || tail == "/" {
		return notAllowed("host %q: path required", host)
	}
	// The hand parse above decides; url.Parse must agree with it so the
	// request goes where it was checked to go.
	u, err := url.Parse(raw)
	if err != nil {
		return notAllowed("host %q: malformed URL", host)
	}
	switch {
	case u.Scheme != "https", u.Opaque != "":
		return notAllowed("host %q: malformed URL", host)
	case u.User != nil:
		return notAllowed("host %q: userinfo present", host)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return notAllowed("host %q: fragment present", host)
	case strings.ToLower(u.Hostname()) != host:
		return notAllowed("host %q: ambiguous host", host)
	}
	return nil
}

// checkHostName accepts only LDH DNS names: dot-separated labels of
// [a-z0-9-], 1-63 bytes, not starting or ending with '-'. This refuses
// IPv6 literals, percent-encoding, userinfo, trailing dots and Unicode.
func checkHostName(host string) error {
	if host == "" {
		return notAllowed("empty host")
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return notAllowed("invalid host name")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return notAllowed("invalid host name")
			}
		}
	}
	return nil
}

func hostAllowed(host string) bool {
	for _, h := range allowedHosts {
		if host == h {
			return true
		}
	}
	for _, s := range allowedSuffixes {
		if len(host) > len(s)+1 && strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func notAllowed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrEndpointNotAllowed, fmt.Sprintf(format, args...))
}

// endpointHost returns the lower-cased host of an endpoint for error
// messages, or "push service" when it cannot be parsed. It never returns
// the path or query.
func endpointHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "push service"
	}
	return strings.ToLower(u.Hostname())
}
