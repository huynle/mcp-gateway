package tunnel

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Tunnel URLs.
//
// A server behind a tunnel is registered with the URL
// tunnel://<tunnel id>/<path> (decision 17iv8p3b). internal/federation/client
// accepts only http(s) URLs, so ClientURL maps it to the equivalent
// http://<tunnel id>.tunnel.invalid/<path>. ".invalid" is reserved (RFC
// 2606/6761) and never resolves, so even a misrouted request could not
// reach the network; the tunnel transport accepts both forms.
const (
	// Scheme is the tunnel URL scheme.
	Scheme = "tunnel"
	// HostSuffix marks the http form of a tunnel URL.
	HostSuffix = ".tunnel.invalid"
)

// ErrNotTunnelURL reports a URL that is not a well-formed tunnel URL.
var ErrNotTunnelURL = errors.New("tunnel: not a tunnel URL")

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// URL returns the tunnel URL of a tunnel ID and a path ("" = "/").
func URL(tunnelID, path string) string {
	if path == "" {
		path = "/"
	}
	return Scheme + "://" + strings.ToLower(tunnelID) + path
}

// ParseURL returns the tunnel ID (lower-case uuid) and request URI (path
// plus query, at least "/") of a tunnel URL in either form.
func ParseURL(raw string) (tunnelID, requestURI string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", ErrNotTunnelURL
	}
	return parseTunnelURL(u)
}

// ClientURL converts a tunnel URL (either form) to the http form that
// internal/federation/client accepts.
func ClientURL(raw string) (string, error) {
	id, uri, err := ParseURL(raw)
	if err != nil {
		return "", err
	}
	return "http://" + id + HostSuffix + uri, nil
}

// IsTunnelURL reports whether raw is a tunnel URL (either form).
func IsTunnelURL(raw string) bool {
	_, _, err := ParseURL(raw)
	return err == nil
}

func parseTunnelURL(u *url.URL) (string, string, error) {
	if u.User != nil || u.Port() != "" || u.Opaque != "" || u.Fragment != "" {
		return "", "", ErrNotTunnelURL
	}
	host := strings.ToLower(u.Hostname())
	switch strings.ToLower(u.Scheme) {
	case Scheme:
	case "http", "https":
		var ok bool
		if host, ok = strings.CutSuffix(host, HostSuffix); !ok {
			return "", "", ErrNotTunnelURL
		}
	default:
		return "", "", ErrNotTunnelURL
	}
	if !uuidRE.MatchString(host) {
		return "", "", ErrNotTunnelURL
	}
	return host, u.RequestURI(), nil
}
