package client

import (
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

// Endpoint is a remote MCP server.
type Endpoint struct {
	// URL is the server's MCP endpoint (Streamable HTTP) or SSE endpoint
	// (legacy). http or https only; netguard decides whether it is
	// reachable.
	URL string
	// Transport selects the transport; "" means TransportAuto.
	Transport Transport
	// Headers are static headers added to every request to the server
	// (e.g. a non-secret routing header). Credentials belong in the
	// Authorizer.
	Headers map[string]string
	// Label identifies the server in CallInfo (e.g. its ID). Optional.
	Label string
}

// reservedHeaders may not be static endpoint headers (compared in
// canonical form, so case-insensitively). Every Mcp-* header is reserved
// as well.
//   - set by the transport or the MCP SDK: Host, Content-Length,
//     Content-Type, Accept, Accept-Encoding, Last-Event-Id, Cache-Control;
//   - hop-by-hop / connection management (RFC 9110 7.6.1 and the legacy
//     ones): Connection, Keep-Alive, Proxy-Connection, Te, Trailer,
//     Transfer-Encoding, Upgrade, Proxy-Authenticate;
//   - credentials: Authorization, Proxy-Authorization, Cookie, Set-Cookie,
//     X-Api-Key. Credentials belong in the Authorizer, which seals them per
//     user and server URL; a static header would send the same plain-text
//     value on every user's calls. The servers portal refuses them too;
//     this is defence in depth for header_config written by any other
//     path (Brain task 68ss4tpc).
var reservedHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Content-Type": true, "Accept": true,
	"Connection": true, "Transfer-Encoding": true, "Te": true, "Trailer": true,
	"Upgrade": true, "Keep-Alive": true, "Proxy-Authorization": true, "Proxy-Authenticate": true,
	"Proxy-Connection": true, "Last-Event-Id": true, "Cache-Control": true, "Accept-Encoding": true,
	"Authorization": true, "Cookie": true, "Set-Cookie": true, "X-Api-Key": true,
}

// validated is a checked Endpoint.
type validated struct {
	u         *url.URL
	transport Transport
	headers   http.Header
	label     string
}

func validate(ep Endpoint) (*validated, error) {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidEndpoint, fmt.Sprintf(format, args...))
	}
	tr := ep.Transport
	switch tr {
	case "":
		tr = TransportAuto
	case TransportAuto, TransportStreamableHTTP, TransportSSE:
	default:
		return nil, bad("unknown transport %q", string(ep.Transport))
	}
	if ep.URL == "" {
		return nil, bad("empty URL")
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil, bad("unparsable URL") // the parse error would echo the URL
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, bad("scheme must be http or https")
	}
	if u.Host == "" {
		return nil, bad("URL has no host")
	}
	h := make(http.Header, len(ep.Headers))
	for name, value := range ep.Headers {
		if !validHeaderName(name) {
			return nil, bad("invalid header name")
		}
		canon := textproto.CanonicalMIMEHeaderKey(name)
		if reservedHeaders[canon] || strings.HasPrefix(canon, "Mcp-") {
			return nil, bad("header %q is reserved", canon)
		}
		if !validHeaderValue(value) {
			return nil, bad("invalid value for header %q", canon)
		}
		h.Set(canon, value)
	}
	return &validated{u: u, transport: tr, headers: h, label: ep.Label}, nil
}

// validHeaderName reports whether s is an RFC 9110 token.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validHeaderValue rejects control characters other than horizontal tab.
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}
