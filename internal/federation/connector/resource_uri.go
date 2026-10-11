package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/yosida95/uritemplate/v3"
)

// ResourceURIScheme is the scheme of the URIs the gateway gives upstream
// resources on its own /mcp.
//
// A gateway resource URI is "mcpgw://<server>/<upstream URI>": the server
// name is the authority and the upstream URI follows the first "/"
// verbatim (no escaping), so the mapping is a plain prefix that reverses
// exactly for any upstream URI, whatever its scheme, query, fragment or
// characters. Because the prefix holds no template expressions, the same
// prefix rewrites a resource template, and a client filling in the
// gateway template gets the gateway URI of what the upstream template
// gives for the same values.
const ResourceURIScheme = "mcpgw"

const resourceURIPrefix = ResourceURIScheme + "://"

// GatewayResourceURI is the gateway URI of upstream resource uri of
// server.
func GatewayResourceURI(server, upstream string) string {
	return resourceURIPrefix + server + "/" + upstream
}

// GatewayResourceTemplate rewrites an upstream URI template (RFC 6570) of
// server for the gateway.
func GatewayResourceTemplate(server, tmpl string) string {
	return GatewayResourceURI(server, tmpl)
}

// ParseGatewayResourceURI maps a gateway resource URI back to its server
// and upstream URI. ok is false for anything the gateway did not issue: a
// different (or upper-case) scheme, a missing or invalid server name, an
// empty upstream URI.
func ParseGatewayResourceURI(uri string) (server, upstream string, ok bool) {
	rest, found := strings.CutPrefix(uri, resourceURIPrefix)
	if !found {
		return "", "", false
	}
	server, upstream, found = strings.Cut(rest, "/")
	if !found || upstream == "" || !serverNameRE.MatchString(server) {
		return "", "", false
	}
	return server, upstream, true
}

// GatewayPromptName is the gateway name of upstream prompt of server:
// "<server>.<prompt>" (server names never contain ".").
func GatewayPromptName(server, prompt string) string { return server + "." + prompt }

// ParseGatewayPromptName splits a gateway prompt name at its first ".".
func ParseGatewayPromptName(name string) (server, prompt string, ok bool) {
	server, prompt, ok = strings.Cut(name, ".")
	if !ok || prompt == "" || !serverNameRE.MatchString(server) {
		return "", "", false
	}
	return server, prompt, true
}

// templateMatches reports whether uri is an expansion of the RFC 6570
// template tmpl (the go-sdk's own matching). An invalid template matches
// nothing.
func templateMatches(tmpl, uri string) bool {
	t, err := uritemplate.New(tmpl)
	if err != nil {
		return false
	}
	return t.Regexp().MatchString(uri)
}

// resourceIdentity is the audit identity of a read of upstream uri on
// server: the server, the URI without query or fragment (they may carry
// search terms or tokens) and the SHA-256 of the full URI, so reads of the
// same resource correlate. Never the content.
func resourceIdentity(server, uri string) map[string]string {
	sum := sha256.Sum256([]byte(uri))
	bare := uri
	if i := strings.IndexAny(bare, "?#"); i >= 0 {
		bare = bare[:i]
	}
	return map[string]string{"server": server, "uri": bare, "uri_sha256": hex.EncodeToString(sum[:])}
}
