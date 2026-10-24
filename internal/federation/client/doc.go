// Package client talks to remote MCP servers as an MCP client, always
// through an injected netguard HTTP client. See docs/federation-client.md.
//
// # Network
//
// Options.HTTPClient is required and must come from netguard
// (Guard.Client()): its Transport does the SSRF-safe dialling and its
// CheckRedirect re-validates every redirect hop. The client copies it per
// session, wraps its Transport (origin pinning, static headers,
// Authorizer, response bounds) and sets http.Client.Timeout to zero,
// because the legacy HTTP+SSE transport keeps one GET stream open for the
// whole session, which a whole-request timeout would kill. Instead, every
// operation (the handshake and each list/call/read/get) runs under its own
// context deadline of Options.Timeout (tools/call: Options.CallTimeout,
// which defaults to Timeout), and Session.Close cancels every request of
// the session.
//
// Requests are built by the MCP SDK from scratch, so nothing from an
// inbound gateway request (its Authorization header, cookies) can reach
// the upstream server: only Endpoint.Headers and what the Authorizer adds.
//
// # Transport selection
//
// Endpoint.Transport "auto" (the default) tries Streamable HTTP first. If
// the initialize POST is answered with an HTTP 4xx other than 401, 403,
// 407, 408 or 429, the server is taken for a legacy HTTP+SSE server and
// the client reconnects with the SSE transport (the MCP specification's
// backwards-compatibility procedure). Credential, rate and timeout
// failures, 5xx, network errors and netguard refusals never fall back.
//
// # Errors
//
// Upstream failures are *Error values with a Class; their messages never
// contain upstream bodies, URLs or credentials. A malformed Endpoint
// yields ErrInvalidEndpoint instead.
package client
