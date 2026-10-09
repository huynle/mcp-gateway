// Package authserver is the MCP OAuth 2.1 authorization server the gateway
// runs for its own /mcp resource (decisions 3ycafouv, ysorv868, uamxx6ba;
// plan 36bakiw8 section 4): Authorization Server Metadata (RFC 8414),
// Protected Resource Metadata (RFC 9728), rate-limited dynamic client
// registration (RFC 7591), the authorization endpoint with company sign-in
// and a consent page, PKCE S256, resource indicators (RFC 8707), the token
// endpoint (single-use codes, rotating refresh tokens with reuse
// detection), revocation (RFC 7009), a JWKS backed by envelope-encrypted
// signing keys with rotation, the JWTAuthenticator that /mcp verifies
// access tokens with (composed with the generated-token authenticator by
// Composite), the connected-harnesses page, the disable hook and the
// pruning and key-rotation jobs.
//
// Handlers are methods on Service with injectable clock, store (Store /
// Tx; authservertest.MemStore for tests) and session resolver (Identity),
// so each endpoint is testable on its own and the attack suite can drive
// them without a portal.
package authserver
