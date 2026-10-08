// Package authserver owns the MCP OAuth 2.1 authorization server: AS metadata
// (RFC 8414), Protected Resource Metadata (RFC 9728) and the WWW-Authenticate
// challenge on 401, resource indicators (RFC 8707), authorize, token,
// rate-limited dynamic client registration and JWKS. Access tokens are 1-hour
// JWTs bound to this gateway; refresh tokens are 30-day and rotated on use.
//
// Design: Brain plan 36bakiw8 section 4; decisions 3ycafouv, ysorv868.
package authserver
