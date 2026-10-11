// Package auth detects how a user-added (federated) MCP server wants to be
// authenticated and holds the gateway's credentials for it: OAuth 2.1
// connections per user (authorization code + PKCE S256, RFC 8707 resource,
// RFC 9207 issuer check; client by CIMD, DCR or a static client), shared
// and per-user API keys, bearer tokens and custom headers. It supplies the
// federation client's Authorizers, refreshing OAuth tokens one at a time
// per connection under a database row lock.
//
// Every outbound request (MCP probe, metadata discovery, registration,
// token, refresh) goes through the injected netguard *http.Client; x/oauth2
// is used only for its PKCE helpers. Secrets are envelope-encrypted with
// associated data binding them to their row and never logged.
//
// Design: Brain plan 0omkv2e1, decisions yhd5kcaz, yd6qrbqc, uvi2nzcw,
// 17iv8p3b; task k3ff95ec. See docs/federation-auth.md.
package auth
