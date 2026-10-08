// Package identity owns users, sign-in identities (provider issuer + permanent
// subject ID, never email), portal sessions and company login via an OIDC
// relying party (Google, Entra, Okta; dex locally). Users are created on first
// company sign-in for admin-allowed domains/tenants, with the configured
// default role; bootstrap admins from config receive the admin role on every
// sign-in. Disabling a user revokes sessions and runs the hooks other modules
// register (tokens, OAuth sessions, connections). It also records the company
// sign-in time that the 30-day token freshness rule relies on.
//
// Sign-in state (state, nonce, PKCE verifier, return path) travels in an
// HMAC-signed cookie so any replica can complete the callback; sessions are
// server-side rows looked up by the hash of the cookie secret.
//
// Design: Brain plan 36bakiw8 sections 2 and 4; decisions uamxx6ba, ysorv868.
package identity
