// Package identity owns users, sign-in identities (provider issuer + permanent
// subject ID, never email), portal sessions and company login via an OIDC
// relying party (Google, Entra, Okta; dex locally). Users are created on first
// company sign-in for admin-allowed domains/tenants. It also owns the 30-day
// sign-in freshness rule that offboarding relies on.
//
// Design: Brain plan 36bakiw8 sections 2 and 4; decisions uamxx6ba, ysorv868.
package identity
