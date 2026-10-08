// Package connections owns per-user app accounts: the admin-registered
// vendor apps (one per vendor, two for Google; client secrets envelope
// encrypted), the generic OAuth 2.0 connect flow (server-side state +
// PKCE S256 in connect_flows, /connect/{vendor}/start and /callback), the
// per-vendor Binder that turns a token into a permanent account ID, a
// display name and a company|personal label, the personal-account policy
// check, envelope-encrypted token bundles, TokenSource with one refresh at
// a time per connection (SELECT ... FOR UPDATE) and rotating refresh
// tokens, needs_reconnect handling with the Notifier, disconnect and the
// identity disable hook, the connectors.AccountSource over the connections
// table, the daily keep-alive job and the portal pages.
//
// Design: Brain plan 36bakiw8 section 5; decisions mh7c6z3v, dovthftx,
// wcp2fmbz.
package connections
