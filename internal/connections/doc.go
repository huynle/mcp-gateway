// Package connections owns per-user app accounts: the admin-registered
// vendor apps (one per vendor, two for Google; the client secret and the
// vendor's extra secrets such as Slack's bot token and signing secret
// envelope encrypted as one bundle, read back through VendorSecrets), the
// Slack account id format and SlackIdentity lookup, the generic OAuth 2.0
// connect flow (server-side state +
// PKCE S256 in connect_flows, /connect/{vendor}/start and /callback), the
// per-vendor Binder that turns a token into a permanent account ID, a
// display name and a company|personal label, the personal-account policy
// check, envelope-encrypted token bundles, TokenSource with one refresh at
// a time per connection (SELECT ... FOR UPDATE) and rotating refresh
// tokens, needs_reconnect handling with the Notifier, disconnect and the
// identity disable hook, the connectors.AccountSource over the connections
// table, the daily keep-alive job and the portal pages. With the tool
// catalog (SetToolCatalog: the registry and the policy view) it computes
// what a connection lacks for the tools its user may see (MissingAccess:
// Grant more access on /connections, AccessHint for list_accounts) and
// filters the scopes a connect flow requests (access.go).
//
// Design: Brain plan 36bakiw8 section 5; decisions mh7c6z3v, dovthftx,
// wcp2fmbz.
package connections
