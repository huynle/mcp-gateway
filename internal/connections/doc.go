// Package connections owns per-user app accounts: vendor OAuth connect flows
// (state + PKCE), binding to permanent vendor account IDs, company/personal
// labels, incremental scopes, envelope-encrypted tokens, serialized refresh per
// connection, needs-reconnect handling and the monthly keep-alive refresh.
//
// Design: Brain plan 36bakiw8 section 5; decision mh7c6z3v.
package connections
