// Package connectors owns the connector contract and the in-process
// connectors (fake, github, slack, atlassian, google, microsoft).
//
// A Connector is App() + Tools() + Call(ctx, Call): tools declare name,
// description, input schema, read/write, required scopes, resource
// identity extraction, result bounds and, for writes, how they reconcile
// after an unknown outcome (none, stable_id, client_id, marker). Tools
// leave Handler nil and Call dispatches by name; RegisterConnector binds
// the handlers, validates the contract and adds "<app>.list_accounts",
// a read over an AccountSource that lists the caller's own accounts (ID,
// label, display name, never tokens). The gateway injects the account and
// approval_id arguments; connectors never see them. A vendor 429 is
// returned as *RateLimited (with Retry-After) and a write whose outcome
// cannot be known wraps ErrOutcomeUnknown. connectortest.ContractTest
// checks every connector; fake is the first and backs every pipeline test.
//
// Design: Brain plan 36bakiw8 section 5; decisions bt8ukyrd, mh7c6z3v,
// dovthftx, 0sod196t.
package connectors
