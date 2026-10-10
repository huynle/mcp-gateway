// Package atlassian is the Atlassian connector: two connector apps, "jira"
// and "confluence", over one vendor ("atlassian", OAuth 2.0 3LO), built
// after the GitHub reference connector (decision bt8ukyrd). A
// connections.Binder identifies the Atlassian account and the site it is
// bound to (binder.go: account id + cloud id, company or personal by the
// site's hostname), read tools (tools_read.go) and write tools with their
// reconciliation (tools_write.go, reconcile.go) run over a thin REST
// client (client.go) against https://api.atlassian.com/ex/{jira|confluence}/
// <cloud id>/...; result shapes are in minimal.go and the Atlassian
// Document Format helpers in adf.go. Tokens come from the connection's
// oauth2.TokenSource per call and the cloud id from the connection's
// bound site, both through functions injected at construction, so the
// connector stores neither.
//
// Read results mark Empty (no items), Partial (clamped page size or a
// result truncated to the bounds) and Unavailable (5xx, network);
// Atlassian's 429 is *connectors.RateLimited with Retry-After; other
// failures are *Error with a Class (reconnect_required, no_account,
// not_found, forbidden, invalid_argument, vendor_error).
//
// Writes require the ledger's Call.OperationID (ErrMissingOperation
// otherwise), embed it as a marker paragraph in what they create
// (jira.create_issue, jira.add_comment, confluence.create_page) or
// declare no reconciliation (jira.transition_issue), return only the
// created resource's identifiers, and report an outcome that cannot be
// known (5xx, timeout, dropped connection, an unreadable reply) as
// connectors.ErrOutcomeUnknown so the reconciler runs
// Reconciliation.Check from the stored resource identity and operation
// id alone (decisions dovthftx, enlsy40f).
//
// Tool names, argument shapes and the simplified result shapes follow
// the design of sooperset/mcp-atlassian (MIT) without copying its code
// (decision 0sod196t); the behaviours of the prototype's
// tests/test_atlassian.py (commit b6ad1b4) are carried as fixture cases
// (docs/connectors/atlassian.md lists the mapping).
//
// Design: Brain plan 36bakiw8 section 5; decisions bt8ukyrd, mh7c6z3v,
// dovthftx, wcp2fmbz, rrmfnkqu, 0sod196t.
package atlassian

// Vendor is the connections vendor both apps use (connections.VendorAtlassian).
const Vendor = "atlassian"

// The two connector apps; every tool is "jira.<name>" or "confluence.<name>".
const (
	JiraApp       = "jira"
	ConfluenceApp = "confluence"
)

// userAgent identifies the gateway to Atlassian.
const userAgent = "mcp-gateway"
