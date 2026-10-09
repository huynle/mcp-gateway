// Package slack is the Slack connector (app "slack"), built on the
// pattern of the GitHub reference connector (decision bt8ukyrd): a
// connections.Binder for Slack OAuth v2 user tokens (binder.go), read
// tools over the Web API through slack-go (tools_read.go) and write
// tools with their reconciliation (tools_write.go, reconcile.go). Tokens
// come from the connection's oauth2.TokenSource, obtained per call
// through the function injected at construction, so the connector never
// stores one.
//
// The vendor app is the same Slack app the approval notifier DMs with
// (internal/approvals/notify_slack.go): user-token scopes drive the
// tools, the bot token drives approvals. The binder produces the
// external account id connections.SlackAccountID(team, user) =
// "<team id>:<user id>" that Service.SlackIdentity reads back.
//
// Read results mark Empty (no items), Partial (clamped page size or a
// result truncated to the bounds) and Unavailable (5xx, Slack's
// fatal_error / internal_error, network); Slack rate limits (HTTP 429
// with Retry-After, or ok:false "ratelimited") are
// *connectors.RateLimited; other failures are *Error with a Class
// (reconnect_required, not_found, forbidden, invalid_argument,
// vendor_error).
//
// Writes require the ledger's Call.OperationID (ErrMissingOperation
// otherwise). post_message and reply_in_thread declare reconciliation
// none by default (an unknown outcome goes straight to unresolved: a
// chat message carries no stable id and invisible markers are fragile);
// with Options.MarkerReconcile (vendor app extra marker_reconcile=true)
// they attach the operation id as message metadata and reconcile by
// scanning the channel or thread for it. add_reaction reconciles by
// stable id (reactions.get on the message). Outcomes that cannot be
// known (5xx, timeout, dropped connection after the request was sent)
// are connectors.ErrOutcomeUnknown (decisions dovthftx, enlsy40f).
//
// Channel and message handling is adapted from korotovsky/slack-mcp-server
// (MIT; see THIRD_PARTY_NOTICES.md).
//
// Design: Brain plan 36bakiw8 section 5; decisions bt8ukyrd, mh7c6z3v,
// dovthftx, wcp2fmbz, rrmfnkqu, q282qtlz, 0sod196t.
package slack

// App is the connector's name; every tool is "slack.<name>".
const App = "slack"
