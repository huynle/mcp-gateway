// Package approvals owns durable confirmations for tool calls (decision
// s0p05diu): the canonical argument digest (Canonical, Digest), the
// encrypted stored argument payload (crypto envelope with AAD
// {user, "approval", approval id, app}), approval_id retry, the bounded
// wait (Wait, GATEWAY_APPROVAL_WAIT, default 30 s), expiry
// (GATEWAY_APPROVAL_TTL, default 15 min; ExpiryJob drops the payloads),
// single-use consumption in the caller's transaction (Consume takes a Tx
// so the ledger can run it next to its insert, decision dovthftx), the
// Notifier interface (PortalNotifier always, MultiNotifier for fan-out,
// SlackNotifier: a Block Kit DM with Approve / Deny buttons to the user's
// connected company Slack account, whose presses internal/slack resolves),
// the pipeline's ConfirmHandler and the portal pages (/approvals,
// /approvals/history, approve, deny).
//
// Design: Brain plan 36bakiw8 section 3; decision s0p05diu.
package approvals
