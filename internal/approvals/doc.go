// Package approvals owns durable confirmations for tool calls: canonical
// argument digests, encrypted stored argument payloads, approval_id retry,
// bounded wait (default 30 s), expiry (default 15 min), single-use consumption
// in the same transaction as the ledger insert, and the notifier interface
// (portal always, Slack DM when connected).
//
// Design: Brain plan 36bakiw8 section 3; decision s0p05diu.
package approvals
