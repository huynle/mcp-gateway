// Package tokens owns generated tokens (mgw_<id>_<secret>): creation, SHA-256
// hash storage, lookup by embedded ID, expiry (max 90 days), revocation,
// read-only and app/tool narrowing, and last-used tracking. It never logs or
// returns the secret after the one-time display.
//
// Design: Brain plan 36bakiw8 section 4; decision uamxx6ba.
package tokens
