// Package jobs owns the background workers that run on one replica under a
// PostgreSQL lock: ledger reconciler, approval expiry, audit purge, token
// keep-alive refresh and the stale in_progress sweep.
//
// Design: Brain plan 36bakiw8 section 7; decision nq8wo4g3.
package jobs
