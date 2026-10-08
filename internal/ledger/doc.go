// Package ledger owns write intent and outcomes: an in_progress row inserted
// before every app call, idempotency keys (approval-scoped or
// user+account+tool+digest within a window), outcomes succeeded / failed /
// unknown / unresolved, and the bounded reconciler with stale in_progress
// sweep.
//
// Design: Brain plan 36bakiw8 section 3; decision dovthftx.
package ledger
