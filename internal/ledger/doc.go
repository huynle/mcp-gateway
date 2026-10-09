// Package ledger owns the write ledger (decision dovthftx): Service.Begin
// inserts the in_progress row before every write, in the same transaction
// that consumes the approval when there is one (ApprovalConsumer, which
// the approvals service implements), and decides idempotency by key:
// ApprovalKey for a consumed approval (at most once), DigestKey (user,
// account, tool, canonical argument digest) inside Config.IdempotencyWindow
// otherwise, answering PriorReplay (succeeded: return the stored result
// IDs), PriorPending (in_progress or unknown) or a new operation (failed,
// unresolved or none). Service.Finish records succeeded (result IDs only,
// SanitizeResultIDs), failed or unknown plus the attempt row.
//
// Service.Reconcile is the bounded reconciler (backoff 2^(n-1) minutes,
// Config.MaxReconcileAttempts, Config.MaxReconcileAge; non-reconcilable
// tools go straight to unresolved, the Notifier is told, an audit event
// records it, and the block lifts); Service.SweepStale turns stale
// in_progress rows into unknown; Service.Shutdown marks this replica's
// in-flight operations unknown after the drain. The jobs package wraps
// the first two as ReconcilerJob and StaleSweepJob; internal/mcp hosts
// the pipeline stage (LedgerStage); Portal serves GET /operations.
//
// Design: Brain plan 36bakiw8 section 3; decisions dovthftx, s0p05diu.
package ledger
