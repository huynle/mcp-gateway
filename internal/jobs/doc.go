// Package jobs owns the background workers that run on one replica under a
// PostgreSQL lease: the Runner drives registered Jobs (Name, Interval,
// Run) and the Locker (job_locks table, NewPostgresLocker) makes each job
// run on exactly one replica at a time. The approach is a row lease with
// a heartbeat (see Runner): a replica takes the job's lease for
// Options.Lease when it is free, expired or its own, renews it every
// Lease/3 while the job runs (a lost lease cancels the run), and keeps
// it for Interval + Lease afterwards, so a healthy replica keeps a job
// and a dead one hands it over within Interval + Lease. Advisory locks
// were not used because they are bound to a session and pooled
// connections make that fragile.
//
// Jobs registered here: approvals expiry (approvals.ExpiryJob); the
// ledger reconciler, audit purge, token keep-alive refresh and the stale
// in_progress sweep come with their modules.
//
// Design: Brain plan 36bakiw8 section 7; decision nq8wo4g3.
package jobs
