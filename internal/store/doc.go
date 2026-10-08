// Package store owns PostgreSQL access: the connection pool, goose migrations
// (run as a pre-upgrade job, never by the service itself), the schema-version
// check exposed through readiness, repositories that require a user ID, and
// row-level security via SET LOCAL app.user_id per transaction with a separate
// bypass role for background jobs.
//
// Design: Brain plan 36bakiw8 section 6; decision v6piaxdb.
package store
