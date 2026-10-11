// Package store owns PostgreSQL access: the pgx connection pools, the
// schema-version check exposed through readiness and enforced at startup,
// repositories per entity, and the two isolation layers of decision v6piaxdb:
//
//   - the repository layer only works inside a transaction opened by
//     [Store.WithUser] (request path, role gateway_app, SET LOCAL app.user_id)
//     or [Store.WithJobs] (background workers, just-in-time user creation and
//     admin metadata reads, role gateway_jobs with BYPASSRLS);
//   - PostgreSQL row-level security, ENABLED and FORCED on every user-scoped
//     table with a policy on app_user_id(), so a connection without a user
//     scope sees and writes nothing.
//
// The goose migrations live in the migrations subpackage and are run by
// cmd/migrate as a pre-upgrade job, never by the service: it only compares
// the database's version with [ExpectedSchemaVersion].
//
// User-added MCP servers (migration 00014, repo_mcp_*.go) follow the same
// model: servers are visible to their owner and to holders of a role they
// are published to; credentials, per-user connections and tunnels stay
// owner-only; publishing is an admin action through WithJobs.
//
// Design: Brain plan 36bakiw8 section 6; decisions v6piaxdb, dovthftx,
// s0p05diu, ysorv868, 490o45d0, uamxx6ba, mh7c6z3v; plan 0omkv2e1 and
// decision yhd5kcaz for MCP servers.
package store
