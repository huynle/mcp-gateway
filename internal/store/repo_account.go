package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Account lifecycle queries (self-service data export and account
// deletion; internal/account, docs/runbooks/user-offboarding.md).

// UserDeleted marks a deleted user's tombstone row (migration 00029).
const UserDeleted = "deleted"

// ExportSections are the sections of a user's data export, in output
// order. Each is a fixed, column-projected query: secrets, hashes,
// encrypted payloads, digests and server credential configuration are
// never selected.
var ExportSections = []string{
	"profile", "identities", "roles", "connections", "tokens", "harness_grants",
	"mcp_servers", "mcp_server_connections", "tunnels", "approvals",
	"ledger_operations", "audit_events", "rate_limits", "resource_caps",
	"machines", "machine_enrollment_codes", "push_subscriptions",
}

// exportQueries: $1 is the user id, $2 the row limit. Every query filters
// on the user explicitly; run them under WithUser so row-level security
// backs the filter.
var exportQueries = map[string]string{
	"profile": `SELECT id, display_name, status, last_company_sign_in_at, disabled_at, gateway_tools_enabled, created_at, updated_at
		FROM users WHERE id = $1 LIMIT $2`,
	"identities": `SELECT id, issuer, subject, last_sign_in_at, created_at
		FROM identities WHERE user_id = $1 ORDER BY created_at LIMIT $2`,
	"roles": `SELECT r.name, r.description, a.created_at AS assigned_at
		FROM role_assignments a JOIN roles r ON r.id = a.role_id WHERE a.user_id = $1 ORDER BY r.name LIMIT $2`,
	"connections": `SELECT id, vendor_app_id, external_account_id, label, display_name, scopes, status,
			last_refreshed_at, token_expires_at, created_at, updated_at
		FROM admin_connections WHERE user_id = $1 ORDER BY created_at LIMIT $2`,
	"tokens": `SELECT id, public_id, name, read_only, scope, expires_at, revoked_at, last_used_at, created_at
		FROM tokens WHERE user_id = $1 ORDER BY created_at LIMIT $2`,
	"harness_grants": `SELECT coalesce(t.family_id, t.id) AS grant_id, c.client_name, t.resource,
			min(t.issued_at) AS granted_at, max(t.expires_at) AS expires_at, max(t.last_used_at) AS last_used_at,
			bool_and(t.revoked_at IS NOT NULL OR t.rotated_at IS NOT NULL) AS ended
		FROM oauth_refresh_tokens t JOIN oauth_clients c ON c.id = t.client_id
		WHERE t.user_id = $1
		GROUP BY coalesce(t.family_id, t.id), c.client_name, t.resource
		ORDER BY min(t.issued_at) LIMIT $2`,
	// The URL loses userinfo and query string: a pasted URL may carry a key.
	"mcp_servers": `SELECT id, name,
			regexp_replace(split_part(split_part(url, '#', 1), '?', 1), '^([a-z][a-z0-9+.-]*://)[^/@]*@', '\1') AS url,
			transport, audience, credential_mode, auth_kind, status, created_at, updated_at
		FROM mcp_servers WHERE owner_user_id = $1 ORDER BY created_at LIMIT $2`,
	"mcp_server_connections": `SELECT id, server_id, status, scopes, expires_at, last_refreshed_at, created_at, updated_at
		FROM mcp_server_user_connections WHERE user_id = $1 ORDER BY created_at LIMIT $2`,
	"tunnels": `SELECT id, name, created_at, last_seen_at, revoked_at
		FROM mcp_tunnels WHERE owner_user_id = $1 ORDER BY created_at LIMIT $2`,
	"approvals": `SELECT id, connection_id, tool, status, resource, token_id, policy_version_id,
			created_at, expires_at, decided_at, consumed_at
		FROM approvals WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
	"ledger_operations": `SELECT id, connection_id, tool, state, resource, token_id, approval_id, policy_version_id,
			result_ids, error_code, window_start, window_end, created_at, updated_at, finished_at
		FROM ledger_operations WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
	"audit_events": `SELECT id, event_type, actor_user_id, token_id, tool, connection_id, account_label, resource,
			decision, policy_version_id, approval_id, operation_id, outcome, latency_ms, details, created_at
		FROM admin_audit_events WHERE user_id = $1 ORDER BY created_at DESC, id LIMIT $2`,
	"rate_limits": `SELECT admin_per_min, self_per_min, updated_at
		FROM gateway_user_rate_limits WHERE user_id = $1 LIMIT $2`,
	"resource_caps": `SELECT servers, tunnels, connections_per_app, connections_total, pending_approvals, machines, updated_at
		FROM gateway_user_resource_caps WHERE user_id = $1 LIMIT $2`,
	"machines": `SELECT id, name, fingerprint, client_version, enrolled_via, enrolled_ip, created_at, last_seen_at, last_ip,
			revoked_at, revoke_reason
		FROM machines WHERE owner_user_id = $1 ORDER BY created_at LIMIT $2`,
	"machine_enrollment_codes": `SELECT id, label, created_at, expires_at, used_at, machine_id, revoked_at
		FROM machine_enrollment_codes WHERE owner_user_id = $1 ORDER BY created_at LIMIT $2`,
	// Display metadata only: the endpoint and its keys are sealed and are
	// never exported (the endpoint is a capability to push to the device).
	"push_subscriptions": `SELECT device_label, endpoint_host, created_at, last_success_at
		FROM push_subscriptions WHERE user_id = $1 ORDER BY created_at LIMIT $2`,
}

// ExportSection returns up to limit rows of one export section for userID
// as JSON objects, and whether more rows exist (the export notes the cap).
func ExportSection(ctx context.Context, q Querier, section, userID string, limit int) ([]json.RawMessage, bool, error) {
	sql, ok := exportQueries[section]
	if !ok {
		return nil, false, fmt.Errorf("store: export: unknown section %q", section)
	}
	if limit <= 0 {
		return nil, false, fmt.Errorf("store: export: limit must be positive, got %d", limit)
	}
	rows, err := q.Query(ctx, `SELECT row_to_json(t)::text FROM (`+sql+`) t`, userID, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("store: export %s: %w", section, err)
	}
	defer rows.Close()
	out := []json.RawMessage{}
	truncated := false
	for rows.Next() {
		if len(out) == limit {
			truncated = true
			break
		}
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, false, fmt.Errorf("store: export %s: %w", section, err)
		}
		out = append(out, json.RawMessage(s))
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store: export %s: %w", section, err)
	}
	return out, truncated, nil
}

// LastUserAuditAction is when userID last recorded a user event with
// resource action (nil: never). The export's rate limit reads it.
func LastUserAuditAction(ctx context.Context, q Querier, userID, action string) (*time.Time, error) {
	var at *time.Time
	err := q.QueryRow(ctx, `
		SELECT max(created_at) FROM audit_events
		WHERE user_id = $1 AND event_type = 'user' AND resource->>'action' = $2`, userID, action).Scan(&at)
	if err != nil {
		return nil, fmt.Errorf("store: last audit action: %w", err)
	}
	return at, nil
}

// LockAccountDeletion serialises account deletions for the rest of the
// transaction, so the last-admin check cannot race another deletion.
func LockAccountDeletion(ctx context.Context, q Querier) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('mcp-gateway:account-deletion'))`); err != nil {
		return fmt.Errorf("store: lock account deletion: %w", err)
	}
	return nil
}

// PublishedMCPServersOwnedBy names the published servers userID owns
// (deleting the owner would take them away from everyone they are
// published to). WithJobs.
func PublishedMCPServersOwnedBy(ctx context.Context, q Querier, userID string) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT name FROM mcp_servers WHERE owner_user_id = $1 AND audience = 'published' ORDER BY name`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: published servers of owner: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CountActiveUsersWithRole counts active users holding the role called
// roleName. WithJobs (cross-user).
func CountActiveUsersWithRole(ctx context.Context, q Querier, roleName string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `
		SELECT count(DISTINCT u.id) FROM users u
		JOIN role_assignments a ON a.user_id = u.id JOIN roles r ON r.id = a.role_id
		WHERE r.name = $1 AND u.status = 'active'`, roleName).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count users with role: %w", err)
	}
	return n, nil
}

// ListIdentitiesForUser returns userID's sign-in identities.
func ListIdentitiesForUser(ctx context.Context, q Querier, userID string) ([]Identity, error) {
	rows, err := q.Query(ctx, `
		SELECT id, user_id, issuer, subject, last_sign_in_at, created_at
		FROM identities WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list identities: %w", err)
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		var i Identity
		if err := rows.Scan(&i.ID, &i.UserID, &i.Issuer, &i.Subject, &i.LastSignInAt, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// UserDeletion is what DeleteUserData removed.
type UserDeletion struct {
	// ServerIDs are the deleted private MCP servers (the federation
	// reloads after the commit).
	ServerIDs []string
	Tunnels   int64
	// Machines are the deleted enrolled machines (their live connections
	// close at the next sync: the owner is no longer active).
	Machines    int64
	Connections int64
	Approvals   int64
}

// DeleteUserData removes or empties everything personal of userID and
// turns the user row into a tombstone (status deleted, deleted_at, no
// display name, no sign-in time, gateway tools off). Run it through
// WithJobs after the identity disable hooks (which revoke at the vendors
// and log per connection), in the same transaction:
//
//   - deleted: identities, sessions, private MCP servers the user owns
//     (role links, shared secret, OAuth client, other users' connections
//     and snapshots cascade), the user's own connections to any server,
//     tunnels, enrolled machines (tokens and assertion ids cascade),
//     machine enrollment codes, decided machine device requests and harness device grants, ephemeral
//     secrets and secret requests, upstream URL elicitations, Web Push subscriptions, connect flows, OAuth
//     authorization codes, connection secrets, role assignments, per-user restrictions and rate limits;
//   - kept but emptied: tokens and OAuth refresh tokens (revoked, token
//     names replaced), connections (revoked, external account id and
//     display name replaced), approvals (payload dropped, open ones
//     expired) — approvals, ledger operations and audit events reference
//     them;
//   - untouched: ledger operations and attempts, audit events (append-only
//     legal record, keyed by the now pseudonymous uuid).
//
// Published servers are not deleted here; the caller refuses the deletion
// while there are any (PublishedMCPServersOwnedBy).
func DeleteUserData(ctx context.Context, q Querier, userID string, at time.Time) (*UserDeletion, error) {
	out := &UserDeletion{}
	rows, err := q.Query(ctx, `DELETE FROM mcp_servers WHERE owner_user_id = $1 AND audience = 'private' RETURNING id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: delete user servers: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		out.ServerIDs = append(out.ServerIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: delete user servers: %w", err)
	}
	counted := []struct {
		dst  *int64
		what string
		sql  string
	}{
		{&out.Tunnels, "tunnels", `DELETE FROM mcp_tunnels WHERE owner_user_id = $1`},
		{&out.Machines, "machines", `DELETE FROM machines WHERE owner_user_id = $1`},
		{&out.Approvals, "approvals", `
			UPDATE approvals SET payload_key_id = NULL, payload_wrapped_key = NULL, payload_nonce = NULL, payload_ciphertext = NULL,
				status = CASE WHEN status IN ('pending', 'approved') THEN 'expired'::approval_status ELSE status END
			WHERE user_id = $1 AND (payload_ciphertext IS NOT NULL OR status IN ('pending', 'approved'))`},
		{&out.Connections, "connections", `
			UPDATE connections SET status = 'revoked', display_name = '', external_account_id = 'deleted:' || id::text, updated_at = $2
			WHERE user_id = $1`},
	}
	for _, c := range counted {
		tag, err := q.Exec(ctx, c.sql, withTime(c.sql, userID, at)...)
		if err != nil {
			return nil, fmt.Errorf("store: delete user %s: %w", c.what, err)
		}
		*c.dst = tag.RowsAffected()
	}
	for _, stmt := range []struct{ what, sql string }{
		{"server connections", `DELETE FROM mcp_server_user_connections WHERE user_id = $1`},
		{"connection secrets", `DELETE FROM connection_secrets WHERE user_id = $1`},
		{"connect flows", `DELETE FROM connect_flows WHERE user_id = $1`},
		{"authorization codes", `DELETE FROM oauth_authorization_codes WHERE user_id = $1`},
		{"refresh tokens", `UPDATE oauth_refresh_tokens SET revoked_at = coalesce(revoked_at, $2) WHERE user_id = $1`},
		{"tokens", `UPDATE tokens SET revoked_at = coalesce(revoked_at, $2), name = 'deleted' WHERE user_id = $1`},
		{"sessions", `DELETE FROM sessions WHERE user_id = $1`},
		{"identities", `DELETE FROM identities WHERE user_id = $1`},
		{"role assignments", `DELETE FROM role_assignments WHERE user_id = $1`},
		{"restrictions", `DELETE FROM user_restrictions WHERE user_id = $1`},
		{"rate limits", `DELETE FROM gateway_user_rate_limits WHERE user_id = $1`},
		{"resource caps", `DELETE FROM gateway_user_resource_caps WHERE user_id = $1`},
		{"enrollment codes", `DELETE FROM machine_enrollment_codes WHERE owner_user_id = $1`},
		{"machine requests", `DELETE FROM machine_device_requests WHERE decided_by = $1`},
		{"harness device grants", `DELETE FROM oauth_device_grants WHERE user_id = $1`},
		{"secrets", `DELETE FROM secrets WHERE owner_user_id = $1`},
		{"upstream elicitations", `DELETE FROM upstream_elicitations WHERE owner_user_id = $1`},
		{"push subscriptions", `DELETE FROM push_subscriptions WHERE user_id = $1`},
	} {
		if _, err := q.Exec(ctx, stmt.sql, withTime(stmt.sql, userID, at)...); err != nil {
			return nil, fmt.Errorf("store: delete user %s: %w", stmt.what, err)
		}
	}
	tag, err := q.Exec(ctx, `
		UPDATE users SET status = 'deleted', deleted_at = $2, disabled_at = coalesce(disabled_at, $2),
			display_name = '', last_company_sign_in_at = NULL, gateway_tools_enabled = false, updated_at = now()
		WHERE id = $1 AND status <> 'deleted'`, userID, at)
	if err != nil {
		return nil, fmt.Errorf("store: tombstone user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// withTime is the argument list for a deletion statement: the user id, and
// the deletion time when the statement uses it ($2).
func withTime(sql, userID string, at time.Time) []any {
	if strings.Contains(sql, "$2") {
		return []any{userID, at}
	}
	return []any{userID}
}
