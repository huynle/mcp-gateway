package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// MCP server capability snapshots (migration 00014). Snapshots are visible
// like their server. The owner adds pending snapshots, and reviews them
// only while the server is private; once published, approving is an admin
// action (WithJobs). Approving supersedes the previously approved snapshot,
// so at most one is current per server (enforced by a partial unique index).

const mcpSnapshotColumns = `id, server_id, version, status, discovered_at, approved_by, approved_at,
	tools, resources, resource_templates, prompts, review`

func scanMCPSnapshot(row interface{ Scan(dest ...any) error }, s *MCPSnapshot) error {
	return row.Scan(&s.ID, &s.ServerID, &s.Version, &s.Status, &s.DiscoveredAt, &s.ApprovedBy, &s.ApprovedAt,
		&s.Tools, &s.Resources, &s.ResourceTemplates, &s.Prompts, &s.Review)
}

// CreateMCPSnapshot stores a newly discovered snapshot as the server's next
// version (pending unless s.Status says otherwise). Nil JSON fields take
// the column defaults. The stored row is written back into s; two
// concurrent creates for one server fail one with a unique violation.
func CreateMCPSnapshot(ctx context.Context, q Querier, s *MCPSnapshot) error {
	err := scanMCPSnapshot(q.QueryRow(ctx, `
		INSERT INTO mcp_server_snapshots (server_id, version, status, tools, resources, resource_templates, prompts, review)
		SELECT $1, coalesce(max(version), 0) + 1, coalesce(nullif($2, ''), 'pending'),
			coalesce($3::jsonb, '[]'::jsonb), coalesce($4::jsonb, '[]'::jsonb), coalesce($5::jsonb, '[]'::jsonb),
			coalesce($6::jsonb, '[]'::jsonb), coalesce($7::jsonb, '{}'::jsonb)
		FROM mcp_server_snapshots WHERE server_id = $1
		RETURNING `+mcpSnapshotColumns,
		s.ServerID, s.Status, s.Tools, s.Resources, s.ResourceTemplates, s.Prompts, s.Review,
	), s)
	if err != nil {
		return fmt.Errorf("store: create mcp snapshot: %w", err)
	}
	return nil
}

// GetMCPSnapshot returns a visible snapshot by ID.
func GetMCPSnapshot(ctx context.Context, q Querier, id string) (*MCPSnapshot, error) {
	var s MCPSnapshot
	if err := scanMCPSnapshot(q.QueryRow(ctx, `SELECT `+mcpSnapshotColumns+` FROM mcp_server_snapshots WHERE id = $1`, id), &s); err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

// LatestMCPSnapshot returns a server's highest-version snapshot, whatever
// its status (the one a review page diffs against the approved one).
func LatestMCPSnapshot(ctx context.Context, q Querier, serverID string) (*MCPSnapshot, error) {
	var s MCPSnapshot
	err := scanMCPSnapshot(q.QueryRow(ctx, `SELECT `+mcpSnapshotColumns+` FROM mcp_server_snapshots
		WHERE server_id = $1 ORDER BY version DESC LIMIT 1`, serverID), &s)
	if err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

// ApprovedMCPSnapshot returns a server's current approved snapshot, the
// only one calls may be served from.
func ApprovedMCPSnapshot(ctx context.Context, q Querier, serverID string) (*MCPSnapshot, error) {
	var s MCPSnapshot
	err := scanMCPSnapshot(q.QueryRow(ctx, `SELECT `+mcpSnapshotColumns+` FROM mcp_server_snapshots
		WHERE server_id = $1 AND status = 'approved'`, serverID), &s)
	if err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

// ListMCPSnapshots returns a server's snapshot history, newest first.
func ListMCPSnapshots(ctx context.Context, q Querier, serverID string) ([]MCPSnapshot, error) {
	rows, err := q.Query(ctx, `SELECT `+mcpSnapshotColumns+` FROM mcp_server_snapshots
		WHERE server_id = $1 ORDER BY version DESC`, serverID)
	if err != nil {
		return nil, fmt.Errorf("store: list mcp snapshots: %w", err)
	}
	defer rows.Close()
	var out []MCPSnapshot
	for rows.Next() {
		var s MCPSnapshot
		if err := scanMCPSnapshot(rows, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateApprovedMCPSnapshotReview rewrites the review of the server's
// approved snapshot id without touching its status or approval record
// (the approval-mode edit). ErrNotFound when the row is not the approved
// one or the caller may not update it (row-level security: the owner
// only while the server is private).
func UpdateApprovedMCPSnapshotReview(ctx context.Context, q Querier, id string, review json.RawMessage) error {
	tag, err := q.Exec(ctx, `UPDATE mcp_server_snapshots SET review = $2::jsonb WHERE id = $1 AND status = 'approved'`, id, review)
	if err != nil {
		return fmt.Errorf("store: update mcp snapshot review: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ApproveMCPSnapshot makes snapshot id its server's approved snapshot,
// recording who approved it (approvedBy may be empty for a system action)
// and, when review is not nil, the reviewer's per-tool decisions; the
// previously approved snapshot becomes superseded. ErrNotFound when the
// snapshot does not exist or the caller may not review it. The caller must
// return the error so the transaction rolls back.
func ApproveMCPSnapshot(ctx context.Context, q Querier, id, approvedBy string, review json.RawMessage) error {
	_, err := q.Exec(ctx, `
		UPDATE mcp_server_snapshots SET status = 'superseded'
		WHERE status = 'approved' AND id <> $1
		  AND server_id = (SELECT server_id FROM mcp_server_snapshots WHERE id = $1)`, id)
	if err != nil {
		return fmt.Errorf("store: supersede mcp snapshot: %w", err)
	}
	tag, err := q.Exec(ctx, `
		UPDATE mcp_server_snapshots SET status = 'approved', approved_by = nullif($2, '')::uuid, approved_at = now(),
			review = coalesce($3::jsonb, review)
		WHERE id = $1`, id, approvedBy, review)
	if err != nil {
		return fmt.Errorf("store: approve mcp snapshot: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
