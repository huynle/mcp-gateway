package store

import (
	"context"
	"fmt"
)

// The netguard SSRF allow-list (migration 00014) is global: every scope
// reads it (the dial-time check), only admins change it through WithJobs;
// gateway_app writes fail with permission denied. Patterns are stored as
// given; parsing and matching belong to internal/netguard.

const netguardAllowHostColumns = `id, pattern, note, created_by, created_at`

func scanNetguardAllowHost(row interface{ Scan(dest ...any) error }, h *NetguardAllowHost) error {
	return row.Scan(&h.ID, &h.Pattern, &h.Note, &h.CreatedBy, &h.CreatedAt)
}

// CreateNetguardAllowHost stores an allow-list entry; the stored row is
// written back into h.
func CreateNetguardAllowHost(ctx context.Context, q Querier, h *NetguardAllowHost) error {
	err := scanNetguardAllowHost(q.QueryRow(ctx, `
		INSERT INTO netguard_allow_hosts (pattern, note, created_by) VALUES ($1, $2, $3)
		RETURNING `+netguardAllowHostColumns, h.Pattern, h.Note, h.CreatedBy), h)
	if err != nil {
		return fmt.Errorf("store: create netguard allow host: %w", err)
	}
	return nil
}

// GetNetguardAllowHost returns an allow-list entry by ID.
func GetNetguardAllowHost(ctx context.Context, q Querier, id string) (*NetguardAllowHost, error) {
	var h NetguardAllowHost
	if err := scanNetguardAllowHost(q.QueryRow(ctx, `SELECT `+netguardAllowHostColumns+` FROM netguard_allow_hosts WHERE id = $1`, id), &h); err != nil {
		return nil, notFound(err)
	}
	return &h, nil
}

// ListNetguardAllowHosts returns the allow-list ordered by pattern.
func ListNetguardAllowHosts(ctx context.Context, q Querier) ([]NetguardAllowHost, error) {
	rows, err := q.Query(ctx, `SELECT `+netguardAllowHostColumns+` FROM netguard_allow_hosts ORDER BY pattern`)
	if err != nil {
		return nil, fmt.Errorf("store: list netguard allow hosts: %w", err)
	}
	defer rows.Close()
	var out []NetguardAllowHost
	for rows.Next() {
		var h NetguardAllowHost
		if err := scanNetguardAllowHost(rows, &h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// UpdateNetguardAllowHost rewrites an entry's pattern and note.
func UpdateNetguardAllowHost(ctx context.Context, q Querier, h *NetguardAllowHost) error {
	tag, err := q.Exec(ctx, `UPDATE netguard_allow_hosts SET pattern = $2, note = $3 WHERE id = $1`, h.ID, h.Pattern, h.Note)
	if err != nil {
		return fmt.Errorf("store: update netguard allow host: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteNetguardAllowHost removes an entry.
func DeleteNetguardAllowHost(ctx context.Context, q Querier, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM netguard_allow_hosts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete netguard allow host: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
