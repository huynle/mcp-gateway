package store

import (
	"context"
	"fmt"
)

// VendorToolApproval is one vendor_tool_approvals row: a built-in app's
// write tool set to Ask (absent tools are Auto).
type VendorToolApproval struct {
	App, Tool string
}

// ListVendorToolApprovals returns every Ask row, by app and tool.
func ListVendorToolApprovals(ctx context.Context, q Querier) ([]VendorToolApproval, error) {
	rows, err := q.Query(ctx, `SELECT app, tool FROM vendor_tool_approvals ORDER BY app, tool`)
	if err != nil {
		return nil, fmt.Errorf("store: list vendor tool approvals: %w", err)
	}
	defer rows.Close()
	var out []VendorToolApproval
	for rows.Next() {
		var x VendorToolApproval
		if err := rows.Scan(&x.App, &x.Tool); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ReplaceVendorToolApprovals makes ask the app's complete Ask set on
// behalf of actor (a user ID, or "" for none). Rows of tools that stay Ask
// keep their updated_by / updated_at.
func ReplaceVendorToolApprovals(ctx context.Context, q Querier, app string, ask []string, actor string) error {
	if ask == nil {
		ask = []string{}
	}
	if _, err := q.Exec(ctx, `DELETE FROM vendor_tool_approvals WHERE app = $1 AND NOT (tool = ANY($2))`, app, ask); err != nil {
		return fmt.Errorf("store: replace vendor tool approvals: %w", err)
	}
	if len(ask) == 0 {
		return nil
	}
	if _, err := q.Exec(ctx, `INSERT INTO vendor_tool_approvals (app, tool, updated_by)
		SELECT $1, t, $3 FROM unnest($2::text[]) AS t ON CONFLICT (app, tool) DO NOTHING`, app, ask, nullString(actor)); err != nil {
		return fmt.Errorf("store: replace vendor tool approvals: %w", err)
	}
	return nil
}
