package store

import (
	"context"
	"fmt"
)

// Gateway management permission and setting (schema 16; Brain task
// ds5tjou2, decision bnneszc1). Both run in the user's own scope
// (WithUser): row-level security on role_assignments and users then only
// shows the user's own rows, so asking about anyone else answers "no" /
// ErrNotFound.

// UserMayAddServers reports whether userID holds the role named adminRole
// or any role with may_add_servers. In another user's scope the answer is
// false (their assignments are invisible).
func UserMayAddServers(ctx context.Context, q Querier, userID, adminRole string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM role_assignments a JOIN roles r ON r.id = a.role_id
			WHERE a.user_id = $1 AND (r.may_add_servers OR r.name = $2))`, userID, adminRole).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("store: may add servers: %w", err)
	}
	return ok, nil
}

// GatewayToolsEnabled returns the user's "Gateway management tools"
// setting; ErrNotFound when the row is not visible (another user, in a
// user scope).
func GatewayToolsEnabled(ctx context.Context, q Querier, userID string) (bool, error) {
	var on bool
	err := q.QueryRow(ctx, `SELECT gateway_tools_enabled FROM users WHERE id = $1`, userID).Scan(&on)
	if err != nil {
		return false, notFound(err)
	}
	return on, nil
}

// SetGatewayToolsEnabled stores the user's setting. gateway_app may update
// this one column of its own row only (column grant + users_self policy);
// ErrNotFound when no visible row matched.
func SetGatewayToolsEnabled(ctx context.Context, q Querier, userID string, on bool) error {
	tag, err := q.Exec(ctx, `UPDATE users SET gateway_tools_enabled = $2 WHERE id = $1`, userID, on)
	if err != nil {
		return fmt.Errorf("store: set gateway tools: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
