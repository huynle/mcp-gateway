package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// Policy-module queries over the roles, role_assignments, user_restrictions
// and policy_versions tables (decision 490o45d0). They take a Querier so
// they run under whichever scope the caller opened; the policy service
// runs them under WithJobs (cross-user reads and admin writes), like the
// identity module's admin actions.

// RoleAssignmentName is one role_assignments row joined with its role's
// name, which is what the policy compiler keys on.
type RoleAssignmentName struct {
	UserID   string
	RoleName string
}

// ListRoleAssignments returns every (user, role name) pair. Cross-user, so
// only WithJobs sees them all.
func ListRoleAssignments(ctx context.Context, q Querier) ([]RoleAssignmentName, error) {
	rows, err := q.Query(ctx, `
		SELECT a.user_id, r.name
		FROM role_assignments a JOIN roles r ON r.id = a.role_id
		ORDER BY a.user_id, r.name`)
	if err != nil {
		return nil, fmt.Errorf("store: list role assignments: %w", err)
	}
	defer rows.Close()
	var out []RoleAssignmentName
	for rows.Next() {
		var a RoleAssignmentName
		if err := rows.Scan(&a.UserID, &a.RoleName); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListUserRestrictions returns every user restriction. Cross-user, so only
// WithJobs sees them all.
func ListUserRestrictions(ctx context.Context, q Querier) ([]UserRestriction, error) {
	rows, err := q.Query(ctx, `
		SELECT id, user_id, definition, created_by, created_at, updated_at
		FROM user_restrictions ORDER BY user_id, created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: list user restrictions: %w", err)
	}
	defer rows.Close()
	var out []UserRestriction
	for rows.Next() {
		var ur UserRestriction
		if err := rows.Scan(&ur.ID, &ur.UserID, &ur.Definition, &ur.CreatedBy, &ur.CreatedAt, &ur.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, ur)
	}
	return out, rows.Err()
}

// UpsertRole creates the role called name or replaces its description,
// definition and may-add-servers flag. Admin path only: gateway_app has no
// write privilege on roles (schema 16).
func UpsertRole(ctx context.Context, q Querier, name, description string, definition json.RawMessage, mayAddServers bool) error {
	if _, err := q.Exec(ctx, `
		INSERT INTO roles (name, description, definition, may_add_servers)
		VALUES ($1, $2, coalesce($3::jsonb, '{}'::jsonb), $4)
		ON CONFLICT (name) DO UPDATE
		SET description = excluded.description, definition = excluded.definition,
		    may_add_servers = excluded.may_add_servers, updated_at = now()`,
		name, description, definition, mayAddServers); err != nil {
		return fmt.Errorf("store: upsert role: %w", err)
	}
	return nil
}

// CountRoleAssignments returns how many users hold the role called name.
func CountRoleAssignments(ctx context.Context, q Querier, name string) (int64, error) {
	var n int64
	err := q.QueryRow(ctx, `
		SELECT count(*) FROM role_assignments a JOIN roles r ON r.id = a.role_id WHERE r.name = $1`, name).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count role assignments: %w", err)
	}
	return n, nil
}

// DeleteRole removes the role called name; ErrNotFound when there is none.
// Callers check CountRoleAssignments first: the foreign key would refuse
// the delete anyway, with a less useful error.
func DeleteRole(ctx context.Context, q Querier, name string) error {
	tag, err := q.Exec(ctx, `DELETE FROM roles WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("store: delete role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDefaultRole flags the role called name as the one new users receive
// and clears the flag everywhere else (the partial unique index allows one
// default). ErrNotFound when there is no such role; the clearing update is
// then rolled back with the transaction.
func SetDefaultRole(ctx context.Context, q Querier, name string) error {
	if _, err := q.Exec(ctx, `UPDATE roles SET is_default = false, updated_at = now() WHERE is_default`); err != nil {
		return fmt.Errorf("store: clear default role: %w", err)
	}
	tag, err := q.Exec(ctx, `UPDATE roles SET is_default = true, updated_at = now() WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("store: set default role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FindDefaultRole returns the role flagged is_default (ErrNotFound when
// none is).
func FindDefaultRole(ctx context.Context, q Querier) (*Role, error) {
	var role Role
	err := q.QueryRow(ctx, `
		SELECT id, name, description, definition, is_default, may_add_servers, created_at, updated_at
		FROM roles WHERE is_default`,
	).Scan(&role.ID, &role.Name, &role.Description, &role.Definition, &role.IsDefault, &role.MayAddServers, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &role, nil
}

// EnsurePolicyVersion stores a compiled policy version unless its hash is
// already present, and returns the stored row either way.
func EnsurePolicyVersion(ctx context.Context, q Querier, p *PolicyVersion) (*PolicyVersion, error) {
	if _, err := q.Exec(ctx, `
		INSERT INTO policy_versions (version_hash, cedar, source, created_by)
		VALUES ($1, $2, coalesce($3::jsonb, '{}'::jsonb), $4)
		ON CONFLICT (version_hash) DO NOTHING`,
		p.VersionHash, p.Cedar, p.Source, p.CreatedBy); err != nil {
		return nil, fmt.Errorf("store: ensure policy version: %w", err)
	}
	var out PolicyVersion
	err := q.QueryRow(ctx, `
		SELECT id, version_hash, cedar, source, created_by, created_at
		FROM policy_versions WHERE version_hash = $1`, p.VersionHash,
	).Scan(&out.ID, &out.VersionHash, &out.Cedar, &out.Source, &out.CreatedBy, &out.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}
