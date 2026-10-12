package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Identity-module queries that the minimal repositories in tx.go do not
// cover: pre-authentication lookups (identity by issuer+subject, session by
// token hash), sign-in bookkeeping, role get-or-create and the admin user
// list.
//
// They take a Querier so they run under whichever scope the caller opened.
// Pre-auth lookups and just-in-time user creation run under WithJobs
// (decision 9z5sdzsm, point 3): a user scope cannot exist before the user is
// known. Self-service reads run under WithUser, where row-level security
// hides everyone else's rows.

// FindIdentity returns the identity bound to issuer+subject.
func FindIdentity(ctx context.Context, q Querier, issuer, subject string) (*Identity, error) {
	var i Identity
	err := q.QueryRow(ctx, `
		SELECT id, user_id, issuer, subject, last_sign_in_at, created_at
		FROM identities WHERE issuer = $1 AND subject = $2`, issuer, subject,
	).Scan(&i.ID, &i.UserID, &i.Issuer, &i.Subject, &i.LastSignInAt, &i.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &i, nil
}

// RecordSignIn stamps the company sign-in time on the user and the identity
// and refreshes the user's display name from the provider.
func RecordSignIn(ctx context.Context, q Querier, userID, identityID, displayName string, at time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE users SET last_company_sign_in_at = $2, display_name = $3, updated_at = now()
		WHERE id = $1`, userID, at, displayName)
	if err != nil {
		return fmt.Errorf("store: record sign-in: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := q.Exec(ctx, `UPDATE identities SET last_sign_in_at = $2 WHERE id = $1`, identityID, at); err != nil {
		return fmt.Errorf("store: record identity sign-in: %w", err)
	}
	return nil
}

// FindRoleByName returns the role called name.
func FindRoleByName(ctx context.Context, q Querier, name string) (*Role, error) {
	var role Role
	err := q.QueryRow(ctx, `
		SELECT id, name, description, definition, is_default, may_add_servers, created_at, updated_at
		FROM roles WHERE name = $1`, name,
	).Scan(&role.ID, &role.Name, &role.Description, &role.Definition, &role.IsDefault, &role.MayAddServers, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &role, nil
}

// EnsureRole returns the role called name, creating it with an empty
// definition when it does not exist yet. Safe under concurrent sign-ins:
// the insert ignores a conflicting name and the select runs afterwards.
func EnsureRole(ctx context.Context, q Querier, name, description string) (*Role, error) {
	if _, err := q.Exec(ctx, `
		INSERT INTO roles (name, description) VALUES ($1, $2)
		ON CONFLICT (name) DO NOTHING`, name, description); err != nil {
		return nil, fmt.Errorf("store: ensure role: %w", err)
	}
	return FindRoleByName(ctx, q, name)
}

// ListRoles returns every role ordered by name.
func ListRoles(ctx context.Context, q Querier) ([]Role, error) {
	return scanRoles(q.Query(ctx, `
		SELECT id, name, description, definition, is_default, may_add_servers, created_at, updated_at
		FROM roles ORDER BY name`))
}

// RolesForUser returns the roles assigned to userID ordered by name.
func RolesForUser(ctx context.Context, q Querier, userID string) ([]Role, error) {
	return scanRoles(q.Query(ctx, `
		SELECT r.id, r.name, r.description, r.definition, r.is_default, r.may_add_servers, r.created_at, r.updated_at
		FROM role_assignments a JOIN roles r ON r.id = a.role_id
		WHERE a.user_id = $1 ORDER BY r.name`, userID))
}

func scanRoles(rows pgx.Rows, err error) ([]Role, error) {
	if err != nil {
		return nil, fmt.Errorf("store: list roles: %w", err)
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.Definition, &role.IsDefault, &role.MayAddServers, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

// AssignRoleIfMissing adds a role to a user; an existing assignment is left
// untouched.
func AssignRoleIfMissing(ctx context.Context, q Querier, userID, roleID string, assignedBy *string) error {
	if _, err := q.Exec(ctx, `
		INSERT INTO role_assignments (user_id, role_id, assigned_by) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING`, userID, roleID, assignedBy); err != nil {
		return fmt.Errorf("store: assign role: %w", err)
	}
	return nil
}

// SetUserRole replaces every role assignment of userID with roleID.
func SetUserRole(ctx context.Context, q Querier, userID, roleID string, assignedBy *string) error {
	if _, err := q.Exec(ctx, `DELETE FROM role_assignments WHERE user_id = $1 AND role_id <> $2`, userID, roleID); err != nil {
		return fmt.Errorf("store: clear role assignments: %w", err)
	}
	return AssignRoleIfMissing(ctx, q, userID, roleID, assignedBy)
}

// FindSessionByTokenHash returns the session whose secret hashes to hash,
// whatever its state; callers check expiry and revocation.
func FindSessionByTokenHash(ctx context.Context, q Querier, hash []byte) (*Session, error) {
	var s Session
	err := q.QueryRow(ctx, `
		SELECT id, user_id, token_hash, created_at, expires_at, last_seen_at, revoked_at
		FROM sessions WHERE token_hash = $1`, hash,
	).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt, &s.LastSeenAt, &s.RevokedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

// TouchSession records activity on a session.
func TouchSession(ctx context.Context, q Querier, id string, at time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE sessions SET last_seen_at = $2 WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("store: touch session: %w", err)
	}
	return nil
}

// RevokeSession revokes one session; an already revoked session keeps its
// original revocation time.
func RevokeSession(ctx context.Context, q Querier, id string, at time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, at); err != nil {
		return fmt.Errorf("store: revoke session: %w", err)
	}
	return nil
}

// RevokeUserSessions revokes every live session of userID and returns how
// many it revoked.
func RevokeUserSessions(ctx context.Context, q Querier, userID string, at time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, userID, at)
	if err != nil {
		return 0, fmt.Errorf("store: revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SetUserStatus sets a user active or disabled, maintaining disabled_at.
func SetUserStatus(ctx context.Context, q Querier, userID, status string, at time.Time) error {
	var disabledAt *time.Time
	switch status {
	case UserActive:
	case UserDisabled:
		disabledAt = &at
	default:
		return fmt.Errorf("store: set user status: unknown status %q", status)
	}
	tag, err := q.Exec(ctx, `
		UPDATE users SET status = $2, disabled_at = $3, updated_at = now() WHERE id = $1`,
		userID, status, disabledAt)
	if err != nil {
		return fmt.Errorf("store: set user status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListUsers returns every user's metadata (through the admin_users view)
// ordered by creation time. Cross-user, so it only lists everyone under
// WithJobs; under WithUser it yields the caller's own row.
func ListUsers(ctx context.Context, q Querier) ([]User, error) {
	rows, err := q.Query(ctx, `
		SELECT id, display_name, status, last_company_sign_in_at, disabled_at, created_at, updated_at
		FROM admin_users ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.DisplayName, &u.Status, &u.LastCompanySignInAt, &u.DisabledAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
