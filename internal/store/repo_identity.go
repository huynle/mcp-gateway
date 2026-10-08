package store

import (
	"context"
	"fmt"
)

type userRepo struct{ q Querier }

func (r userRepo) Create(ctx context.Context, u *User) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO users (display_name, status)
		VALUES ($1, coalesce(nullif($2, ''), 'active'))
		RETURNING id, status, created_at, updated_at`,
		u.DisplayName, u.Status,
	).Scan(&u.ID, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: create user: %w", err)
	}
	return nil
}

func (r userRepo) Get(ctx context.Context, id string) (*User, error) {
	var u User
	err := r.q.QueryRow(ctx, `
		SELECT id, display_name, status, last_company_sign_in_at, disabled_at, created_at, updated_at
		FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.DisplayName, &u.Status, &u.LastCompanySignInAt, &u.DisabledAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &u, nil
}

type identityRepo struct{ q Querier }

func (r identityRepo) Create(ctx context.Context, i *Identity) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO identities (user_id, issuer, subject, last_sign_in_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`,
		i.UserID, i.Issuer, i.Subject, i.LastSignInAt,
	).Scan(&i.ID, &i.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create identity: %w", err)
	}
	return nil
}

func (r identityRepo) Get(ctx context.Context, id string) (*Identity, error) {
	var i Identity
	err := r.q.QueryRow(ctx, `
		SELECT id, user_id, issuer, subject, last_sign_in_at, created_at
		FROM identities WHERE id = $1`, id,
	).Scan(&i.ID, &i.UserID, &i.Issuer, &i.Subject, &i.LastSignInAt, &i.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &i, nil
}

type sessionRepo struct{ q Querier }

func (r sessionRepo) Create(ctx context.Context, s *Session) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, created_at`,
		s.UserID, s.TokenHash, s.ExpiresAt,
	).Scan(&s.ID, &s.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

func (r sessionRepo) Get(ctx context.Context, id string) (*Session, error) {
	var s Session
	err := r.q.QueryRow(ctx, `
		SELECT id, user_id, token_hash, created_at, expires_at, last_seen_at, revoked_at
		FROM sessions WHERE id = $1`, id,
	).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt, &s.LastSeenAt, &s.RevokedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

type roleRepo struct{ q Querier }

func (r roleRepo) Create(ctx context.Context, role *Role) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO roles (name, description, definition, is_default)
		VALUES ($1, $2, coalesce($3::jsonb, '{}'::jsonb), $4)
		RETURNING id, definition, created_at, updated_at`,
		role.Name, role.Description, role.Definition, role.IsDefault,
	).Scan(&role.ID, &role.Definition, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: create role: %w", err)
	}
	return nil
}

func (r roleRepo) Get(ctx context.Context, id string) (*Role, error) {
	var role Role
	err := r.q.QueryRow(ctx, `
		SELECT id, name, description, definition, is_default, created_at, updated_at
		FROM roles WHERE id = $1`, id,
	).Scan(&role.ID, &role.Name, &role.Description, &role.Definition, &role.IsDefault, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &role, nil
}

func (r roleRepo) Assign(ctx context.Context, a *RoleAssignment) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO role_assignments (user_id, role_id, assigned_by)
		VALUES ($1, $2, $3)
		RETURNING created_at`,
		a.UserID, a.RoleID, a.AssignedBy,
	).Scan(&a.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: assign role: %w", err)
	}
	return nil
}

func (r roleRepo) AssignmentsForUser(ctx context.Context, userID string) ([]RoleAssignment, error) {
	rows, err := r.q.Query(ctx, `
		SELECT user_id, role_id, assigned_by, created_at
		FROM role_assignments WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list role assignments: %w", err)
	}
	defer rows.Close()
	var out []RoleAssignment
	for rows.Next() {
		var a RoleAssignment
		if err := rows.Scan(&a.UserID, &a.RoleID, &a.AssignedBy, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r roleRepo) CreateRestriction(ctx context.Context, ur *UserRestriction) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO user_restrictions (user_id, definition, created_by)
		VALUES ($1, coalesce($2::jsonb, '{}'::jsonb), $3)
		RETURNING id, definition, created_at, updated_at`,
		ur.UserID, ur.Definition, ur.CreatedBy,
	).Scan(&ur.ID, &ur.Definition, &ur.CreatedAt, &ur.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: create user restriction: %w", err)
	}
	return nil
}

func (r roleRepo) RestrictionsForUser(ctx context.Context, userID string) ([]UserRestriction, error) {
	rows, err := r.q.Query(ctx, `
		SELECT id, user_id, definition, created_by, created_at, updated_at
		FROM user_restrictions WHERE user_id = $1 ORDER BY created_at`, userID)
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

type policyVersionRepo struct{ q Querier }

func (r policyVersionRepo) Create(ctx context.Context, p *PolicyVersion) error {
	err := r.q.QueryRow(ctx, `
		INSERT INTO policy_versions (version_hash, cedar, source)
		VALUES ($1, $2, coalesce($3::jsonb, '{}'::jsonb))
		RETURNING id, source, created_at`,
		p.VersionHash, p.Cedar, p.Source,
	).Scan(&p.ID, &p.Source, &p.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create policy version: %w", err)
	}
	return nil
}

func (r policyVersionRepo) Get(ctx context.Context, id string) (*PolicyVersion, error) {
	var p PolicyVersion
	err := r.q.QueryRow(ctx, `
		SELECT id, version_hash, cedar, source, created_at
		FROM policy_versions WHERE id = $1`, id,
	).Scan(&p.ID, &p.VersionHash, &p.Cedar, &p.Source, &p.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &p, nil
}
