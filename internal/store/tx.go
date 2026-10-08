package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the subset of pgx used by repositories; pgx.Tx satisfies it.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Tx is a transaction handed to WithUser / WithJobs callbacks. The raw
// Querier methods are available for queries the repositories do not cover;
// they run under the same user scope.
type Tx interface {
	Querier
	Users() UserRepository
	Identities() IdentityRepository
	Sessions() SessionRepository
	Roles() RoleRepository
	PolicyVersions() PolicyVersionRepository
	Tokens() TokenRepository
	OAuth() OAuthRepository
	VendorApps() VendorAppRepository
	Connections() ConnectionRepository
	Approvals() ApprovalRepository
	Ledger() LedgerRepository
	Audit() AuditRepository
	SigningKeys() SigningKeyRepository
	JobLocks() JobLockRepository
}

// The repositories below are deliberately minimal (insert + get, plus the
// child-row lookups needed to exercise every table) so this task proves the
// schema and row-level security; the owning modules extend them.

// UserRepository accesses users. Create needs the bypass scope (WithJobs)
// because a user cannot exist before its own scope does.
type UserRepository interface {
	Create(ctx context.Context, u *User) error
	Get(ctx context.Context, id string) (*User, error)
}

// IdentityRepository accesses identities.
type IdentityRepository interface {
	Create(ctx context.Context, i *Identity) error
	Get(ctx context.Context, id string) (*Identity, error)
}

// SessionRepository accesses sessions.
type SessionRepository interface {
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
}

// RoleRepository accesses roles, role assignments and user restrictions.
type RoleRepository interface {
	Create(ctx context.Context, r *Role) error
	Get(ctx context.Context, id string) (*Role, error)
	Assign(ctx context.Context, a *RoleAssignment) error
	AssignmentsForUser(ctx context.Context, userID string) ([]RoleAssignment, error)
	CreateRestriction(ctx context.Context, r *UserRestriction) error
	RestrictionsForUser(ctx context.Context, userID string) ([]UserRestriction, error)
}

// PolicyVersionRepository accesses compiled policy versions.
type PolicyVersionRepository interface {
	Create(ctx context.Context, p *PolicyVersion) error
	Get(ctx context.Context, id string) (*PolicyVersion, error)
}

// TokenRepository accesses generated tokens.
type TokenRepository interface {
	Create(ctx context.Context, t *Token) error
	Get(ctx context.Context, id string) (*Token, error)
}

// OAuthRepository accesses OAuth clients and refresh tokens.
type OAuthRepository interface {
	CreateClient(ctx context.Context, c *OAuthClient) error
	GetClient(ctx context.Context, id string) (*OAuthClient, error)
	CreateRefreshToken(ctx context.Context, t *OAuthRefreshToken) error
	GetRefreshToken(ctx context.Context, id string) (*OAuthRefreshToken, error)
}

// VendorAppRepository accesses vendor app registrations.
type VendorAppRepository interface {
	Create(ctx context.Context, a *VendorApp) error
	Get(ctx context.Context, id string) (*VendorApp, error)
}

// ConnectionRepository accesses connections and their secrets.
type ConnectionRepository interface {
	Create(ctx context.Context, c *Connection) error
	Get(ctx context.Context, id string) (*Connection, error)
	PutSecret(ctx context.Context, s *ConnectionSecret) error
	GetSecret(ctx context.Context, connectionID string) (*ConnectionSecret, error)
}

// ApprovalRepository accesses approvals.
type ApprovalRepository interface {
	Create(ctx context.Context, a *Approval) error
	Get(ctx context.Context, id string) (*Approval, error)
}

// LedgerRepository accesses ledger operations and attempts.
type LedgerRepository interface {
	CreateOperation(ctx context.Context, op *LedgerOperation) error
	GetOperation(ctx context.Context, id string) (*LedgerOperation, error)
	CreateAttempt(ctx context.Context, a *LedgerAttempt) error
	AttemptsForOperation(ctx context.Context, operationID string) ([]LedgerAttempt, error)
}

// AuditRepository appends and reads audit events. Purge is the retention
// job's delete and only works through WithJobs.
type AuditRepository interface {
	Create(ctx context.Context, e *AuditEvent) error
	Get(ctx context.Context, id string) (*AuditEvent, error)
	Purge(ctx context.Context, olderThan time.Time) error
}

// SigningKeyRepository accesses signing keys.
type SigningKeyRepository interface {
	Create(ctx context.Context, k *SigningKey) error
	Get(ctx context.Context, id string) (*SigningKey, error)
}

// JobLockRepository accesses job leases.
type JobLockRepository interface {
	Upsert(ctx context.Context, l *JobLock) error
	Get(ctx context.Context, name string) (*JobLock, error)
}

// scope implements Tx over a pgx transaction.
type scope struct {
	pgx.Tx
}

func (s *scope) Users() UserRepository                   { return userRepo{s.Tx} }
func (s *scope) Identities() IdentityRepository          { return identityRepo{s.Tx} }
func (s *scope) Sessions() SessionRepository             { return sessionRepo{s.Tx} }
func (s *scope) Roles() RoleRepository                   { return roleRepo{s.Tx} }
func (s *scope) PolicyVersions() PolicyVersionRepository { return policyVersionRepo{s.Tx} }
func (s *scope) Tokens() TokenRepository                 { return tokenRepo{s.Tx} }
func (s *scope) OAuth() OAuthRepository                  { return oauthRepo{s.Tx} }
func (s *scope) VendorApps() VendorAppRepository         { return vendorAppRepo{s.Tx} }
func (s *scope) Connections() ConnectionRepository       { return connectionRepo{s.Tx} }
func (s *scope) Approvals() ApprovalRepository           { return approvalRepo{s.Tx} }
func (s *scope) Ledger() LedgerRepository                { return ledgerRepo{s.Tx} }
func (s *scope) Audit() AuditRepository                  { return auditRepo{s.Tx} }
func (s *scope) SigningKeys() SigningKeyRepository       { return signingKeyRepo{s.Tx} }
func (s *scope) JobLocks() JobLockRepository             { return jobLockRepo{s.Tx} }

// notFound maps pgx's no-rows error to ErrNotFound.
func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
