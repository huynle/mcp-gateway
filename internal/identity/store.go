package identity

import (
	"context"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Store is the persistence the identity service needs. The production
// implementation (NewPostgresStore) runs Bypass through store.WithJobs and
// AsUser through store.WithUser; unit tests use an in-memory fake.
type Store interface {
	// Bypass runs fn in one transaction that sees every row. Used for the
	// lookups that precede user resolution (identity by issuer+subject,
	// session by hash), just-in-time user creation and admin actions
	// (decision 9z5sdzsm, point 3).
	Bypass(ctx context.Context, fn func(Tx) error) error
	// AsUser runs fn scoped to userID: row-level security hides everyone
	// else's rows.
	AsUser(ctx context.Context, userID string, fn func(Tx) error) error
}

// Tx is the set of persistence operations the identity service performs
// inside one transaction. Methods map one-to-one onto store repositories
// and the helpers in store/repo_identity_lookup.go.
type Tx interface {
	// Raw exposes the underlying store transaction so DisableHooks from
	// other modules can revoke their own rows atomically. Nil in fakes.
	Raw() store.Tx

	FindIdentity(ctx context.Context, issuer, subject string) (*store.Identity, error)
	GetUser(ctx context.Context, id string) (*store.User, error)
	CreateUser(ctx context.Context, displayName string) (*store.User, error)
	CreateIdentity(ctx context.Context, userID, issuer, subject string) (*store.Identity, error)
	RecordSignIn(ctx context.Context, userID, identityID, displayName string, at time.Time) error

	FindRoleByName(ctx context.Context, name string) (*store.Role, error)
	// FindDefaultRole returns the role admins flagged as the default in
	// the portal (store.ErrNotFound when none is flagged).
	FindDefaultRole(ctx context.Context) (*store.Role, error)
	EnsureRole(ctx context.Context, name, description string) (*store.Role, error)
	ListRoles(ctx context.Context) ([]store.Role, error)
	AssignRole(ctx context.Context, userID, roleID string, assignedBy *string) error
	SetUserRole(ctx context.Context, userID, roleID string, assignedBy *string) error
	RolesForUser(ctx context.Context, userID string) ([]store.Role, error)

	ListUsers(ctx context.Context) ([]store.User, error)
	SetUserStatus(ctx context.Context, userID, status string, at time.Time) error

	CreateSession(ctx context.Context, userID string, tokenHash []byte, expiresAt time.Time) (*store.Session, error)
	FindSessionByTokenHash(ctx context.Context, hash []byte) (*store.Session, error)
	TouchSession(ctx context.Context, id string, at time.Time) error
	RevokeSession(ctx context.Context, id string, at time.Time) error
	RevokeUserSessions(ctx context.Context, userID string, at time.Time) (int64, error)
}

// postgresStore adapts *store.Store to Store.
type postgresStore struct{ st *store.Store }

// NewPostgresStore returns the production Store over the PostgreSQL store.
func NewPostgresStore(st *store.Store) Store { return postgresStore{st: st} }

func (p postgresStore) Bypass(ctx context.Context, fn func(Tx) error) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return fn(pgTx{tx}) })
}

func (p postgresStore) AsUser(ctx context.Context, userID string, fn func(Tx) error) error {
	return p.st.WithUser(ctx, userID, func(tx store.Tx) error { return fn(pgTx{tx}) })
}

type pgTx struct{ tx store.Tx }

func (t pgTx) Raw() store.Tx { return t.tx }

func (t pgTx) FindIdentity(ctx context.Context, issuer, subject string) (*store.Identity, error) {
	return store.FindIdentity(ctx, t.tx, issuer, subject)
}

func (t pgTx) GetUser(ctx context.Context, id string) (*store.User, error) {
	return t.tx.Users().Get(ctx, id)
}

func (t pgTx) CreateUser(ctx context.Context, displayName string) (*store.User, error) {
	u := &store.User{DisplayName: displayName, Status: store.UserActive}
	if err := t.tx.Users().Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (t pgTx) CreateIdentity(ctx context.Context, userID, issuer, subject string) (*store.Identity, error) {
	i := &store.Identity{UserID: userID, Issuer: issuer, Subject: subject}
	if err := t.tx.Identities().Create(ctx, i); err != nil {
		return nil, err
	}
	return i, nil
}

func (t pgTx) RecordSignIn(ctx context.Context, userID, identityID, displayName string, at time.Time) error {
	return store.RecordSignIn(ctx, t.tx, userID, identityID, displayName, at)
}

func (t pgTx) FindRoleByName(ctx context.Context, name string) (*store.Role, error) {
	return store.FindRoleByName(ctx, t.tx, name)
}

func (t pgTx) FindDefaultRole(ctx context.Context) (*store.Role, error) {
	return store.FindDefaultRole(ctx, t.tx)
}

func (t pgTx) EnsureRole(ctx context.Context, name, description string) (*store.Role, error) {
	return store.EnsureRole(ctx, t.tx, name, description)
}

func (t pgTx) ListRoles(ctx context.Context) ([]store.Role, error) {
	return store.ListRoles(ctx, t.tx)
}

func (t pgTx) AssignRole(ctx context.Context, userID, roleID string, assignedBy *string) error {
	return store.AssignRoleIfMissing(ctx, t.tx, userID, roleID, assignedBy)
}

func (t pgTx) SetUserRole(ctx context.Context, userID, roleID string, assignedBy *string) error {
	return store.SetUserRole(ctx, t.tx, userID, roleID, assignedBy)
}

func (t pgTx) RolesForUser(ctx context.Context, userID string) ([]store.Role, error) {
	return store.RolesForUser(ctx, t.tx, userID)
}

func (t pgTx) ListUsers(ctx context.Context) ([]store.User, error) {
	return store.ListUsers(ctx, t.tx)
}

func (t pgTx) SetUserStatus(ctx context.Context, userID, status string, at time.Time) error {
	return store.SetUserStatus(ctx, t.tx, userID, status, at)
}

func (t pgTx) CreateSession(ctx context.Context, userID string, tokenHash []byte, expiresAt time.Time) (*store.Session, error) {
	s := &store.Session{UserID: userID, TokenHash: tokenHash, ExpiresAt: expiresAt}
	if err := t.tx.Sessions().Create(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

func (t pgTx) FindSessionByTokenHash(ctx context.Context, hash []byte) (*store.Session, error) {
	return store.FindSessionByTokenHash(ctx, t.tx, hash)
}

func (t pgTx) TouchSession(ctx context.Context, id string, at time.Time) error {
	return store.TouchSession(ctx, t.tx, id, at)
}

func (t pgTx) RevokeSession(ctx context.Context, id string, at time.Time) error {
	return store.RevokeSession(ctx, t.tx, id, at)
}

func (t pgTx) RevokeUserSessions(ctx context.Context, userID string, at time.Time) (int64, error) {
	return store.RevokeUserSessions(ctx, t.tx, userID, at)
}
