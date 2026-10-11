package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ErrRoleAssigned reports a delete of a role that users still hold.
var ErrRoleAssigned = errors.New("policy: role is assigned to users")

// DefaultMaxAge bounds how long a compiled policy is used before the
// tables are read again: admin edits through this service invalidate at
// once, but role assignments made by the identity module (sign-in,
// /admin/users) and edits on another replica are only seen on reload.
const DefaultMaxAge = 15 * time.Second

// unknownUserRefresh bounds how often an unknown user (no assignment in
// the compiled set) may trigger an early reload.
const unknownUserRefresh = time.Second

// StoredRole is a role row: the role plus the default flag.
type StoredRole struct {
	Role
	IsDefault bool
}

// Snapshot is everything Compile needs, as read from the tables.
type Snapshot struct {
	Roles        []StoredRole
	Assignments  []Assignment
	Restrictions []UserRestriction
	// Owners are the implicit owner grants of private user-added MCP
	// servers (OwnerGrant); empty when there are none.
	Owners []OwnerGrant
}

// Version is one policy_versions row.
type Version struct {
	ID        string
	Hash      string
	Cedar     string
	CreatedBy string
	CreatedAt time.Time
}

// Store is the persistence the service needs: NewPostgresStore is the
// production implementation, policytest.MemStore the in-memory one.
type Store interface {
	// Load reads every role, assignment and restriction.
	Load(ctx context.Context) (Snapshot, error)
	// SaveRole inserts or updates the role named r.Name.
	SaveRole(ctx context.Context, r Role) error
	// DeleteRole removes a role: store.ErrNotFound when it does not exist,
	// ErrRoleAssigned when a user still holds it.
	DeleteRole(ctx context.Context, name string) error
	// SetDefaultRole flags name as the role new users get
	// (store.ErrNotFound when it does not exist).
	SetDefaultRole(ctx context.Context, name string) error
	// SaveVersion persists a compiled version, returning the existing
	// row when the hash is already stored.
	SaveVersion(ctx context.Context, v Version) (Version, error)
}

// Options configures New. Everything is optional.
type Options struct {
	// Audit records every admin change (actor = the admin's user ID).
	Audit audit.Recorder
	// Metrics counts decisions by outcome (policy_decisions_total).
	Metrics *observability.Metrics
	Log     *slog.Logger
	// MaxAge is the reload interval; 0 means DefaultMaxAge.
	MaxAge time.Duration
}

// Service owns the compiled policy: it loads roles, assignments and
// restrictions, compiles them, persists every new version, caches the
// result and answers Decide and Visible. Admin changes go through it so
// they are validated, audited and effective at once.
type Service struct {
	store   Store
	audit   audit.Recorder
	metrics *observability.Metrics
	log     *slog.Logger
	maxAge  time.Duration
	now     func() time.Time

	mu          sync.RWMutex
	current     *Compiled
	loadedAt    time.Time
	lastUnknown time.Time
	reload      sync.Mutex
}

// New builds the service over st. Nothing is loaded until first use.
func New(st Store, opts Options) (*Service, error) {
	if st == nil {
		return nil, errors.New("policy: store is required")
	}
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	return &Service{store: st, audit: opts.Audit, metrics: opts.Metrics, log: opts.Log, maxAge: opts.MaxAge, now: time.Now}, nil
}

// SetClock replaces the time source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Invalidate forces the next read to reload and recompile.
func (s *Service) Invalidate() {
	s.mu.Lock()
	s.loadedAt = time.Time{}
	s.mu.Unlock()
}

// Current returns the compiled policy in force, reloading when the cache
// is older than MaxAge. When a reload fails and a policy was loaded
// before, that policy stays in force and the error is logged: a database
// hiccup must not turn every call into a denial.
func (s *Service) Current(ctx context.Context) (*Compiled, error) {
	s.mu.RLock()
	c, loadedAt := s.current, s.loadedAt
	s.mu.RUnlock()
	if c != nil && s.now().Sub(loadedAt) < s.maxAge {
		return c, nil
	}
	return s.refresh(ctx, "")
}

// refresh reloads, compiles, persists a new version (createdBy is the
// admin whose change triggered it, or empty) and swaps the cache.
func (s *Service) refresh(ctx context.Context, createdBy string) (*Compiled, error) {
	s.reload.Lock()
	defer s.reload.Unlock()
	// Another goroutine may have refreshed while we waited.
	s.mu.RLock()
	c, loadedAt := s.current, s.loadedAt
	s.mu.RUnlock()
	if c != nil && !loadedAt.IsZero() && s.now().Sub(loadedAt) < s.maxAge && createdBy == "" {
		return c, nil
	}
	compiled, err := s.compile(ctx, createdBy)
	if err != nil {
		if c != nil {
			s.log.Error("policy reload failed; keeping the last good policy", "event", "policy.reload_failed",
				"version", c.Version, "error", observability.RedactError(err))
			return c, nil
		}
		return nil, err
	}
	s.mu.Lock()
	s.current, s.loadedAt = compiled, s.now()
	s.mu.Unlock()
	return compiled, nil
}

func (s *Service) compile(ctx context.Context, createdBy string) (*Compiled, error) {
	snap, err := s.store.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: load: %w", err)
	}
	roles := make([]Role, 0, len(snap.Roles))
	for _, r := range snap.Roles {
		roles = append(roles, r.Role)
	}
	compiled, err := CompileWithOwners(roles, snap.Assignments, snap.Restrictions, snap.Owners)
	if err != nil {
		return nil, fmt.Errorf("policy: compile: %w", err)
	}
	for _, w := range compiled.Warnings {
		s.log.Warn("restriction rule ignored", "event", "policy.restriction_ignored", "detail", w)
	}
	s.mu.RLock()
	prev := s.current
	s.mu.RUnlock()
	if prev != nil && prev.Version == compiled.Version {
		compiled.ID = prev.ID
		return compiled, nil
	}
	v, err := s.store.SaveVersion(ctx, Version{Hash: compiled.Version, Cedar: compiled.Cedar, CreatedBy: createdBy})
	if err != nil {
		return nil, fmt.Errorf("policy: save version: %w", err)
	}
	compiled.ID = v.ID
	s.log.Info("policy compiled", "event", "policy.compiled", "version", compiled.Version, "version_id", v.ID,
		"roles", len(roles), "assignments", len(snap.Assignments), "restrictions", len(snap.Restrictions), "owner_grants", len(snap.Owners), "created_by", createdBy)
	return compiled, nil
}

// Decide answers for the user's assigned roles (in.Roles is replaced: the
// caller cannot claim a role) and counts the outcome. Without any policy
// (first load failed) it returns deny with the error.
func (s *Service) Decide(ctx context.Context, in Input) (Decision, error) {
	c, err := s.forUser(ctx, in.UserID)
	if err != nil {
		return Decision{Outcome: OutcomeDeny, Reason: "policy unavailable"}, err
	}
	in.Roles = c.RolesFor(in.UserID)
	d := c.Decide(in)
	if s.metrics != nil {
		s.metrics.PolicyDecision(string(d.Outcome))
	}
	return d, nil
}

// Visible reports whether the tool is listed for the user and token.
func (s *Service) Visible(ctx context.Context, in Input) (bool, error) {
	c, err := s.forUser(ctx, in.UserID)
	if err != nil {
		return false, err
	}
	in.Roles = c.RolesFor(in.UserID)
	return c.Visible(in), nil
}

// forUser returns the current policy, reloading early (at most once per
// second) when userID has no assignment in it: the user may have been
// created or assigned since the last load.
func (s *Service) forUser(ctx context.Context, userID string) (*Compiled, error) {
	c, err := s.Current(ctx)
	if err != nil {
		return nil, err
	}
	if c.KnowsUser(userID) {
		return c, nil
	}
	s.mu.Lock()
	due := s.now().Sub(s.lastUnknown) >= unknownUserRefresh
	if due {
		s.lastUnknown = s.now()
		s.loadedAt = time.Time{}
	}
	s.mu.Unlock()
	if !due {
		return c, nil
	}
	return s.refresh(ctx, "")
}

// --- admin operations ---------------------------------------------------------

// Roles lists every role with its default flag, by name.
func (s *Service) Roles(ctx context.Context) ([]StoredRole, error) {
	snap, err := s.store.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: load: %w", err)
	}
	return snap.Roles, nil
}

// Role returns one role by name (store.ErrNotFound when missing).
func (s *Service) Role(ctx context.Context, name string) (Role, error) {
	roles, err := s.Roles(ctx)
	if err != nil {
		return Role{}, err
	}
	for _, r := range roles {
		if r.Name == name {
			return r.Role, nil
		}
	}
	return Role{}, store.ErrNotFound
}

// SaveRole validates, normalises and stores the role (creating it when
// the name is new), audits the change under actorID and recompiles.
func (s *Service) SaveRole(ctx context.Context, actorID string, r Role) error {
	r.Normalize()
	if err := r.Validate(); err != nil {
		return err
	}
	if err := s.store.SaveRole(ctx, r); err != nil {
		return err
	}
	return s.afterChange(ctx, actorID, "role_saved", r.Name)
}

// DeleteRole removes an unassigned role.
func (s *Service) DeleteRole(ctx context.Context, actorID, name string) error {
	if err := s.store.DeleteRole(ctx, name); err != nil {
		return err
	}
	return s.afterChange(ctx, actorID, "role_deleted", name)
}

// SetDefaultRole flags the role new users receive.
func (s *Service) SetDefaultRole(ctx context.Context, actorID, name string) error {
	if err := s.store.SetDefaultRole(ctx, name); err != nil {
		return err
	}
	return s.afterChange(ctx, actorID, "default_role_set", name)
}

// DefaultRole returns the flagged default role's name, or "" when none is
// flagged (the configured GATEWAY_DEFAULT_ROLE then applies).
func (s *Service) DefaultRole(ctx context.Context) (string, error) {
	roles, err := s.Roles(ctx)
	if err != nil {
		return "", err
	}
	for _, r := range roles {
		if r.IsDefault {
			return r.Name, nil
		}
	}
	return "", nil
}

// afterChange recompiles under the actor and records the audit event
// with the version now in force.
func (s *Service) afterChange(ctx context.Context, actorID, action, role string) error {
	c, err := s.refresh(ctx, actorID)
	if err != nil {
		return err
	}
	ev := audit.Event{
		Time:             s.now(),
		UserID:           actorID,
		ResourceIdentity: map[string]string{"action": action, "role": role},
		Decision:         "allow",
		PolicyVersion:    c.ID, // the row id: audit_events.policy_version_id is a uuid
		Outcome:          "succeeded",
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.Error("audit event not recorded", "event", "policy.audit_failed", "action", action, "role", role,
			"error", observability.RedactError(err))
	}
	s.log.Info("policy changed", "event", "policy."+action, "role", role, "actor_user_id", actorID, "version", c.Version)
	return nil
}
