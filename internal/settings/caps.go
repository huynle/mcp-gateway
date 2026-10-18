package settings

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"regexp"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// ErrInvalidCap is a refused cap change: unknown resource, a value outside
// 0..caps.Max, an empty change or a malformed user ID.
var ErrInvalidCap = errors.New("settings: resource cap must be a known resource with a value between 0 (unlimited) and 100000")

// CapsSnapshot is the persisted state: organization values and per-user
// administrator overrides (absent resources inherit), and who is an admin.
type CapsSnapshot struct {
	Org     caps.Values
	Users   map[string]caps.Values
	Admins  map[string]bool
	Version int64
}

// CapsStore persists resource caps (NewPostgresCapsStore).
type CapsStore interface {
	LoadCaps(ctx context.Context) (CapsSnapshot, error)
	PatchOrgCaps(ctx context.Context, p caps.Patch, actor string) error
	PatchUserCaps(ctx context.Context, user string, p caps.Patch, actor string) error
}

// CapsOptions configures NewCaps. Defaults are the ENV values; a missing
// or non-positive one falls back to caps.Builtin (ENV never means
// unlimited).
type CapsOptions struct {
	Defaults       caps.Values
	ReloadInterval time.Duration
	Audit          audit.Recorder
	Log            *slog.Logger
	Now            func() time.Time
}

// CapsService resolves and changes per-user resource caps: per-user
// administrator override, else organization value, else ENV default. It
// implements caps.Limiter. Like Service (rate limits) the snapshot is
// cached for ReloadInterval and refreshed at once after a local change.
type CapsService struct {
	st       CapsStore
	defaults caps.Values
	reload   time.Duration
	audit    audit.Recorder
	log      *slog.Logger
	now      func() time.Time
	mu       sync.RWMutex
	snap     CapsSnapshot
	loaded   time.Time
}

// NewCaps builds the service over st.
func NewCaps(st CapsStore, o CapsOptions) *CapsService {
	if o.ReloadInterval <= 0 {
		o.ReloadInterval = DefaultReloadInterval
	}
	if o.Audit == nil {
		o.Audit = audit.NopRecorder{}
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	d := caps.Values{}
	for _, r := range caps.Resources {
		d[r] = caps.Builtin[r]
		if v, ok := o.Defaults[r]; ok && v > 0 && v <= caps.Max {
			d[r] = v
		}
	}
	return &CapsService{st: st, defaults: d, reload: o.ReloadInterval, audit: o.Audit, log: o.Log, now: o.Now}
}

func cloneCaps(s CapsSnapshot) CapsSnapshot {
	s.Org = maps.Clone(s.Org)
	if s.Org == nil {
		s.Org = caps.Values{}
	}
	users := make(map[string]caps.Values, len(s.Users))
	for k, v := range s.Users {
		users[k] = maps.Clone(v)
	}
	s.Users = users
	s.Admins = maps.Clone(s.Admins)
	if s.Admins == nil {
		s.Admins = map[string]bool{}
	}
	return s
}

// Refresh reloads the snapshot from the store.
func (s *CapsService) Refresh(ctx context.Context) error {
	v, err := s.st.LoadCaps(ctx)
	if err != nil {
		return err
	}
	v = cloneCaps(v)
	s.mu.Lock()
	s.snap, s.loaded = v, s.now()
	s.mu.Unlock()
	return nil
}

func (s *CapsService) snapshot(ctx context.Context) CapsSnapshot {
	s.mu.RLock()
	v, at := s.snap, s.loaded
	s.mu.RUnlock()
	if at.IsZero() || s.now().Sub(at) >= s.reload {
		if err := s.Refresh(ctx); err != nil {
			s.log.Error("resource caps refresh failed; using last/default values", "error", observability.RedactError(err))
			if at.IsZero() {
				return cloneCaps(CapsSnapshot{})
			}
		}
		s.mu.RLock()
		v = s.snap
		s.mu.RUnlock()
	}
	return cloneCaps(v)
}

func (s *CapsService) resolve(v CapsSnapshot, user string, r caps.Resource) int {
	if n, ok := v.Users[user][r]; ok {
		return n
	}
	if n, ok := v.Org[r]; ok {
		return n
	}
	return s.defaults[r]
}

// Limit implements caps.Limiter: the user's effective cap, 0 = unlimited.
func (s *CapsService) Limit(ctx context.Context, user string, r caps.Resource) int {
	return s.resolve(s.snapshot(ctx), user, r)
}

// Refused implements caps.Limiter: one log line per refusal.
func (s *CapsService) Refused(ctx context.Context, user string, r caps.Resource, limit int) {
	s.log.Warn("resource cap reached", "event", "caps.exceeded", "class", caps.Class, "user_id", user,
		"resource", string(r), "limit", limit, observability.RequestIDAttr(ctx))
}

// Effective returns every resource's effective cap for user.
func (s *CapsService) Effective(ctx context.Context, user string) caps.Values {
	v := s.snapshot(ctx)
	out := caps.Values{}
	for _, r := range caps.Resources {
		out[r] = s.resolve(v, user, r)
	}
	return out
}

// Defaults returns the ENV (or built-in) defaults.
func (s *CapsService) Defaults() caps.Values { return maps.Clone(s.defaults) }

// CapsSnapshot returns the persisted state (admin pages and tools).
func (s *CapsService) CapsSnapshot(ctx context.Context) CapsSnapshot { return s.snapshot(ctx) }

// IsAdmin reports whether user holds the admin role (from the snapshot).
func (s *CapsService) IsAdmin(ctx context.Context, user string) bool {
	return s.snapshot(ctx).Admins[user]
}

func validPatch(p caps.Patch) bool {
	if len(p) == 0 {
		return false
	}
	for r, v := range p {
		if !caps.Valid(r) || (v != nil && (*v < 0 || *v > caps.Max)) {
			return false
		}
	}
	return true
}

// SetOrg changes organization values (administrators only; audited).
func (s *CapsService) SetOrg(ctx context.Context, actor string, p caps.Patch) error {
	if !s.IsAdmin(ctx, actor) {
		return ErrNotAdmin
	}
	if !validPatch(p) {
		return ErrInvalidCap
	}
	if err := s.st.PatchOrgCaps(ctx, p, actor); err != nil {
		return err
	}
	if err := s.Refresh(ctx); err != nil {
		return err
	}
	s.recordCaps(ctx, actor, "organization.resource_caps_changed", "", p)
	return nil
}

// SetUser changes one user's administrator overrides (audited).
func (s *CapsService) SetUser(ctx context.Context, actor, user string, p caps.Patch) error {
	if !s.IsAdmin(ctx, actor) {
		return ErrNotAdmin
	}
	if !uuidRE.MatchString(user) || !validPatch(p) {
		return ErrInvalidCap
	}
	if err := s.st.PatchUserCaps(ctx, user, p, actor); err != nil {
		return err
	}
	if err := s.Refresh(ctx); err != nil {
		return err
	}
	s.recordCaps(ctx, actor, "organization.user_resource_caps_changed", user, p)
	return nil
}

func (s *CapsService) recordCaps(ctx context.Context, actor, action, target string, p caps.Patch) {
	r := map[string]string{"action": action}
	if target != "" {
		r["target_user"] = target
	}
	for res, v := range p {
		r[string(res)] = fmtLimit(v)
	}
	if err := s.audit.Record(ctx, audit.Event{Time: s.now(), UserID: actor, ResourceIdentity: r, Decision: "allow", Outcome: "succeeded", RequestID: observability.RequestIDFromContext(ctx)}); err != nil {
		s.log.Error("settings audit failed", "action", action, "error", observability.RedactError(err))
	}
}

var _ caps.Limiter = (*CapsService)(nil)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
