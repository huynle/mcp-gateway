// Package settings owns durable gateway-wide and per-user runtime settings.
// Environment configuration is the fallback; persisted values take precedence.
package settings

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
)

const (
	MinPerMinute          = 1
	MaxPerMinute          = 100000
	DefaultReloadInterval = 2 * time.Second
)

var (
	ErrInvalidLimit     = errors.New("settings: rate limit must be between 1 and 100000")
	ErrNotAdmin         = errors.New("settings: administrator required")
	ErrSelfLimitTooHigh = errors.New("settings: personal ceiling cannot exceed the administrator limit")
	appRE               = regexp.MustCompile(`^[a-z0-9_-]{1,63}$`)
)

type UserLimit struct{ Admin, Self *int }
type Snapshot struct {
	UserDefault, AppDefault int
	Apps                    map[string]int
	Users                   map[string]UserLimit
	Admins                  map[string]bool
	Version                 int64
}

type Store interface {
	Load(ctx context.Context) (Snapshot, error)
	SetOrg(ctx context.Context, user, app int, actor string) error
	SetApp(ctx context.Context, app string, limit *int, actor string) error
	SetUserAdmin(ctx context.Context, user string, limit *int, actor string) error
	SetUserSelf(ctx context.Context, user string, limit *int) error
}

type Options struct {
	DefaultUserPerMinute, DefaultAppPerMinute int
	ReloadInterval                            time.Duration
	Audit                                     audit.Recorder
	Log                                       *slog.Logger
	Now                                       func() time.Time
}

type Service struct {
	st       Store
	defaults Snapshot
	reload   time.Duration
	audit    audit.Recorder
	log      *slog.Logger
	now      func() time.Time
	mu       sync.RWMutex
	snap     Snapshot
	loaded   time.Time
}

func New(st Store, o Options) *Service {
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
	return &Service{st: st, defaults: Snapshot{UserDefault: o.DefaultUserPerMinute, AppDefault: o.DefaultAppPerMinute, Apps: map[string]int{}, Users: map[string]UserLimit{}, Admins: map[string]bool{}}, reload: o.ReloadInterval, audit: o.Audit, log: o.Log, now: o.Now}
}

func clone(s Snapshot) Snapshot {
	s.Apps = maps.Clone(s.Apps)
	s.Users = maps.Clone(s.Users)
	s.Admins = maps.Clone(s.Admins)
	return s
}
func (s *Service) Refresh(ctx context.Context) error {
	v, err := s.st.Load(ctx)
	if err != nil {
		return err
	}
	if v.UserDefault <= 0 {
		v.UserDefault = s.defaults.UserDefault
	}
	if v.AppDefault <= 0 {
		v.AppDefault = s.defaults.AppDefault
	}
	if v.Apps == nil {
		v.Apps = map[string]int{}
	}
	if v.Users == nil {
		v.Users = map[string]UserLimit{}
	}
	if v.Admins == nil {
		v.Admins = map[string]bool{}
	}
	s.mu.Lock()
	s.snap = clone(v)
	s.loaded = s.now()
	s.mu.Unlock()
	return nil
}
func (s *Service) snapshot(ctx context.Context) Snapshot {
	s.mu.RLock()
	v, at := clone(s.snap), s.loaded
	s.mu.RUnlock()
	if at.IsZero() || s.now().Sub(at) >= s.reload {
		if err := s.Refresh(ctx); err != nil {
			s.log.Error("rate settings refresh failed; using last/default values", "error", observability.RedactError(err))
			if at.IsZero() {
				return clone(s.defaults)
			}
		}
		s.mu.RLock()
		v = clone(s.snap)
		s.mu.RUnlock()
	}
	return v
}

// Limits implements mcp.LimitProvider.
func (s *Service) Limits(ctx context.Context, user, app string) (int, int) {
	v := s.snapshot(ctx)
	ul := v.UserDefault
	if x, ok := v.Users[user]; ok {
		if x.Admin != nil {
			ul = *x.Admin
		}
		if x.Self != nil {
			ul = min(ul, *x.Self)
		}
	}
	al := v.AppDefault
	if x, ok := v.Apps[app]; ok {
		al = x
	}
	return ul, al
}
func (s *Service) Snapshot(ctx context.Context) Snapshot         { return s.snapshot(ctx) }
func (s *Service) IsAdmin(ctx context.Context, user string) bool { return s.snapshot(ctx).Admins[user] }
func valid(n int) bool                                           { return n >= MinPerMinute && n <= MaxPerMinute }

func (s *Service) SetOrg(ctx context.Context, actor string, user, app int) error {
	if !s.IsAdmin(ctx, actor) {
		return ErrNotAdmin
	}
	if !valid(user) || !valid(app) {
		return ErrInvalidLimit
	}
	if err := s.st.SetOrg(ctx, user, app, actor); err != nil {
		return err
	}
	if err := s.Refresh(ctx); err != nil {
		return err
	}
	s.record(ctx, actor, "organization.rate_limits_changed", map[string]string{"user_per_min": strconv.Itoa(user), "app_per_min": strconv.Itoa(app)})
	return nil
}
func (s *Service) SetApp(ctx context.Context, actor, app string, limit *int) error {
	if !s.IsAdmin(ctx, actor) {
		return ErrNotAdmin
	}
	if !appRE.MatchString(app) || (limit != nil && !valid(*limit)) {
		return ErrInvalidLimit
	}
	if err := s.st.SetApp(ctx, app, limit, actor); err != nil {
		return err
	}
	if err := s.Refresh(ctx); err != nil {
		return err
	}
	s.record(ctx, actor, "organization.app_rate_limit_changed", map[string]string{"app": app, "per_min": fmtLimit(limit)})
	return nil
}
func (s *Service) SetUserAdmin(ctx context.Context, actor, user string, limit *int) error {
	if !s.IsAdmin(ctx, actor) {
		return ErrNotAdmin
	}
	if limit != nil && !valid(*limit) {
		return ErrInvalidLimit
	}
	if err := s.st.SetUserAdmin(ctx, user, limit, actor); err != nil {
		return err
	}
	if err := s.Refresh(ctx); err != nil {
		return err
	}
	s.record(ctx, actor, "organization.user_rate_limit_changed", map[string]string{"target_user": user, "per_min": fmtLimit(limit)})
	return nil
}
func (s *Service) SetSelf(ctx context.Context, user string, limit *int) error {
	if limit != nil && !valid(*limit) {
		return ErrInvalidLimit
	}
	v := s.snapshot(ctx)
	base := v.UserDefault
	if x, ok := v.Users[user]; ok && x.Admin != nil {
		base = *x.Admin
	}
	if limit != nil && *limit > base {
		return ErrSelfLimitTooHigh
	}
	if err := s.st.SetUserSelf(ctx, user, limit); err != nil {
		return err
	}
	if err := s.Refresh(ctx); err != nil {
		return err
	}
	s.record(ctx, user, "user.rate_limit_changed", map[string]string{"per_min": fmtLimit(limit)})
	return nil
}
func fmtLimit(p *int) string {
	if p == nil {
		return "default"
	}
	return strconv.Itoa(*p)
}
func (s *Service) record(ctx context.Context, user, action string, extra map[string]string) {
	r := map[string]string{"action": action}
	maps.Copy(r, extra)
	if err := s.audit.Record(ctx, audit.Event{Time: s.now(), UserID: user, ResourceIdentity: r, Decision: "allow", Outcome: "succeeded", RequestID: observability.RequestIDFromContext(ctx)}); err != nil {
		s.log.Error("settings audit failed", "action", action, "error", observability.RedactError(err))
	}
}
