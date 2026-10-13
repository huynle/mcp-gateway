package settings_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/settings"
)

type memStore struct{ snap settings.Snapshot }

func (m *memStore) Load(context.Context) (settings.Snapshot, error) { return m.snap, nil }
func (m *memStore) SetOrg(_ context.Context, u, a int, _ string) error {
	m.snap.UserDefault = u
	m.snap.AppDefault = a
	m.snap.Version++
	return nil
}
func (m *memStore) SetApp(_ context.Context, app string, n *int, _ string) error {
	if n == nil {
		delete(m.snap.Apps, app)
	} else {
		m.snap.Apps[app] = *n
	}
	return nil
}
func (m *memStore) SetUserAdmin(_ context.Context, u string, n *int, _ string) error {
	x := m.snap.Users[u]
	x.Admin = n
	m.snap.Users[u] = x
	return nil
}
func (m *memStore) SetUserSelf(_ context.Context, u string, n *int) error {
	x := m.snap.Users[u]
	x.Self = n
	m.snap.Users[u] = x
	return nil
}

func TestPrecedenceAndImmediateChanges(t *testing.T) {
	st := &memStore{snap: settings.Snapshot{Apps: map[string]int{}, Users: map[string]settings.UserLimit{}, Admins: map[string]bool{"admin": true}}}
	s := settings.New(st, settings.Options{DefaultUserPerMinute: 60, DefaultAppPerMinute: 600, ReloadInterval: time.Hour})
	u, a := s.Limits(t.Context(), "alice", "brain")
	if u != 60 || a != 600 {
		t.Fatalf("defaults=%d/%d", u, a)
	}
	if err := s.SetOrg(t.Context(), "admin", 600, 3000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApp(t.Context(), "admin", "brain", ptr(1000)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(t.Context(), "admin", "alice", ptr(800)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSelf(t.Context(), "alice", ptr(500)); err != nil {
		t.Fatal(err)
	}
	u, a = s.Limits(t.Context(), "alice", "brain")
	if u != 500 || a != 1000 {
		t.Fatalf("effective=%d/%d", u, a)
	}
	if err := s.SetSelf(t.Context(), "alice", ptr(900)); !errors.Is(err, settings.ErrSelfLimitTooHigh) {
		t.Fatalf("high self=%v", err)
	}
	if err := s.SetOrg(t.Context(), "alice", 10, 10); !errors.Is(err, settings.ErrNotAdmin) {
		t.Fatalf("nonadmin=%v", err)
	}
}

func ptr(n int) *int { return &n }
