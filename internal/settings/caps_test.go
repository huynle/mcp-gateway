package settings_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/settings"
)

const (
	capAdmin = "00000000-0000-0000-0000-00000000000a"
	capAlice = "00000000-0000-0000-0000-0000000000a1"
)

type memCaps struct {
	mu   sync.Mutex
	snap settings.CapsSnapshot
	fail error
}

func newMemCaps() *memCaps {
	return &memCaps{snap: settings.CapsSnapshot{Org: caps.Values{}, Users: map[string]caps.Values{}, Admins: map[string]bool{capAdmin: true}}}
}

func apply(dst caps.Values, p caps.Patch) caps.Values {
	out := maps.Clone(dst)
	if out == nil {
		out = caps.Values{}
	}
	for r, v := range p {
		if v == nil {
			delete(out, r)
		} else {
			out[r] = *v
		}
	}
	return out
}

func (m *memCaps) LoadCaps(context.Context) (settings.CapsSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return settings.CapsSnapshot{}, m.fail
	}
	s := m.snap
	s.Org = maps.Clone(s.Org)
	s.Users = maps.Clone(s.Users)
	s.Admins = maps.Clone(s.Admins)
	return s, nil
}
func (m *memCaps) PatchOrgCaps(_ context.Context, p caps.Patch, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snap.Org = apply(m.snap.Org, p)
	m.snap.Version++
	return nil
}
func (m *memCaps) PatchUserCaps(_ context.Context, user string, p caps.Patch, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := apply(m.snap.Users[user], p)
	if len(v) == 0 {
		delete(m.snap.Users, user)
	} else {
		m.snap.Users[user] = v
	}
	return nil
}

type recAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recAudit) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func newCaps(t *testing.T, st settings.CapsStore, defaults caps.Values) (*settings.CapsService, *recAudit, *bytes.Buffer) {
	t.Helper()
	rec := &recAudit{}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	return settings.NewCaps(st, settings.CapsOptions{Defaults: defaults, ReloadInterval: time.Hour, Audit: rec, Log: log}), rec, &buf
}

func TestCapsDefaultsFromEnvNeverUnlimited(t *testing.T) {
	s, _, _ := newCaps(t, newMemCaps(), caps.Values{caps.Servers: 3, caps.Tunnels: 0, caps.ConnectionsTotal: -1})
	ctx := t.Context()
	if got := s.Limit(ctx, capAlice, caps.Servers); got != 3 {
		t.Errorf("servers = %d, want ENV 3", got)
	}
	// ENV 0 / negative / missing never means unlimited: built-in default.
	for _, r := range []caps.Resource{caps.Tunnels, caps.ConnectionsTotal, caps.ConnectionsPerApp, caps.PendingApprovals} {
		if got := s.Limit(ctx, capAlice, r); got != caps.Builtin[r] {
			t.Errorf("%s = %d, want built-in %d", r, got, caps.Builtin[r])
		}
	}
}

func TestCapsPrecedenceOrgThenUserAndUnlimited(t *testing.T) {
	st := newMemCaps()
	s, rec, _ := newCaps(t, st, caps.Values{caps.Servers: 10, caps.Tunnels: 5})
	ctx := t.Context()
	if err := s.SetOrg(ctx, capAdmin, caps.Patch{caps.Servers: ptr(4)}); err != nil {
		t.Fatal(err)
	}
	if got := s.Limit(ctx, capAlice, caps.Servers); got != 4 {
		t.Fatalf("org servers = %d, want 4 (immediately)", got)
	}
	if got := s.Limit(ctx, capAlice, caps.Tunnels); got != 5 {
		t.Fatalf("tunnels = %d, want ENV 5 (untouched)", got)
	}
	if err := s.SetUser(ctx, capAdmin, capAlice, caps.Patch{caps.Servers: ptr(0), caps.Tunnels: ptr(1)}); err != nil {
		t.Fatal(err)
	}
	if got := s.Limit(ctx, capAlice, caps.Servers); got != 0 {
		t.Errorf("user servers = %d, want 0 (unlimited by admin)", got)
	}
	if got := s.Limit(ctx, capAlice, caps.Tunnels); got != 1 {
		t.Errorf("user tunnels = %d, want 1", got)
	}
	if got := s.Limit(ctx, capAdmin, caps.Servers); got != 4 {
		t.Errorf("other user servers = %d, want org 4", got)
	}
	eff := s.Effective(ctx, capAlice)
	if eff[caps.Servers] != 0 || eff[caps.Tunnels] != 1 || eff[caps.PendingApprovals] != caps.Builtin[caps.PendingApprovals] || len(eff) != len(caps.Resources) {
		t.Errorf("effective = %v", eff)
	}
	// Clearing returns to the parent level.
	if err := s.SetUser(ctx, capAdmin, capAlice, caps.Patch{caps.Servers: nil}); err != nil {
		t.Fatal(err)
	}
	if got := s.Limit(ctx, capAlice, caps.Servers); got != 4 {
		t.Errorf("cleared user servers = %d, want org 4", got)
	}
	if err := s.SetOrg(ctx, capAdmin, caps.Patch{caps.Servers: nil}); err != nil {
		t.Fatal(err)
	}
	if got := s.Limit(ctx, capAlice, caps.Servers); got != 10 {
		t.Errorf("cleared org servers = %d, want ENV 10", got)
	}
	// Every change is audited with the action and values only.
	want := []string{"organization.resource_caps_changed", "organization.user_resource_caps_changed", "organization.user_resource_caps_changed", "organization.resource_caps_changed"}
	if len(rec.events) != len(want) {
		t.Fatalf("audit events = %d, want %d", len(rec.events), len(want))
	}
	for i, e := range rec.events {
		if e.ResourceIdentity["action"] != want[i] || e.UserID != capAdmin || e.Outcome != "succeeded" {
			t.Errorf("event %d = %+v", i, e)
		}
	}
	if e := rec.events[0]; e.ResourceIdentity["servers"] != "4" {
		t.Errorf("org event = %v", e.ResourceIdentity)
	}
	if e := rec.events[1]; e.ResourceIdentity["target_user"] != capAlice || e.ResourceIdentity["servers"] != "0" || e.ResourceIdentity["tunnels"] != "1" {
		t.Errorf("user event = %v", e.ResourceIdentity)
	}
	if e := rec.events[3]; e.ResourceIdentity["servers"] != "default" {
		t.Errorf("clear event = %v", e.ResourceIdentity)
	}
}

func TestCapsSettersRefuse(t *testing.T) {
	s, rec, _ := newCaps(t, newMemCaps(), nil)
	ctx := t.Context()
	if err := s.SetOrg(ctx, capAlice, caps.Patch{caps.Servers: ptr(1)}); !errors.Is(err, settings.ErrNotAdmin) {
		t.Errorf("non-admin org = %v", err)
	}
	if err := s.SetUser(ctx, capAlice, capAlice, caps.Patch{caps.Servers: ptr(100)}); !errors.Is(err, settings.ErrNotAdmin) {
		t.Errorf("non-admin user = %v", err)
	}
	for name, p := range map[string]caps.Patch{
		"negative": {caps.Servers: ptr(-1)},
		"too big":  {caps.Tunnels: ptr(caps.Max + 1)},
		"unknown":  {"users": ptr(1)},
		"empty":    {},
	} {
		if err := s.SetOrg(ctx, capAdmin, p); !errors.Is(err, settings.ErrInvalidCap) {
			t.Errorf("%s org = %v, want ErrInvalidCap", name, err)
		}
		if err := s.SetUser(ctx, capAdmin, capAlice, p); !errors.Is(err, settings.ErrInvalidCap) {
			t.Errorf("%s user = %v, want ErrInvalidCap", name, err)
		}
	}
	if err := s.SetUser(ctx, capAdmin, "alice", caps.Patch{caps.Servers: ptr(1)}); !errors.Is(err, settings.ErrInvalidCap) {
		t.Errorf("non-uuid user = %v", err)
	}
	if len(rec.events) != 0 {
		t.Errorf("refused changes audited: %v", rec.events)
	}
}

func TestCapsRefusedIsLoggedWithClass(t *testing.T) {
	s, _, buf := newCaps(t, newMemCaps(), nil)
	s.Refused(t.Context(), capAlice, caps.Tunnels, 5)
	out := buf.String()
	for _, want := range []string{`"event":"caps.exceeded"`, `"class":"cap_exceeded"`, `"user_id":"` + capAlice + `"`, `"resource":"tunnels"`, `"limit":5`} {
		if !strings.Contains(out, want) {
			t.Errorf("log %s lacks %s", out, want)
		}
	}
}

func TestCapsLoadFailureFallsBackToDefaults(t *testing.T) {
	st := newMemCaps()
	st.fail = errors.New("db down")
	s, _, _ := newCaps(t, st, caps.Values{caps.Servers: 2})
	if got := s.Limit(t.Context(), capAlice, caps.Servers); got != 2 {
		t.Errorf("servers = %d, want ENV 2 when the store fails (never unlimited)", got)
	}
	if s.IsAdmin(t.Context(), capAdmin) {
		t.Error("admin without a loaded snapshot")
	}
}
