package main

import (
	"net/http"
	"slices"
	"testing"
)

type recordingMounts struct{ user, admin []string }

func (m *recordingMounts) MountUser(p string, _ http.Handler)  { m.user = append(m.user, p) }
func (m *recordingMounts) MountAdmin(p string, _ http.Handler) { m.admin = append(m.admin, p) }

// Extras mount through one function; anything under /admin goes behind
// the portal's admin check, everything else behind sign-in.
func TestPortalMountRoutesAdminPatterns(t *testing.T) {
	m := &recordingMounts{}
	mount := portalMount(m)
	for _, p := range []string{
		"GET /servers", "POST /servers/{id}/review", "GET /administrator", "GET /operations",
		"GET /admin/servers", "POST /admin/servers/{id}/publish", "GET /admin", "/admin/network/allow-hosts",
	} {
		mount(p, http.NotFoundHandler())
	}
	if want := []string{"GET /servers", "POST /servers/{id}/review", "GET /administrator", "GET /operations"}; !slices.Equal(m.user, want) {
		t.Errorf("user mounts = %v, want %v", m.user, want)
	}
	if want := []string{"GET /admin/servers", "POST /admin/servers/{id}/publish", "GET /admin", "/admin/network/allow-hosts"}; !slices.Equal(m.admin, want) {
		t.Errorf("admin mounts = %v, want %v", m.admin, want)
	}
}

// Without a federation nothing is mounted.
func TestFederationAdminNotMountedWithoutFederation(t *testing.T) {
	m := &recordingMounts{}
	withFederationAdmin(nil, nil, nil)(nil, portalMount(m), nil, nil)
	if len(m.user)+len(m.admin) != 0 {
		t.Errorf("mounted %v %v without a federation", m.user, m.admin)
	}
}
