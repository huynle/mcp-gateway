package main

import (
	"net/http"
	"strings"
)

// portalMounter is the part of *portal.Portal the extras mount through.
type portalMounter interface {
	MountUser(pattern string, h http.Handler)
	MountAdmin(pattern string, h http.Handler)
}

// portalMount is the mount function handed to portal extras: patterns for
// /admin or below go behind the portal's admin check (MountAdmin: a
// non-admin gets the 404 page, before the CSRF check), everything else
// behind its sign-in check (MountUser). An extra can therefore never
// expose an /admin page to plain users by mounting it the wrong way.
func portalMount(p portalMounter) func(pattern string, h http.Handler) {
	return func(pattern string, h http.Handler) {
		if isAdminPattern(pattern) {
			p.MountAdmin(pattern, h)
			return
		}
		p.MountUser(pattern, h)
	}
}

// isAdminPattern reports whether a ServeMux pattern ("[METHOD ]/path")
// is /admin or below it.
func isAdminPattern(pattern string) bool {
	path := pattern
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		path = strings.TrimSpace(pattern[i+1:])
	}
	return path == "/admin" || strings.HasPrefix(path, "/admin/")
}
