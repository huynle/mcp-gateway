// Package navtest reads the shared portal nav back out of a rendered page,
// for tests of the modules that render it.
package navtest

import (
	"regexp"
	"slices"
	"strings"
)

// Member and Admin are the exact link sets, in sidebar order (My account,
// then the Access, Integrations and Activity groups, then Admin), every
// portal page must show to a member and to an admin, pinned literally (not derived from package
// nav) so a test fails if the bar changes by accident.
var (
	Member = []string{"/account", "/tokens", "/harnesses", "/machines", "/connections", "/servers", "/secrets", "/approvals", "/operations", "/activity"}
	Admin  = append(slices.Clone(Member), "/admin/settings", "/admin/users", "/admin/roles", "/admin/servers", "/admin/machines", "/admin/audit", "/admin/vendor-apps")
)

var (
	hrefRE    = regexp.MustCompile(`<a [^>]*href="([^"]*)"`)
	currentRE = regexp.MustCompile(`<a [^>]*href="([^"]*)"[^>]*aria-current="page"`)
)

// block returns the inside of the site nav, or "" when the page has none.
func block(body string) string {
	_, rest, ok := strings.Cut(body, `<nav class="site-nav"`)
	if !ok {
		return ""
	}
	inside, _, _ := strings.Cut(rest, "</nav>")
	return inside
}

// Links returns the hrefs of the site nav in order (nil when the page has
// no site nav).
func Links(body string) []string {
	var out []string
	for _, m := range hrefRE.FindAllStringSubmatch(block(body), -1) {
		out = append(out, m[1])
	}
	return out
}

// Current returns the href marked aria-current, or "".
func Current(body string) string {
	if m := currentRE.FindStringSubmatch(block(body)); m != nil {
		return m[1]
	}
	return ""
}

// Count returns how many site navs the page has (every page must have
// exactly one).
func Count(body string) int {
	return strings.Count(body, `<nav class="site-nav"`)
}
