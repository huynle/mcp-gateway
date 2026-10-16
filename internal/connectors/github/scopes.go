package github

import "strings"

// ScopeCovered is the connectors.ScopeCoverage of the GitHub app: the
// tools' RequiredScopes are GitHub App permissions written
// "<permission>:<access>", and GitHub grants read with write, so a
// recorded "contents:write" covers a required "contents:read" (the
// connect flow records what it asked for, and a connection that asked
// for create_branch's contents:write can run get_file_contents).
// Anything else compares names, ignoring case and surrounding space.
func ScopeCovered(granted []string, required string) bool {
	required = strings.ToLower(strings.TrimSpace(required))
	perm, access, ok := strings.Cut(required, ":")
	for _, g := range granted {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == required || (ok && access == "read" && g == perm+":write") {
			return true
		}
	}
	return false
}
