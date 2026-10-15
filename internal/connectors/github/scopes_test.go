package github_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

func TestScopeCovered(t *testing.T) {
	cases := []struct {
		granted  []string
		required string
		want     bool
	}{
		{[]string{"contents:read"}, "contents:read", true},
		{[]string{"contents:write"}, "contents:read", true},
		{[]string{" Contents:Write "}, "contents:read", true},
		{[]string{"contents:read"}, "contents:write", false},
		{[]string{"issues:write"}, "contents:read", false},
		{[]string{"actions:write"}, "actions:write", true},
		{[]string{"pull_requests:write"}, "issues:read", false},
		{nil, "checks:read", false},
		{[]string{"statuses"}, "statuses:read", false},
		{[]string{"repo"}, "repo", true},
	}
	for _, tc := range cases {
		if got := github.ScopeCovered(tc.granted, tc.required); got != tc.want {
			t.Errorf("ScopeCovered(%v, %q) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}
