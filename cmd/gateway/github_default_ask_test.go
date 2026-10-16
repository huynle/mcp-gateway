package main

import (
	"context"
	"regexp"
	"slices"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The GitHub writes that predate the tool-gap work keep their Auto
// default; every later GitHub write is seeded as Ask by migration 00024.
// A new GitHub write must be seeded by a migration like it (or be listed
// here on purpose), so it never ships without the confirmation default.
var githubAutoWrites = []string{github.ToolCreateIssue, github.ToolAddIssueComment, github.ToolCreatePullRequest, github.ToolCreateBranch}

func TestGitHubNewWritesAreSeededAsAsk(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00024_github_default_ask.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := regexp.MustCompile(`(?s)-- \+goose Up(.*)-- \+goose Down(.*)`).FindSubmatch(raw)
	if sections == nil {
		t.Fatal("no goose Up / Down sections")
	}
	pairs := regexp.MustCompile(`\('github', '([a-z0-9_]+)'\)`)
	names := func(b []byte) []string {
		var out []string
		for _, m := range pairs.FindAllSubmatch(b, -1) {
			out = append(out, string(m[1]))
		}
		slices.Sort(out)
		return out
	}
	up, down := names(sections[1]), names(sections[2])

	c, err := github.New(github.Options{Tokens: func(context.Context, string, string) oauth2.TokenSource { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, tool := range c.Tools() {
		if tool.Kind == connectors.KindWrite && !slices.Contains(githubAutoWrites, tool.Name) {
			want = append(want, tool.Name)
		}
	}
	slices.Sort(want)
	if len(want) == 0 || !slices.Equal(up, want) {
		t.Errorf("migration seeds Ask for %v,\nwant every new GitHub write %v", up, want)
	}
	if !slices.Equal(down, up) {
		t.Errorf("Down removes %v, want exactly the seeded %v", down, up)
	}
	for _, auto := range githubAutoWrites {
		if slices.Contains(up, auto) {
			t.Errorf("%s keeps its Auto default; it must not be seeded", auto)
		}
	}
}
