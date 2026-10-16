package main

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The Jira and Confluence writes that predate the Rovo gap closing keep
// their Auto default; every later write is seeded as Ask by migration
// 00025. A new Atlassian write tool must be seeded by a migration like it
// (or be listed here on purpose), so it never ships without the
// confirmation default.
var atlassianAutoWrites = []string{
	atlassian.JiraApp + "." + atlassian.ToolCreateIssue,
	atlassian.JiraApp + "." + atlassian.ToolAddComment,
	atlassian.JiraApp + "." + atlassian.ToolTransitionIssue,
	atlassian.ConfluenceApp + "." + atlassian.ToolCreatePage,
}

func TestAtlassianNewWritesAreSeededAsAsk(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00025_atlassian_default_ask.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := regexp.MustCompile(`(?s)-- \+goose Up(.*)-- \+goose Down(.*)`).FindSubmatch(raw)
	if sections == nil {
		t.Fatal("no goose Up / Down sections")
	}
	pairs := regexp.MustCompile(`\('(jira|confluence)', '([a-z0-9_]+)'\)`)
	names := func(b []byte) []string {
		var out []string
		for _, m := range pairs.FindAllSubmatch(b, -1) {
			out = append(out, string(m[1])+"."+string(m[2]))
		}
		slices.Sort(out)
		return out
	}
	up, down := names(sections[1]), names(sections[2])

	opts := atlassian.Options{
		Tokens:     func(context.Context, string, string) oauth2.TokenSource { return nil },
		Sites:      func(context.Context, string, string) (atlassian.Site, error) { return atlassian.Site{}, nil },
		HTTPClient: http.DefaultClient,
	}
	var want []string
	for _, app := range []string{atlassian.JiraApp, atlassian.ConfluenceApp} {
		c, err := atlassian.New(app, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range c.Tools() {
			if name := tool.App + "." + tool.Name; tool.Kind == connectors.KindWrite && !slices.Contains(atlassianAutoWrites, name) {
				want = append(want, name)
			}
		}
	}
	slices.Sort(want)
	if len(want) == 0 || !slices.Equal(up, want) {
		t.Errorf("migration seeds Ask for %v,\nwant every new Atlassian write %v", up, want)
	}
	if !slices.Equal(down, up) {
		t.Errorf("Down removes %v, want exactly the seeded %v", down, up)
	}
	for _, auto := range atlassianAutoWrites {
		if slices.Contains(up, auto) {
			t.Errorf("%s keeps its Auto default; it must not be seeded", auto)
		}
	}
}
