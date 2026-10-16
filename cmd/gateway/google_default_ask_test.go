package main

import (
	"context"
	"regexp"
	"slices"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The Google writes of increments 1 and 2 keep their Auto default; every
// later Google write is seeded as Ask by migration 00022. A new Google
// write tool must be seeded by a migration like it (or be listed here on
// purpose), so it never ships without the confirmation default.
var googleAutoWrites = []string{
	"calendar.create_event", "tasks.create", "gmail.send", "gmail.create_draft",
	"drive.create_folder", "docs.create", "docs.append_text", "sheets.append_rows",
}

func TestGoogleNewWritesAreSeededAsAsk(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00022_google_default_ask.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := regexp.MustCompile(`(?s)-- \+goose Up(.*)-- \+goose Down(.*)`).FindSubmatch(raw)
	if sections == nil {
		t.Fatal("no goose Up / Down sections")
	}
	pairs := regexp.MustCompile(`\('([a-z0-9_]+)', '([a-z0-9_]+)'\)`)
	names := func(b []byte) []string {
		var out []string
		for _, m := range pairs.FindAllSubmatch(b, -1) {
			out = append(out, string(m[1])+"."+string(m[2]))
		}
		slices.Sort(out)
		return out
	}
	up, down := names(sections[1]), names(sections[2])

	c, err := google.New(google.Options{Tokens: func(context.Context, string, string) oauth2.TokenSource { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, app := range c.Apps() {
		for _, tool := range app.Tools() {
			full := app.App() + "." + tool.Name
			if tool.Kind == connectors.KindWrite && !slices.Contains(googleAutoWrites, full) {
				want = append(want, full)
			}
		}
	}
	slices.Sort(want)
	if len(want) == 0 || !slices.Equal(up, want) {
		t.Errorf("migration seeds Ask for %v,\nwant every new Google write %v", up, want)
	}
	if !slices.Equal(down, up) {
		t.Errorf("Down removes %v, want exactly the seeded %v", down, up)
	}
	for _, auto := range googleAutoWrites {
		if slices.Contains(up, auto) {
			t.Errorf("%s keeps its Auto default; it must not be seeded", auto)
		}
	}
}
