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
// later Google write is seeded as Ask by a migration: 00022 (increment 3),
// 00035 (increment 4, Workspace tools) or 00037 (increment 5, the full
// Calendar, Tasks and Contacts APIs; later phases append to them). A
// new Google write tool must be seeded by one of them (or be listed here
// on purpose), so it never ships without the confirmation default.
var googleAutoWrites = []string{
	"calendar.create_event", "tasks.create", "gmail.send", "gmail.create_draft",
	"drive.create_folder", "docs.create", "docs.append_text", "sheets.append_rows",
}

// googleAskMigrations are the migrations seeding Ask for Google writes.
var googleAskMigrations = []string{
	"00022_google_default_ask.sql",
	"00035_google_workspace_default_ask.sql",
	"00037_google_calendar_tasks_contacts_default_ask.sql",
}

// seededAsk returns the (app.tool) rows a migration's goose Up inserts
// and its Down deletes, each sorted.
func seededAsk(t *testing.T, file string) (up, down []string) {
	t.Helper()
	raw, err := migrations.FS.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	sections := regexp.MustCompile(`(?s)-- \+goose Up(.*)-- \+goose Down(.*)`).FindSubmatch(raw)
	if sections == nil {
		t.Fatalf("%s: no goose Up / Down sections", file)
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
	return names(sections[1]), names(sections[2])
}

func TestGoogleNewWritesAreSeededAsAsk(t *testing.T) {
	var up []string
	for _, file := range googleAskMigrations {
		u, d := seededAsk(t, file)
		if len(u) == 0 {
			t.Errorf("%s seeds nothing", file)
		}
		if !slices.Equal(d, u) {
			t.Errorf("%s: Down removes %v, want exactly the seeded %v", file, d, u)
		}
		for _, name := range u {
			if slices.Contains(up, name) {
				t.Errorf("%s seeds %s again", file, name)
			}
		}
		up = append(up, u...)
	}
	slices.Sort(up)

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
		t.Errorf("migrations seed Ask for %v,\nwant every new Google write %v", up, want)
	}
	for _, auto := range googleAutoWrites {
		if slices.Contains(up, auto) {
			t.Errorf("%s keeps its Auto default; it must not be seeded", auto)
		}
	}
}
