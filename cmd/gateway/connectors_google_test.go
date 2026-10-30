package main

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// The Google connector's apps (calendar, tasks, gmail, drive, docs, sheets, contacts, chat, slides) are
// registered whenever the connections service is mounted, before any
// admin registers the Google vendor apps: their tools exist, list no
// accounts for a user who has not connected, and fail with a clear "no
// connected account" error rather than a crash when called without one.
func TestRegisterConnectorsRegistersGoogleWithConnections(t *testing.T) {
	ctx := context.Background()
	connSvc, _ := newMemConnections(t)
	registry := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"calendar.list_events", "calendar.get_event", "calendar.create_event", "calendar.list_accounts",
		"tasks.list", "tasks.create", "tasks.list_accounts",
		"gmail.search", "gmail.get_message", "gmail.list_labels", "gmail.send", "gmail.create_draft", "gmail.list_accounts",
		"chat.list_spaces", "chat.get_space", "chat.list_messages", "chat.get_message", "chat.list_members",
		"chat.send_message", "chat.reply_in_thread", "chat.list_accounts",
		"gmail.get_vacation", "gmail.list_filters", "gmail.set_vacation",
		"slides.get_text", "slides.create", "slides.replace_text", "slides.list_accounts",
	}
	for _, name := range want {
		if _, ok := registry.Get(name); !ok {
			t.Errorf("%s missing from the registry", name)
		}
	}
	for _, app := range google.Apps {
		accts, err := src.ListAccounts(ctx, userAlice, app)
		if err != nil || len(accts) != 0 {
			t.Errorf("%s accounts before connecting = %+v, %v; want none", app, accts, err)
		}
	}
	tool, _ := registry.Get("gmail.list_labels")
	_, err = tool.Handler(ctx, connectors.Call{Tool: "gmail.list_labels", Principal: connectors.Principal{UserID: userAlice}, Args: map[string]any{}})
	var gerr *google.Error
	if !errors.As(err, &gerr) || gerr.Class != google.ClassNoAccount {
		t.Errorf("list_labels without an account: err = %v, want class %s", err, google.ClassNoAccount)
	}
}

// Every Google app tells the access gap that personal accounts cannot
// grant the Workspace-only scopes (google.ScopeGrantable).
func TestRegisterGoogleInstallsScopeGrantable(t *testing.T) {
	connSvc, _ := newMemConnections(t)
	registry := connectors.NewRegistry()
	if _, err := registerConnectors(config.Config{}, registry, connSvc, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(google.Apps, google.AppChat) || !slices.Contains(google.Apps, google.AppSlides) {
		t.Fatalf("google.Apps = %v, want chat and slides registered", google.Apps)
	}
	for _, app := range google.Apps {
		if registry.Grantable(app, connectors.LabelPersonal, google.ScopeDirectoryReadonly) {
			t.Errorf("%s: personal accounts may grant directory.readonly, want not", app)
		}
		for _, sc := range []string{google.ScopeChatMessagesReadonly, google.ScopeChatMessagesCreate, google.ScopeChatSpacesReadonly, google.ScopeChatMembershipsReadonly} {
			if registry.Grantable(app, connectors.LabelPersonal, sc) || !registry.Grantable(app, connectors.LabelCompany, sc) {
				t.Errorf("%s: %s must be grantable by company accounts only", app, sc)
			}
		}
		if !registry.Grantable(app, connectors.LabelPersonal, google.ScopePresentations) {
			t.Errorf("%s: personal accounts must be able to grant the Slides scope", app)
		}
		if !registry.Grantable(app, connectors.LabelCompany, google.ScopeDirectoryReadonly) || !registry.Grantable(app, connectors.LabelPersonal, google.ScopeContactsReadonly) {
			t.Errorf("%s: company accounts and consumer scopes must stay grantable", app)
		}
	}
	if _, ok := registry.Get("contacts.search_directory"); !ok {
		t.Error("contacts.search_directory missing from the registry")
	}
}
