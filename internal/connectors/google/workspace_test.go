package google_test

import (
	"context"
	"slices"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// workspaceScopes are every scope only Google Workspace accounts can
// grant: the directory and the Chat scopes.
var workspaceScopes = []string{
	google.ScopeDirectoryReadonly,
	google.ScopeChatSpacesReadonly, google.ScopeChatSpaces,
	google.ScopeChatMessagesReadonly, google.ScopeChatMessages, google.ScopeChatMessagesCreate,
}

func TestWorkspaceOnlyScope(t *testing.T) {
	for _, sc := range workspaceScopes {
		if !google.WorkspaceOnlyScope(sc) {
			t.Errorf("WorkspaceOnlyScope(%s) = false, want true", sc)
		}
	}
	for _, sc := range []string{
		"openid", "https://www.googleapis.com/auth/userinfo.email", google.ScopeContactsReadonly, google.ScopeContacts,
		google.ScopeGmailReadonly, google.ScopeDrive, google.ScopeCalendarEvents, "",
	} {
		if google.WorkspaceOnlyScope(sc) {
			t.Errorf("WorkspaceOnlyScope(%q) = true, want false", sc)
		}
	}
}

func TestScopeGrantable(t *testing.T) {
	for _, sc := range workspaceScopes {
		if google.ScopeGrantable(connectors.LabelPersonal, sc) {
			t.Errorf("personal can grant %s, want not", sc)
		}
		if !google.ScopeGrantable(connectors.LabelCompany, sc) {
			t.Errorf("company cannot grant %s, want it can", sc)
		}
	}
	if !google.ScopeGrantable(connectors.LabelPersonal, google.ScopeContactsReadonly) || !google.ScopeGrantable(connectors.LabelCompany, google.ScopeGmailReadonly) {
		t.Error("every label can grant the consumer scopes")
	}
}

// The Chat scopes follow the API's accepted-scope lists: chat.spaces
// covers chat.spaces.readonly; chat.messages covers chat.messages.readonly
// and chat.messages.create.
func TestGrantsChatImplication(t *testing.T) {
	cases := []struct {
		granted, required string
		want              bool
	}{
		{google.ScopeChatSpaces, google.ScopeChatSpacesReadonly, true},
		{google.ScopeChatSpacesReadonly, google.ScopeChatSpaces, false},
		{google.ScopeChatMessages, google.ScopeChatMessagesReadonly, true},
		{google.ScopeChatMessages, google.ScopeChatMessagesCreate, true},
		{google.ScopeChatMessagesReadonly, google.ScopeChatMessagesCreate, false},
		{google.ScopeChatMessagesCreate, google.ScopeChatMessagesReadonly, false},
		{google.ScopeChatMessages, google.ScopeChatSpacesReadonly, false},
		{google.ScopeContacts, google.ScopeDirectoryReadonly, false},
		{google.ScopeDirectoryReadonly, google.ScopeDirectoryReadonly, true},
	}
	for _, tc := range cases {
		if got := google.Grants([]string{tc.granted}, tc.required); got != tc.want {
			t.Errorf("Grants(%s, %s) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}

// A consumer account (userinfo without hd) can never use the Workspace
// scopes, so the binder drops them from what it records whatever the
// label; a Workspace account (hd present) keeps them.
func TestBinderStripsWorkspaceScopesWithoutHostedDomain(t *testing.T) {
	granted := "openid " + google.ScopeContactsReadonly + " " + google.ScopeDirectoryReadonly + " " + google.ScopeChatMessages
	tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{"scope": granted})
	cases := []struct {
		name      string
		userinfo  string
		extra     map[string]string
		wantLabel connectors.AccountLabel
		keep      bool
	}{
		{"workspace account keeps them", "userinfo_company.json", nil, connectors.LabelPersonal, true},
		{"consumer account drops them", "userinfo_personal.json", nil, connectors.LabelPersonal, false},
		{"consumer labelled company still drops them", "userinfo_personal.json", map[string]string{connections.ExtraDefaultLabel: "company"}, connectors.LabelCompany, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: tc.userinfo}})
			bound, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, tc.extra, tok))
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if bound.Label != tc.wantLabel {
				t.Errorf("Label = %q, want %q", bound.Label, tc.wantLabel)
			}
			if !slices.Contains(bound.Scopes, google.ScopeContactsReadonly) || !slices.Contains(bound.Scopes, "openid") {
				t.Errorf("Scopes = %v, lost a consumer scope", bound.Scopes)
			}
			for _, sc := range []string{google.ScopeDirectoryReadonly, google.ScopeChatMessages} {
				if got := slices.Contains(bound.Scopes, sc); got != tc.keep {
					t.Errorf("Scopes = %v: has %s = %v, want %v", bound.Scopes, sc, got, tc.keep)
				}
			}
		})
	}
}

// Without a scope field the flow records the requested scopes; for a
// consumer account the binder records them minus the Workspace scopes
// instead.
func TestBinderStripsRequestedWorkspaceScopesWithoutScopeField(t *testing.T) {
	srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: "userinfo_personal.json"}})
	in := bindInput(srv, connections.GoogleExternal, nil, nil)
	in.RequestedScopes = append(in.RequestedScopes, google.ScopeDirectoryReadonly)
	bound, err := google.Binder{}.Bind(context.Background(), in)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if slices.Contains(bound.Scopes, google.ScopeDirectoryReadonly) || !slices.Contains(bound.Scopes, google.ScopeCalendarEvents) {
		t.Errorf("Scopes = %v, want the requested scopes without directory.readonly", bound.Scopes)
	}
	// A Workspace account without a scope field is left to the flow.
	srv = newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: "userinfo_company.json"}})
	in = bindInput(srv, connections.GoogleExternal, nil, nil)
	in.RequestedScopes = append(in.RequestedScopes, google.ScopeDirectoryReadonly)
	if bound, err = (google.Binder{}).Bind(context.Background(), in); err != nil || bound.Scopes != nil {
		t.Errorf("workspace account: Scopes = %v, err = %v; want nil", bound.Scopes, err)
	}
}
