package tokens_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/huynle/mcp-gateway/internal/tokens"
)

func TestParseAllowListSplitsAppsAndTools(t *testing.T) {
	s, err := tokens.ParseAllowList("github, slack.post_message\n GitHub.create_issue  slack ")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Apps, []string{"github", "slack"}) {
		t.Errorf("apps = %v", s.Apps)
	}
	if !slices.Equal(s.Tools, []string{"github.create_issue", "slack.post_message"}) {
		t.Errorf("tools = %v", s.Tools)
	}
	if s.IsRestricted() != true {
		t.Error("allow-list with entries should be restricted")
	}
}

func TestParseAllowListEmptyMeansEverything(t *testing.T) {
	for _, in := range []string{"", "  ", ",,", "\n"} {
		s, err := tokens.ParseAllowList(in)
		if err != nil {
			t.Fatalf("ParseAllowList(%q): %v", in, err)
		}
		if s.IsRestricted() || len(s.Apps) != 0 || len(s.Tools) != 0 {
			t.Errorf("ParseAllowList(%q) = %+v, want unrestricted", in, s)
		}
	}
}

func TestParseAllowListRejectsBadEntries(t *testing.T) {
	for _, in := range []string{"github..x", ".create", "github.", "a.b.c", "git/hub", "git@hub"} {
		_, err := tokens.ParseAllowList(in)
		if !errors.Is(err, tokens.ErrInvalidScope) {
			t.Errorf("ParseAllowList(%q) = %v, want ErrInvalidScope", in, err)
		}
	}
}

func TestScopeAllows(t *testing.T) {
	everything := tokens.Scope{}
	narrowed := tokens.Scope{Apps: []string{"github"}, Tools: []string{"slack.post_message"}}
	cases := []struct {
		scope tokens.Scope
		tool  string
		want  bool
	}{
		{everything, "github.create_issue", true},
		{everything, "anything.at_all", true},
		{narrowed, "github.create_issue", true},
		{narrowed, "github.list_issues", true},
		{narrowed, "slack.post_message", true},
		{narrowed, "slack.list_channels", false},
		{narrowed, "jira.create_issue", false},
		{narrowed, "github", false},
		{narrowed, "githubx.create_issue", false},
	}
	for _, c := range cases {
		if got := c.scope.Allows(c.tool); got != c.want {
			t.Errorf("%+v Allows(%q) = %v, want %v", c.scope, c.tool, got, c.want)
		}
	}
}

func TestScopeJSONRoundTrip(t *testing.T) {
	s := tokens.Scope{Apps: []string{"github"}, Tools: []string{"slack.post_message"}, ReadOnly: true}
	raw, err := s.MarshalStore()
	if err != nil {
		t.Fatal(err)
	}
	// ReadOnly is a column, not part of the JSON document.
	if string(raw) != `{"apps":["github"],"tools":["slack.post_message"]}` {
		t.Errorf("stored JSON = %s", raw)
	}
	back, err := tokens.ScopeFromStore(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(back.Apps, s.Apps) || !slices.Equal(back.Tools, s.Tools) || !back.ReadOnly {
		t.Errorf("round trip = %+v, want %+v", back, s)
	}

	// Unrestricted scope stores as NULL (nil) and loads back as unrestricted.
	raw, err = tokens.Scope{}.MarshalStore()
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		t.Errorf("unrestricted scope stored as %s, want nil", raw)
	}
	back, err = tokens.ScopeFromStore(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if back.IsRestricted() || back.ReadOnly {
		t.Errorf("nil scope loaded as %+v", back)
	}
	if _, err := tokens.ScopeFromStore([]byte(`{"apps": 5}`), false); err == nil {
		t.Error("corrupt scope document accepted")
	}
}

func TestScopeString(t *testing.T) {
	if got := (tokens.Scope{}).String(); got != "all tools" {
		t.Errorf("unrestricted = %q", got)
	}
	if got := (tokens.Scope{ReadOnly: true}).String(); got != "all tools, read-only" {
		t.Errorf("read-only = %q", got)
	}
	if got := (tokens.Scope{Apps: []string{"github"}, Tools: []string{"slack.post_message"}, ReadOnly: true}).String(); got != "github, slack.post_message, read-only" {
		t.Errorf("narrowed = %q", got)
	}
}
