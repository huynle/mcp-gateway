package microsoft_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// Personal Microsoft accounts cannot use Teams chats, the directory
// (user search) or findMeetingTimes (Calendars.Read.Shared): Connect and
// grant more access never ask them for those permissions, and the binder
// strips them. Mail, calendar, files, To Do, contacts and people stay
// grantable.
func TestWorkOnlyScopes(t *testing.T) {
	workOnly := []string{
		"Team.ReadBasic.All", "Channel.ReadBasic.All", "ChannelMessage.Read.All", "ChannelMessage.Send",
		"Chat.ReadBasic", "Chat.Read", "ChatMessage.Send", "chatmessage.send",
		"User.ReadBasic.All", "Calendars.Read.Shared", "https://graph.microsoft.com/User.ReadBasic.All", "Sites.Read.All",
	}
	everyone := []string{
		"User.Read", "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Calendars.Read", "Calendars.ReadWrite",
		"Files.Read.All", "Files.ReadWrite", "Tasks.Read", "Tasks.ReadWrite", "Contacts.Read", "People.Read", "offline_access",
	}
	for _, s := range workOnly {
		if !microsoft.WorkOnlyScope(s) {
			t.Errorf("WorkOnlyScope(%q) = false, want true", s)
		}
		if microsoft.ScopeGrantable(connectors.LabelPersonal, s) {
			t.Errorf("personal accounts can grant %s, want not", s)
		}
		if !microsoft.ScopeGrantable(connectors.LabelCompany, s) {
			t.Errorf("work accounts cannot grant %s, want they can", s)
		}
	}
	for _, s := range everyone {
		if microsoft.WorkOnlyScope(s) {
			t.Errorf("WorkOnlyScope(%q) = true, want false", s)
		}
		if !microsoft.ScopeGrantable(connectors.LabelPersonal, s) {
			t.Errorf("personal accounts cannot grant %s, want they can", s)
		}
	}
}
